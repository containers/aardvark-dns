use crate::backend::DNSBackend;
use crate::backend::DNSResult;
use arc_swap::ArcSwap;
use arc_swap::Guard;
use futures_util::StreamExt;
use futures_util::TryStreamExt;
use hickory_client::{client::AsyncClient, proto::xfer::SerialMessage, rr::rdata, rr::Name};
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{DNSClass, RData, Record, RecordType},
    udp::{UdpClientStream, UdpStream},
    xfer::{dns_handle::DnsHandle, BufDnsStreamHandle, DnsRequest},
    DnsStreamHandle,
};
use log::{debug, error, trace, warn};
use resolv_conf;
use resolv_conf::ScopedIp;
use std::convert::TryInto;
use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

// Containers can be recreated with different ips quickly so
// do not let the clients cache to dns response for to long,
// aardvark-dns runs on the same host so caching is not that important.
// see https://github.com/containers/netavark/discussions/644
const CONTAINER_TTL: u32 = 60;

pub struct CoreDns {
    name: Name,                            // name or origin
    network_name: String,                  // raw network name
    address: IpAddr,                       // server address
    port: u32,                             // server port
    backend: &'static ArcSwap<DNSBackend>, // server's data store
    rx: flume::Receiver<()>,               // kill switch receiver
    resolv_conf: resolv_conf::Config,      // host's parsed /etc/resolv.conf
    no_proxy: bool,                        // do not forward to external resolvers
}

impl CoreDns {
    // Most of the arg can be removed in design refactor.
    // so dont create a struct for this now.
    pub fn new(
        address: IpAddr,
        port: u32,
        network_name: String,
        backend: &'static ArcSwap<DNSBackend>,
        rx: flume::Receiver<()>,
        no_proxy: bool,
    ) -> anyhow::Result<Self> {
        // this does not have to be unique, if we fail getting server name later
        // start with empty name
        let mut name: Name = Name::new();

        if network_name.len() > 10 {
            // to long to set this as name of dns server strip only first 10 chars
            // trust dns limitation, this is nothing to worry about since server name
            // has nothing to do without DNS logic, name can be random as well.
            if let Ok(n) = Name::parse(&network_name[..10], None) {
                name = n;
            }
        } else if let Ok(n) = Name::parse(&network_name, None) {
            name = n;
        }

        let mut resolv_conf: resolv_conf::Config = resolv_conf::Config::new();
        let mut buf = Vec::with_capacity(4096);
        if let Ok(mut f) = File::open("/etc/resolv.conf") {
            if f.read_to_end(&mut buf).is_ok() {
                if let Ok(conf) = resolv_conf::Config::parse(&buf) {
                    resolv_conf = conf;
                }
            }
        }

        Ok(CoreDns {
            name,
            network_name,
            address,
            port,
            backend,
            rx,
            resolv_conf,
            no_proxy,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        tokio::try_join!(self.register_port())?;
        Ok(())
    }

    // registers port supports udp for now
    async fn register_port(&mut self) -> anyhow::Result<()> {
        debug!("Starting listen on udp {:?}:{}", self.address, self.port);

        // Do we need to serve on tcp anywhere in future ?
        let socket = UdpSocket::bind(format!("{}:{}", self.address, self.port)).await?;
        let address = SocketAddr::new(self.address, self.port.try_into().unwrap());
        let (mut receiver, sender_original) = UdpStream::with_bound(socket, address);

        loop {
            tokio::select! {
                _ = self.rx.recv_async() => {
                    break;
                },
                v = receiver.next() => {
                    let msg_received = match v {
                        Some(value) => value,
                        None => {
                            // None received, nothing to process so continue
                            debug!("None recevied from stream, continue the loop");
                            continue;
                        }
                    };
                    self.process_message(msg_received, &sender_original);
                },
            }
        }
        Ok(())
    }

    fn process_message(
        &self,
        msg_received: Result<SerialMessage, Error>,
        sender_original: &BufDnsStreamHandle,
    ) {
        let msg = match msg_received {
            Ok(msg) => msg,
            Err(e) => {
                error!("Error parsing dns message {:?}", e);
                return;
            }
        };
        let backend = self.backend.load();
        let src_address = msg.addr();
        let mut sender = sender_original.with_remote_addr(src_address);
        let (request_name, record_type, mut req) = match parse_dns_msg(msg) {
            Some((name, record_type, req)) => (name, record_type, req),
            _ => {
                error!("None received while parsing dns message, this is not expected server will ignore this message");
                return;
            }
        };
        let request_name_string = request_name.to_string();

        let mut resolved_ip_list: Vec<IpAddr> = Vec::new();

        // Create debug and trace info for key parameters.
        trace!("server name: {:?}", self.name.to_ascii());
        debug!("request source address: {:?}", src_address);
        trace!("requested record type: {:?}", record_type);
        debug!(
            "checking if backend has entry for: {:?}",
            &request_name_string
        );
        trace!("server backend.name_mappings: {:?}", backend.name_mappings);
        trace!("server backend.ip_mappings: {:?}", backend.ip_mappings);

        // if record type is PTR try resolving early and return if record found
        if record_type == RecordType::PTR {
            if let Some(msg) = reply_ptr(&request_name_string, &backend, src_address, &req) {
                reply(&mut sender, src_address, &msg);
                return;
            }
        }

        // attempt intra network resolution
        match backend.lookup(&src_address.ip(), &request_name_string) {
            // If we go success from backend lookup
            DNSResult::Success(_ip_vec) => {
                debug!("Found backend lookup");
                resolved_ip_list = _ip_vec;
            }
            // For everything else assume the src_address was not in ip_mappings
            _ => {
                debug!("No backend lookup found, try resolving in current resolvers entry");
                if let Some(container_mappings) = backend.name_mappings.get(&self.network_name) {
                    if let Some(ips) = container_mappings.get(&request_name_string) {
                        resolved_ip_list.clone_from(ips);
                    }
                }
            }
        }
        if !resolved_ip_list.is_empty() {
            if record_type == RecordType::A {
                for record_addr in resolved_ip_list {
                    if let IpAddr::V4(ipv4) = record_addr {
                        req.add_answer(
                            Record::new()
                                .set_name(request_name.clone())
                                .set_ttl(CONTAINER_TTL)
                                .set_rr_type(RecordType::A)
                                .set_dns_class(DNSClass::IN)
                                .set_data(Some(RData::A(rdata::A(ipv4))))
                                .clone(),
                        );
                    }
                }
            } else if record_type == RecordType::AAAA {
                for record_addr in resolved_ip_list {
                    if let IpAddr::V6(ipv6) = record_addr {
                        req.add_answer(
                            Record::new()
                                .set_name(request_name.clone())
                                .set_ttl(CONTAINER_TTL)
                                .set_rr_type(RecordType::AAAA)
                                .set_dns_class(DNSClass::IN)
                                .set_data(Some(RData::AAAA(rdata::AAAA(ipv6))))
                                .clone(),
                        );
                    }
                }
            }
            reply(&mut sender, src_address, &req);
        } else {
            debug!(
                "Not found, forwarding dns request for {:?}",
                &request_name_string
            );
            if self.no_proxy
                || backend.ctr_is_internal(&src_address.ip())
                || request_name_string.ends_with(&backend.search_domain)
                || request_name_string.matches('.').count() == 1
            {
                let mut nx_message = req.clone();
                nx_message.set_response_code(ResponseCode::NXDomain);
                reply(&mut sender, src_address, &nx_message);
            } else {
                let mut upstream_resolvers = self.resolv_conf.nameservers.clone();
                let mut nameservers_scoped: Vec<ScopedIp> = Vec::new();
                // Add resolvers configured for container
                if let Some(Some(dns_servers)) = backend.ctr_dns_server.get(&src_address.ip()) {
                    for dns_server in dns_servers.iter() {
                        nameservers_scoped.push(ScopedIp::from(*dns_server));
                    }
                    // Add network scoped resolvers only if container specific resolvers were not configured
                } else if let Some(network_dns_servers) =
                    backend.get_network_scoped_resolvers(&src_address.ip())
                {
                    for dns_server in network_dns_servers.iter() {
                        nameservers_scoped.push(ScopedIp::from(*dns_server));
                    }
                }
                // Override host resolvers with custom resolvers if any  were
                // configured for container or network.
                if !nameservers_scoped.is_empty() {
                    upstream_resolvers = nameservers_scoped;
                }

                tokio::spawn(async move {
                    // forward dns request to hosts's /etc/resolv.conf
                    for nameserver in &upstream_resolvers {
                        let connection = UdpClientStream::<UdpSocket>::new(SocketAddr::new(
                            nameserver.into(),
                            53,
                        ));

                        if let Ok((cl, req_sender)) = AsyncClient::connect(connection).await {
                            tokio::spawn(req_sender);
                            if let Some(resp) = forward_dns_req(cl, req.clone()).await {
                                if reply(&mut sender, src_address, &resp).is_some() {
                                    // request resolved from following resolver so
                                    // break and don't try other resolvers
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
    }
}

fn reply(sender: &mut BufDnsStreamHandle, socket_addr: SocketAddr, msg: &Message) -> Option<()> {
    let id = msg.id();
    let mut msg_mut = msg.clone();
    msg_mut.set_message_type(MessageType::Response);
    // If `RD` is set and `RA` is false set `RA`.
    if msg.recursion_desired() && !msg.recursion_available() {
        msg_mut.set_recursion_available(true);
    }
    let response = SerialMessage::new(msg_mut.to_vec().ok()?, socket_addr);

    match sender.send(response) {
        Ok(_) => {
            debug!("[{}] success reponse", id);
        }
        Err(e) => {
            error!("[{}] fail response: {:?}", id, e);
        }
    }

    Some(())
}

fn parse_dns_msg(body: SerialMessage) -> Option<(Name, RecordType, Message)> {
    match Message::from_vec(body.bytes()) {
        Ok(msg) => {
            let mut name = Name::default();
            let mut record_type: RecordType = RecordType::A;

            let parsed_msg = format!(
                "[{}] parsed message body: {} edns: {}",
                msg.id(),
                msg.queries()
                    .first()
                    .map(|q| {
                        name = q.name().clone();
                        record_type = q.query_type();

                        format!("{} {} {}", q.name(), q.query_type(), q.query_class(),)
                    })
                    .unwrap_or_else(Default::default,),
                msg.extensions().is_some(),
            );

            debug!("parsed message {:?}", parsed_msg);

            Some((name, record_type, msg))
        }
        Err(e) => {
            warn!("Failed while parsing message: {}", e);
            None
        }
    }
}

async fn forward_dns_req(cl: AsyncClient, message: Message) -> Option<Message> {
    let req = DnsRequest::new(message, Default::default());
    let id = req.id();

    match cl.send(req).try_next().await {
        Ok(Some(response)) => {
            for answer in response.answers() {
                debug!(
                    "{} {} {} {} => {:#?}",
                    id,
                    answer.name().to_string(),
                    answer.record_type(),
                    answer.dns_class(),
                    answer.data(),
                );
            }
            let mut response_message = response.into_message();
            response_message.set_id(id);
            Some(response_message)
        }
        Ok(None) => {
            error!("{} dns request got empty response", id);
            None
        }
        Err(e) => {
            error!("{} dns request failed: {}", id, e);
            None
        }
    }
}

fn reply_ptr(
    name: &str,
    backend: &Guard<Arc<DNSBackend>>,
    src_address: SocketAddr,
    req: &Message,
) -> Option<Message> {
    let ptr_lookup_ip: String;
    // Are we IPv4 or IPv6?

    match name.strip_suffix(".in-addr.arpa.") {
        Some(n) => ptr_lookup_ip = n.split('.').rev().collect::<Vec<&str>>().join("."),
        None => {
            // not ipv4
            match name.strip_suffix(".ip6.arpa.") {
                Some(n) => {
                    // ipv6 string is 39 chars max
                    let mut tmp_ip = String::with_capacity(40);
                    for (i, c) in n.split('.').rev().enumerate() {
                        tmp_ip.push_str(c);
                        // insert colon after 4 hex chars but not at the end
                        if i % 4 == 3 && i < 31 {
                            tmp_ip.push(':');
                        }
                    }
                    ptr_lookup_ip = tmp_ip;
                }
                // neither ipv4 or ipv6, something we do not understand
                None => return None,
            }
        }
    }

    trace!("Performing reverse lookup for ip: {}", &ptr_lookup_ip);

    // We should probably log malformed queries, but for now if-let should be fine.
    if let Ok(lookup_ip) = ptr_lookup_ip.parse() {
        if let Some(reverse_lookup) = backend.reverse_lookup(&src_address.ip(), &lookup_ip) {
            let mut req_clone = req.clone();
            for entry in reverse_lookup {
                if let Ok(answer) = Name::from_ascii(format!("{}.", entry)) {
                    req_clone.add_answer(
                        Record::new()
                            .set_name(Name::from_str_relaxed(name).unwrap_or_default())
                            .set_ttl(CONTAINER_TTL)
                            .set_rr_type(RecordType::PTR)
                            .set_dns_class(DNSClass::IN)
                            .set_data(Some(RData::PTR(rdata::PTR(answer))))
                            .clone(),
                    );
                }
            }
            return Some(req_clone);
        }
    };
    None
}
