use crate::backend::DNSBackend;
use crate::backend::DNSResult;
use futures_util::StreamExt;
use futures_util::TryStreamExt;
use log::{debug, error, trace, warn};
use resolv_conf;
use resolv_conf::ScopedIp;
use std::convert::TryInto;
use std::env;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use trust_dns_client::{client::AsyncClient, proto::xfer::SerialMessage, rr::Name};
use trust_dns_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{DNSClass, RData, Record, RecordType},
    udp::{UdpClientStream, UdpStream},
    xfer::{dns_handle::DnsHandle, BufDnsStreamHandle, DnsRequest},
    DnsStreamHandle,
};

pub struct CoreDns {
    name: Name,                          // name or origin
    network_name: String,                // raw network name
    address: IpAddr,                     // server address
    port: u32,                           // server port
    backend: Arc<DNSBackend>,            // server's data store
    kill_switch: Arc<Mutex<bool>>,       // global kill_switch
    filter_search_domain: String,        // filter_search_domain
    rx: async_broadcast::Receiver<bool>, // kill switch receiver
    resolv_conf: resolv_conf::Config,    // host's parsed /etc/resolv.conf
}

impl CoreDns {
    // Most of the arg can be removed in design refactor.
    // so dont create a struct for this now.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        address: IpAddr,
        port: u32,
        network_name: &str,
        forward_addr: IpAddr,
        forward_port: u16,
        backend: Arc<DNSBackend>,
        kill_switch: Arc<Mutex<bool>>,
        filter_search_domain: String,
        rx: async_broadcast::Receiver<bool>,
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
        } else if let Ok(n) = Name::parse(network_name, None) {
            name = n;
        }

        debug!(
            "Will Forward dns requests to udp://{:?}:{}",
            forward_addr, forward_port,
        );

        let mut resolv_conf: resolv_conf::Config = resolv_conf::Config::new();
        let mut buf = Vec::with_capacity(4096);
        if let Ok(mut f) = File::open("/etc/resolv.conf") {
            if f.read_to_end(&mut buf).is_ok() {
                if let Ok(conf) = resolv_conf::Config::parse(&buf) {
                    resolv_conf = conf;
                }
            }
        }

        let network_name = network_name.to_owned();

        Ok(CoreDns {
            name,
            network_name,
            address,
            port,
            backend,
            kill_switch,
            filter_search_domain,
            rx,
            resolv_conf,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        tokio::try_join!(self.register_port())?;
        Ok(())
    }

    // registers port supports udp for now
    async fn register_port(&mut self) -> anyhow::Result<()> {
        debug!("Starting listen on udp {:?}:{}", self.address, self.port);

        let no_proxy: bool = matches!(env::var("AARDVARK_NO_PROXY"), Ok(_));

        // Do we need to serve on tcp anywhere in future ?
        let socket = UdpSocket::bind(format!("{}:{}", self.address, self.port)).await?;
        let address = SocketAddr::new(self.address, self.port.try_into().unwrap());
        let (mut receiver, sender_original) = UdpStream::with_bound(socket, address);

        loop {
            tokio::select! {
                _ = self.rx.recv() => {
                    break;
                },
                v = receiver.next() => {
                    let msg_received = match v {
                        Some(value) => value,
                        _ => {
                            // None received, nothing to process so continue
                            debug!("None recevied from stream, continue the loop");
                            continue;
                        }
                    };
                    match msg_received {
                        Ok(msg) => {
                            let src_address = msg.addr();
                            let mut dns_resolver = self.resolv_conf.clone();
                            let sender = sender_original.clone().with_remote_addr(src_address);
                            let (name, record_type, mut req) = match parse_dns_msg(msg) {
                                Some((name, record_type, req)) => (name, record_type, req),
                                _ => {
                                    error!("None received while parsing dns message, this is not expected server will ignore this message");
                                    continue;
                                }
                            };
                            let mut resolved_ip_list: Vec<IpAddr> = Vec::new();
                            let mut nameservers_scoped: Vec<ScopedIp> = Vec::new();
                            // Add resolvers configured for container
                            if let Some(Some(dns_servers)) = self.backend.ctr_dns_server.get(&src_address.ip()) {
                                    if !dns_servers.is_empty() {
                                        for dns_server in dns_servers.iter() {
                                            nameservers_scoped.push(ScopedIp::from(*dns_server));
                                        }
                                    }
                            // Add network scoped resolvers only if container specific resolvers were not configured
                            } else if let Some(network_dns_servers) = self.backend.get_network_scoped_resolvers(&src_address.ip()) {
                                        for dns_server in network_dns_servers.iter() {
                                                nameservers_scoped.push(ScopedIp::from(*dns_server));
                                        }
                            }
                            // Override host resolvers with custom resolvers if any  were
                            // configured for container or network.
                            if !nameservers_scoped.is_empty() {
                                        dns_resolver = resolv_conf::Config::new();
                                        dns_resolver.nameservers = nameservers_scoped;
                            }

                            // Create debug and trace info for key parameters.
                            trace!("server name: {:?}", self.name.to_ascii());
                            debug!("request source address: {:?}", src_address);
                            trace!("requested record type: {:?}", record_type);
                            debug!("checking if backend has entry for: {:?}", name);
                            trace!(
                                "server backend.name_mappings: {:?}",
                                self.backend.name_mappings
                            );
                            trace!("server backend.ip_mappings: {:?}", self.backend.ip_mappings);
                            trace!(
                                 "server backend kill switch: {:?}",
                                 self.kill_switch.lock().is_ok()
                            );


                            // if record type is PTR try resolving early and return if record found
                            if record_type == RecordType::PTR {
                                let mut ptr_lookup_ip: String;
                                // Are we IPv4 or IPv6?
                                if name.contains(".in-addr.arpa.") {
                                    // IPv4
                                    ptr_lookup_ip = name.trim_end_matches(".in-addr.arpa.").split('.').rev().collect::<Vec<&str>>().join(".");
                                } else if name.contains(".ip6.arpa.") {
                                    // IPv6
                                    ptr_lookup_ip = name.trim_end_matches(".ip6.arpa.").split('.').rev().collect::<String>();
                                    // We removed all periods; now we need to insert a : every 4 characters.
                                    // split_off() reduces the original string to 4 characters and returns the remainder.
                                    // So append the 4-character and continue going until we run out of characters.
                                    let mut split: Vec<String> = Vec::new();
                                    while ptr_lookup_ip.len() > 4 {
                                        let tmp = ptr_lookup_ip.split_off(4);
                                        split.push(ptr_lookup_ip);
                                        ptr_lookup_ip = tmp;
                                    }
                                    // Length should be equal to 4 here, but just use > 0 for safety.
                                    if !ptr_lookup_ip.is_empty() {
                                        split.push(ptr_lookup_ip);
                                    }
                                    ptr_lookup_ip = split.join(":");
                                } else {
                                    // Not a valid address, so force parse() to fail
                                    // TODO: this is ugly and I don't like it
                                    ptr_lookup_ip = String::from("not an ip");
                                }

                                trace!("Performing lookup reverse lookup for ip: {:?}", ptr_lookup_ip.to_owned());
                                // We should probably log malformed queries, but for now if-let should be fine.
                                if let Ok(lookup_ip) = ptr_lookup_ip.parse() {
                                    if let Some(reverse_lookup) = self.backend.reverse_lookup(&src_address.ip(), &lookup_ip) {
                                        let mut req_clone = req.clone();
                                        for entry in reverse_lookup {
                                            if let Ok(answer) = Name::from_ascii(format!("{}.", entry)) {
                                                req_clone.add_answer(
                                                    Record::new()
                                                        .set_ttl(86400)
                                                        .set_rr_type(RecordType::PTR)
                                                        .set_dns_class(DNSClass::IN)
                                                        .set_data(Some(RData::PTR(answer)))
                                                        .clone(),
                                                );
                                            }
                                        }
                                        reply(sender.clone(), src_address, &req_clone);
                                    }
                                };
                            }

                            // attempt intra network resolution
                            match self.backend.lookup(&src_address.ip(), name.as_str()) {
                                // If we go success from backend lookup
                                DNSResult::Success(_ip_vec) => {
                                    debug!("Found backend lookup");
                                    resolved_ip_list = _ip_vec;
                                }
                                // For everything else assume the src_address was not in ip_mappings
                                _ => {
                                    debug!(
                                "No backend lookup found, try resolving in current resolvers entry"
                            );
                                    if let Some(container_mappings) = self.backend.name_mappings.get(&self.network_name) {
                                        for (key, value) in container_mappings {

                                            // if query contains search domain, strip it out.
                                            // Why? This is a workaround so aardvark works well
                                            // with setup which was created for dnsname/dnsmasq

                                            let mut request_name = name.as_str().to_owned();
                                            let mut filter_domain_ndots_complete = self.filter_search_domain.to_owned();
                                            filter_domain_ndots_complete.push('.');

                                            if request_name.ends_with(&self.filter_search_domain) {
                                                request_name = match request_name.strip_suffix(&self.filter_search_domain) {
                                                    Some(value) => value.to_string(),
                                                     _ => {
                                                        error!("Unable to parse string suffix, ignore parsing this request");
                                                        continue;
                                                    }
                                                };
                                                request_name.push('.');
                                            }
                                            if request_name.ends_with(&filter_domain_ndots_complete) {
                                                request_name = match request_name.strip_suffix(&filter_domain_ndots_complete) {
                                                    Some(value) => value.to_string(),
                                                     _ => {
                                                        error!("Unable to parse string suffix, ignore parsing this request");
                                                        continue;
                                                    }
                                                };
                                                request_name.push('.');
                                            }

                                            // convert key to fully qualified domain name
                                            let mut key_fqdn = key.to_owned();
                                            key_fqdn.push('.');
                                            if key_fqdn == request_name {
                                                resolved_ip_list = value.to_vec();
                                            }
                                        }
                                    }
                                }
                            }
                            let record_name: Name = match Name::from_str_relaxed(name.as_str()) {
                                Ok(name) => name,
                                Err(e) => {
                                    // log and continue server
                                    error!("Error while parsing record name: {:?}", e);
                                    continue;
                                }
                            };
                            if !resolved_ip_list.is_empty() {
                                if record_type == RecordType::A {
                                    for record_addr in resolved_ip_list {
                                        if let IpAddr::V4(ipv4) = record_addr {
                                            req.add_answer(
                                                Record::new()
                                                    .set_name(record_name.clone())
                                                    .set_ttl(86400)
                                                    .set_rr_type(RecordType::A)
                                                    .set_dns_class(DNSClass::IN)
                                                    .set_data(Some(RData::A(ipv4)))
                                                    .clone(),
                                            );
                                        }
                                    }
                                } else if record_type == RecordType::AAAA {
                                    for record_addr in resolved_ip_list {
                                        if let IpAddr::V6(ipv6) = record_addr {
                                            req.add_answer(
                                                Record::new()
                                                    .set_name(record_name.clone())
                                                    .set_ttl(86400)
                                                    .set_rr_type(RecordType::AAAA)
                                                    .set_dns_class(DNSClass::IN)
                                                    .set_data(Some(RData::AAAA(ipv6)))
                                                    .clone(),
                                            );
                                        }
                                    }
                                }
                                reply(sender, src_address, &req);
                            } else {
                                debug!("Not found, forwarding dns request for {:?}", name);
                                let request_name = name.as_str().to_owned();
                                let filter_search_domain_ndots = self.filter_search_domain.clone() + ".";
                                if no_proxy || request_name.ends_with(&self.filter_search_domain) || request_name.ends_with(&filter_search_domain_ndots) || request_name.matches('.').count() == 1  {
                                    let mut nx_message = req.clone();
                                    nx_message.set_response_code(ResponseCode::NXDomain);
                                    reply(sender.clone(), src_address, &nx_message);
                                } else {
                                    let nameservers = dns_resolver.nameservers.clone();
                                    tokio::spawn(async move {
                                        // forward dns request to hosts's /etc/resolv.conf
                                        for nameserver in nameservers {
                                            let connection = UdpClientStream::<UdpSocket>::new(SocketAddr::new(
                                                nameserver.into(),
                                                53,
                                            ));

                                            if let Ok((cl, req_sender)) = AsyncClient::connect(connection).await {
                                                tokio::spawn(req_sender);
                                                if let Some(resp) = forward_dns_req(cl, req.clone()).await {
                                                    if reply(sender.clone(), src_address, &resp).is_some() {
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

                        Err(e) => error!("Error parsing dns message {:?}", e),
                    }
                },
            }
        }

        Ok(()) //TODO: My IDE sees this as unreachable code.  Fix when refactoring
    }
}

fn reply(mut sender: BufDnsStreamHandle, socket_addr: SocketAddr, msg: &Message) -> Option<()> {
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

fn parse_dns_msg(body: SerialMessage) -> Option<(String, RecordType, Message)> {
    match Message::from_vec(body.bytes()) {
        Ok(msg) => {
            let mut name: String = "".to_string();
            let mut record_type: RecordType = RecordType::A;

            let parsed_msg = format!(
                "[{}] parsed message body: {} edns: {}",
                msg.id(),
                msg.queries()
                    .first()
                    .map(|q| {
                        name = q.name().to_string();
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

async fn forward_dns_req(mut cl: AsyncClient, message: Message) -> Option<Message> {
    let req = DnsRequest::new(message, Default::default());
    let id = req.id();

    match cl.send(req).try_next().await {
        Ok(Some(mut response)) => {
            response.set_id(id);
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
            Some(response.into())
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
