use crate::backend::DNSBackend;
use crate::backend::DNSResult;
use futures_util::StreamExt;
use log::{debug, error, trace, warn};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::time::{self, Duration};
use trust_dns_client::{client::AsyncClient, proto::xfer::SerialMessage, rr::Name};
use trust_dns_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{DNSClass, RData, Record, RecordType},
    udp::{UdpClientStream, UdpStream},
    xfer::{dns_handle::DnsHandle, DnsRequest},
    BufStreamHandle,
};
use trust_dns_server::{authority::ZoneType, store::in_memory::InMemoryAuthority};

pub struct CoreDns {
    name: Name,                    // name or origin
    address: IpAddr,               // server address
    port: u32,                     // server port
    authority: InMemoryAuthority,  // server authority
    cl: AsyncClient,               //server client
    backend: Arc<DNSBackend>,      // server's data store
    kill_switch: Arc<Mutex<bool>>, // global kill_swtich
    filter_search_domain: String,  // filter_search_domain
}

impl CoreDns {
    pub async fn new(
        address: IpAddr,
        port: u32,
        name: &str,
        forward_addr: IpAddr,
        forward_port: u16,
        backend: Arc<DNSBackend>,
        kill_switch: Arc<Mutex<bool>>,
        filter_search_domain: String,
    ) -> anyhow::Result<Self> {
        let name: Name = Name::parse(name, None).unwrap();
        let authority = InMemoryAuthority::empty(name.clone(), ZoneType::Primary, false);

        debug!(
            "Will Forward dns requests to udp://{:?}:{}",
            forward_addr, forward_port,
        );

        let connection = UdpClientStream::<UdpSocket>::new(SocketAddr::new(
            IpAddr::from(forward_addr),
            forward_port,
        ));

        let (cl, req_sender) = AsyncClient::connect(connection).await?;
        let _ = tokio::spawn(req_sender);

        Ok(CoreDns {
            name,
            address,
            port,
            authority,
            cl,
            backend,
            kill_switch,
            filter_search_domain,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        tokio::try_join!(self.register_port())?;
        Ok(())
    }

    pub fn update_record(&mut self, name: &str, addr: IpAddr, ttl: u32) {
        //Note: this is important we must accept `_` underscore in record name.
        // If IDNA fails try parsing with utf8, this is `RFC 952` breach but expected.
        // Accept create origin name from str_relaxed so we could use underscore
        let origin: Name = Name::from_str_relaxed(name).unwrap();
        match addr {
            IpAddr::V4(ipv4) => {
                self.authority.upsert(
                    Record::new()
                        .set_name(origin.clone())
                        .set_ttl(ttl)
                        .set_rr_type(RecordType::A)
                        .set_dns_class(DNSClass::IN)
                        .set_rdata(RData::A(ipv4))
                        .clone(),
                    0,
                );
            }
            IpAddr::V6(ipv6) => {
                self.authority.upsert(
                    Record::new()
                        .set_name(origin.clone())
                        .set_ttl(ttl)
                        .set_rr_type(RecordType::AAAA)
                        .set_dns_class(DNSClass::IN)
                        .set_rdata(RData::AAAA(ipv6))
                        .clone(),
                    0,
                );
            }
        }
    }

    // registers port supports udp for now
    async fn register_port(&self) -> anyhow::Result<()> {
        debug!("Starting listen on udp {:?}:{}", self.address, self.port);

        let no_proxy: bool = match env::var("AARDVARK_NO_PROXY") {
            Ok(_) => true,
            _ => false,
        };

        // Do we need to serve on tcp anywhere in future ?
        let socket = UdpSocket::bind(format!("{}:{}", self.address, self.port)).await?;
        let (mut receiver, sender) = UdpStream::with_bound(socket);

        // following delay is async and is responsible for invkoing kill_switch
        let non_blocking_delay = time::sleep(Duration::from_millis(50));
        tokio::pin!(non_blocking_delay);

        loop {
            tokio::select! {
                _ = &mut non_blocking_delay => {
                    if *self.kill_switch.lock().unwrap() {
                        break;
                    }
                },
                v = receiver.next() => {
                    match v.unwrap() {
                        Ok(msg) => {
                            let client = self.cl.clone();
                            let src_address = msg.addr().clone();
                            let sender = sender.clone();
                            let (name, record_type, mut req) = parse_dns_msg(msg).unwrap();
                            let mut resolved_ip_list: Vec<IpAddr> = Vec::new();

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
                                self.kill_switch.lock().unwrap()
                            );

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
                                    match self.backend.name_mappings.get(&self.name.to_ascii()) {
                                        Some(container_mappings) => {
                                            for (key, value) in container_mappings {

                                                // if query contains search domain, strip it out.
                                                // Why? This is a workaround so aardvark works well
                                                // with setup which was created for dnsname/dnsmasq

                                                let mut request_name = name.as_str().to_owned();
                                                let mut filter_domain_ndots_complete = self.filter_search_domain.to_owned();
                                                filter_domain_ndots_complete.push_str(".");

                                                if request_name.ends_with(&self.filter_search_domain) {
                                                    request_name = request_name.strip_suffix(&self.filter_search_domain).unwrap().to_string();
                                                    request_name.push_str(".");
                                                }
                                                if request_name.ends_with(&filter_domain_ndots_complete) {
                                                    request_name = request_name.strip_suffix(&filter_domain_ndots_complete).unwrap().to_string();
                                                    request_name.push_str(".");
                                                }

                                                // convert key to fully qualified domain name
                                                let mut key_fqdn = key.to_owned();
                                                key_fqdn.push_str(".");
                                                if key_fqdn == request_name {
                                                    resolved_ip_list = value.to_vec();
                                                }
                                            }
                                        }
                                        _ => { /*Nothing found request will be forwared to configured forwarder */
                                        }
                                    }
                                }
                            }
                            let record_name: Name = Name::from_str_relaxed(name.as_str()).unwrap();
                            if resolved_ip_list.len() > 0
                                && (record_type == RecordType::A || record_type == RecordType::AAAA)
                            {
                                for record_addr in resolved_ip_list {
                                    match record_addr {
                                        IpAddr::V4(ipv4) => {
                                            req.add_answer(
                                                Record::new()
                                                    .set_name(record_name.clone())
                                                    .set_ttl(86400)
                                                    .set_rr_type(RecordType::A)
                                                    .set_dns_class(DNSClass::IN)
                                                    .set_rdata(RData::A(ipv4))
                                                    .clone(),
                                            );
                                        }
                                        IpAddr::V6(ipv6) => {
                                            req.add_answer(
                                                Record::new()
                                                    .set_name(record_name.clone())
                                                    .set_ttl(86400)
                                                    .set_rr_type(RecordType::AAAA)
                                                    .set_dns_class(DNSClass::IN)
                                                    .set_rdata(RData::AAAA(ipv6))
                                                    .clone(),
                                            );
                                        }
                                    }
                                }
                                reply(sender, src_address, &req);
                            } else {
                                debug!("Not found, forwarding dns request for {:?}", name);
                                if no_proxy {
                                    let mut nx_message = req.clone();
                                    nx_message.set_response_code(ResponseCode::NXDomain);
                                    reply(sender.clone(), src_address, &nx_message).unwrap();
                                } else {
                                    tokio::spawn(async move {
                                        if let Some(resp) = forward_dns_req(client, req.clone()).await {
                                            reply(sender.clone(), src_address, &resp).unwrap();
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

        Ok(())
    }
}

fn reply(mut sender: BufStreamHandle, socket_addr: SocketAddr, msg: &Message) -> Option<()> {
    let id = msg.id();
    let mut msg_mut = msg.clone();
    msg_mut.set_message_type(MessageType::Response);
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

                        format!(
                            "{} {} {}",
                            q.name().to_string(),
                            q.query_type(),
                            q.query_class(),
                        )
                    })
                    .unwrap_or_else(|| Default::default(),),
                msg.edns().is_some(),
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

    match cl.send(req).await {
        Ok(mut response) => {
            response.set_id(id);
            for answer in response.answers() {
                debug!(
                    "{} {} {} {} => {}",
                    id,
                    answer.name().to_string(),
                    answer.record_type(),
                    answer.dns_class(),
                    answer.rdata(),
                );
            }
            Some(response.into())
        }
        Err(e) => {
            error!("{} dns request failed: {}", id, e);
            None
        }
    }
}
