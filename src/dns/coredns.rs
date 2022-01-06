use futures_util::StreamExt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::net::UdpSocket;
use trust_dns_client::{
    client::AsyncClient,
    proto::{rr::dnssec::SupportedAlgorithms, xfer::SerialMessage},
    rr::{LowerName, Name},
};
use trust_dns_proto::{
    op::Message,
    rr::{DNSClass, RData, Record, RecordType},
    udp::{UdpClientStream, UdpStream},
    xfer::{dns_handle::DnsHandle, DnsRequest},
    BufStreamHandle,
};

use log::{debug, error, warn};
use trust_dns_server::{
    authority::{Authority, ZoneType},
    store::in_memory::InMemoryAuthority,
};

pub struct CoreDns {
    name: Name,                   // name or origin
    address: IpAddr,              // server address
    port: u32,                    // server port
    authority: InMemoryAuthority, // server authority
    cl: AsyncClient,              //server client
}

impl CoreDns {
    pub async fn new(
        address: IpAddr,
        port: u32,
        name: &str,
        forward_addr: IpAddr,
        forward_port: u16,
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
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        tokio::try_join!(self.register_port())?;

        Ok(())
    }

    pub fn update_record(&mut self, name: &str, addr: IpAddr, ttl: u32) {
        let origin: Name = Name::parse(name.clone(), None).unwrap();
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

        // Do we need to serve on tcp anywhere in future ?
        let socket = UdpSocket::bind(format!("{}:{}", self.address, self.port)).await?;
        let (mut receiver, sender) = UdpStream::with_bound(socket);

        while let Some(message) = receiver.next().await {
            match message {
                Ok(msg) => {
                    let client = self.cl.clone();
                    let src_address = msg.addr().clone();
                    let sender = sender.clone();
                    let (name, record_type, mut req) = parse_dns_msg(msg).unwrap();

                    debug!("server orgin/name: {:?}", self.name);
                    debug!("checking if authority has entry for: {:?}", name);

                    match self
                        .authority
                        .lookup(
                            &LowerName::from_str(name.as_str())?,
                            record_type,
                            false,
                            SupportedAlgorithms::new(),
                        )
                        .await
                    {
                        Ok(lookup) => {
                            debug!("not found in auth: {:?}", lookup);

                            if let Some(record) = lookup.iter().next() {
                                req.add_answer(Record::from_rdata(
                                    Name::from_str(name.as_str())?,
                                    600,
                                    record.clone().into_data(),
                                ));
                            }

                            reply(sender, src_address, &req);
                        }
                        Err(_) => {
                            debug!("Not found, forwarding dns request for {:?}", name);
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
        }

        Ok(())
    }
}

fn reply(mut sender: BufStreamHandle, socket_addr: SocketAddr, msg: &Message) -> Option<()> {
    let id = msg.id();
    let response = SerialMessage::new(msg.to_vec().ok()?, socket_addr);

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

            debug!(
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
