use crate::backend::DNSBackend;
use crate::backend::DNSResult;
use crate::error::AardvarkResult;
use arc_swap::ArcSwap;
use arc_swap::Guard;
use futures_util::StreamExt;
use futures_util::TryStreamExt;
use hickory_client::{client::AsyncClient, proto::xfer::SerialMessage, rr::rdata, rr::Name};
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::DnsUdpSocket;
use hickory_proto::{
    iocompat::AsyncIoTokioAsStd,
    op::{Message, MessageType, ResponseCode},
    rr::{DNSClass, RData, Record, RecordType},
    tcp::TcpStream,
    udp::{UdpClientStream, UdpStream},
    xfer::{dns_handle::DnsHandle, BufDnsStreamHandle, DnsRequest},
    DnsStreamHandle,
};
use log::{debug, error, trace, warn};
use resolv_conf;
use resolv_conf::ScopedIp;
use std::io::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;

// Containers can be recreated with different ips quickly so
// do not let the clients cache to dns response for to long,
// aardvark-dns runs on the same host so caching is not that important.
// see https://github.com/containers/netavark/discussions/644
const CONTAINER_TTL: u32 = 60;

pub struct CoreDns {
    rx: flume::Receiver<()>, // kill switch receiver
    inner: CoreDnsData,
}

#[derive(Clone)]
struct CoreDnsData {
    network_name: String,                   // raw network name
    backend: &'static ArcSwap<DNSBackend>,  // server's data store
    no_proxy: bool,                         // do not forward to external resolvers
    nameservers: Arc<Mutex<Vec<ScopedIp>>>, // host nameservers from resolv.conf
}

enum Protocol {
    Udp,
    Tcp,
}

trait CoreDnsUdp: DnsUdpSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

impl CoreDnsUdp for tokio::net::UdpSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.local_addr()
    }
}

impl CoreDns {
    // Most of the arg can be removed in design refactor.
    // so dont create a struct for this now.
    pub fn new(
        network_name: String,
        backend: &'static ArcSwap<DNSBackend>,
        rx: flume::Receiver<()>,
        no_proxy: bool,
        nameservers: Arc<Mutex<Vec<ScopedIp>>>,
    ) -> Self {
        CoreDns {
            rx,
            inner: CoreDnsData {
                network_name,
                backend,
                no_proxy,
                nameservers,
            },
        }
    }

    pub async fn run(
        &self,
        udp_socket: impl CoreDnsUdp + 'static,
        tcp_listener: TcpListener,
    ) -> AardvarkResult<()> {
        let address = udp_socket.local_addr()?;
        let (mut receiver, sender_original) = UdpStream::with_bound(udp_socket, address);

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
                    Self::process_message(&self.inner, msg_received, &sender_original, Protocol::Udp).await;
                },
                res = tcp_listener.accept() => {
                    match res {
                        Ok((sock,addr)) => {
                            tokio::spawn(Self::process_tcp_stream(self.inner.clone(), sock, addr));
                        }
                        Err(e) => {
                            error!("Failed to accept new tcp connection: {e}");
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn process_tcp_stream(
        data: CoreDnsData,
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
    ) {
        let (mut hickory_stream, sender_original) =
            TcpStream::from_stream(AsyncIoTokioAsStd(stream), peer);

        // It is possible for a client to keep the tcp socket open forever and never send any data,
        // we do not want this so add a 3s timeout then we close the socket.
        match tokio::time::timeout(Duration::from_secs(3), hickory_stream.next()).await {
            Ok(message) => {
                if let Some(msg) = message {
                    Self::process_message(&data, msg, &sender_original, Protocol::Tcp).await;
                    // The API is a bit strange, first time we call next we get the message,
                    // but we must call again to send our reply back
                    hickory_stream.next().await;
                }
            }
            Err(_) => debug!(
                "Tcp connection {} was cancelled after 3s as it took to long to receive message",
                peer
            ),
        }
    }

    async fn process_message(
        data: &CoreDnsData,
        msg_received: Result<SerialMessage, Error>,
        sender_original: &BufDnsStreamHandle,
        proto: Protocol,
    ) {
        let msg = match msg_received {
            Ok(msg) => msg,
            Err(e) => {
                error!("Error parsing dns message {:?}", e);
                return;
            }
        };
        let backend = data.backend.load();
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

        // Create debug and trace info for key parameters.
        trace!("server network name: {:?}", data.network_name);
        debug!("request source address: {:?}", src_address);
        trace!("requested record type: {:?}", record_type);
        debug!(
            "checking if backend has entry for: {:?}",
            &request_name_string
        );
        trace!("server backend.name_mappings: {:?}", backend.name_mappings);
        trace!("server backend.ip_mappings: {:?}", backend.ip_mappings);

        match record_type {
            RecordType::PTR => {
                if let Some(msg) = reply_ptr(&request_name_string, &backend, src_address, &req) {
                    reply(&mut sender, src_address, &msg);
                    return;
                }
                // No match found, forwarding below.
            }
            RecordType::A | RecordType::AAAA => {
                if let Some(msg) = reply_ip(
                    &request_name_string,
                    &request_name,
                    &data.network_name,
                    record_type,
                    &backend,
                    src_address,
                    &mut req,
                ) {
                    reply(&mut sender, src_address, msg);
                    return;
                }
                // No match found, forwarding below.
            }

            // TODO: handle MX here like docker does

            // We do not handle this request type so do nothing,
            // we forward the request to upstream resolvers below.
            _ => {}
        };

        // are we allowed to forward?
        if data.no_proxy
            || backend.ctr_is_internal(&src_address.ip())
            || request_name_string.ends_with(&backend.search_domain)
            || request_name_string.matches('.').count() == 1
        {
            let mut nx_message = req.clone();
            nx_message.set_response_code(ResponseCode::NXDomain);
            reply(&mut sender, src_address, &nx_message);
        } else {
            debug!(
                "Forwarding dns request for {} type: {}",
                &request_name_string, record_type
            );
            let mut nameservers: Vec<ScopedIp> = Vec::new();
            // Add resolvers configured for container
            if let Some(Some(dns_servers)) = backend.ctr_dns_server.get(&src_address.ip()) {
                for dns_server in dns_servers.iter() {
                    nameservers.push(ScopedIp::from(*dns_server));
                }
                // Add network scoped resolvers only if container specific resolvers were not configured
            } else if let Some(network_dns_servers) =
                backend.get_network_scoped_resolvers(&src_address.ip())
            {
                for dns_server in network_dns_servers.iter() {
                    nameservers.push(ScopedIp::from(*dns_server));
                }
            }
            // Use host resolvers if no custom resolvers are set for the container.
            if nameservers.is_empty() {
                nameservers.clone_from(&data.nameservers.lock().expect("lock nameservers"));
            }

            match proto {
                Protocol::Udp => {
                    tokio::spawn(Self::forward_to_servers(
                        nameservers,
                        sender,
                        src_address,
                        req,
                        proto,
                    ));
                }
                Protocol::Tcp => {
                    // we already spawned a new future when we read the message so there is no need to spawn another one
                    Self::forward_to_servers(nameservers, sender, src_address, req, proto).await;
                }
            }
        }
    }

    async fn forward_to_servers(
        nameservers: Vec<ScopedIp>,
        mut sender: BufDnsStreamHandle,
        src_address: SocketAddr,
        req: Message,
        proto: Protocol,
    ) {
        // forward dns request to hosts's /etc/resolv.conf
        for nameserver in &nameservers {
            let addr = SocketAddr::new(nameserver.into(), 53);
            let (client, handle) = match proto {
                Protocol::Udp => {
                    let stream = UdpClientStream::<UdpSocket>::new(addr);
                    let (cl, bg) = match AsyncClient::connect(stream).await {
                        Ok(a) => a,
                        Err(e) => {
                            debug!("Failed to connect to {addr}: {e}");
                            continue;
                        }
                    };
                    let handle = tokio::spawn(bg);
                    (cl, handle)
                }
                Protocol::Tcp => {
                    let (stream, sender) =
                        TcpClientStream::<AsyncIoTokioAsStd<tokio::net::TcpStream>>::new(addr);
                    let (cl, bg) = match AsyncClient::new(stream, sender, None).await {
                        Ok(a) => a,
                        Err(e) => {
                            debug!("Failed to connect to {addr}: {e}");
                            continue;
                        }
                    };
                    let handle = tokio::spawn(bg);
                    (cl, handle)
                }
            };

            if let Some(resp) = forward_dns_req(client, req.clone()).await {
                if reply(&mut sender, src_address, &resp).is_some() {
                    // request resolved from following resolver so
                    // break and don't try other resolvers
                    break;
                }
            }
            handle.abort();
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

fn reply_ip<'a>(
    name: &str,
    request_name: &Name,
    network_name: &str,
    record_type: RecordType,
    backend: &Guard<Arc<DNSBackend>>,
    src_address: SocketAddr,
    req: &'a mut Message,
) -> Option<&'a Message> {
    let mut resolved_ip_list: Vec<IpAddr> = Vec::new();
    // attempt intra network resolution
    match backend.lookup(&src_address.ip(), name) {
        // If we go success from backend lookup
        DNSResult::Success(_ip_vec) => {
            debug!("Found backend lookup");
            resolved_ip_list = _ip_vec;
        }
        // For everything else assume the src_address was not in ip_mappings
        _ => {
            debug!("No backend lookup found, try resolving in current resolvers entry");
            if let Some(container_mappings) = backend.name_mappings.get(network_name) {
                if let Some(ips) = container_mappings.get(name) {
                    resolved_ip_list.clone_from(ips);
                }
            }
        }
    }
    if resolved_ip_list.is_empty() {
        return None;
    }
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
    Some(req)
}

#[cfg(test)]
mod test {
    use std::{
        fmt::Display,
        future::ready,
        io,
        sync::OnceLock,
        task::{Context, Poll},
    };

    use clap::error::ErrorKind;
    use hickory_proto::{op::Query, xfer::DnsRequestSender};
    use tokio::time::error::Elapsed;

    use super::*;

    struct TestUdp;

    #[derive(Debug)]
    struct BrokenPipeError;

    impl Display for BrokenPipeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "BrokenPipeError")
        }
    }

    impl std::error::Error for BrokenPipeError {}

    impl DnsUdpSocket for TestUdp {
        type Time = hickory_proto::TokioTime;

        fn poll_recv_from(
            &self,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<(usize, SocketAddr)>> {
            Poll::Ready(io::Result::Err(Error::new(
                std::io::ErrorKind::BrokenPipe,
                BrokenPipeError,
            )))
        }

        fn poll_send_to(
            &self,
            cx: &mut Context<'_>,
            buf: &[u8],
            target: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            unimplemented!()
        }
    }

    impl CoreDnsUdp for TestUdp {
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    // we need 2 threads or tokio::spawn will block since it never yields
    #[test_log::test(tokio::test(flavor = "multi_thread", worker_threads = 2))]
    async fn broken_pipe_in_udp_socket_exits() {
        static DNSBACKEND: OnceLock<ArcSwap<DNSBackend>> = OnceLock::new();
        let backend = DNSBACKEND.get_or_init(|| {
            ArcSwap::from(Arc::new(DNSBackend {
                ctr_dns_server: Default::default(),
                network_dns_server: Default::default(),
                network_is_internal: Default::default(),
                search_domain: Default::default(),
                ip_mappings: Default::default(),
                name_mappings: Default::default(),
                reverse_mappings: Default::default(),
            }))
        });

        let (_tx, rx) = flume::unbounded();

        let dns = CoreDns::new(
            "network_name".to_string(),
            backend,
            rx,
            false,
            Arc::new(Mutex::new(Vec::new())),
        );

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

        let handle = tokio::spawn(async move { dns.run(TestUdp, tcp_listener).await.unwrap() });
        let abort_handle = handle.abort_handle();

        // timeout or abort
        let result = tokio::time::timeout(Duration::from_secs(1), handle).await;
        if let Err(_) = result {
            // timed out...
            abort_handle.abort();
            panic!("tokio stuck in a loop");
        }
    }
}
