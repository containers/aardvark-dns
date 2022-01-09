use crate::backend::DNSBackend;
use crate::config;
use crate::dns::coredns::CoreDns;
use log::debug;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::thread;

// Will be only used by server to share backend
// across threads
#[derive(Clone)]
struct DNSBackendWithArc {
    pub backend: Arc<DNSBackend>,
}

pub fn serve(_config_path: &str) -> Result<(), std::io::Error> {
    match config::parse_configs(_config_path) {
        Ok((backend, listen_ip_v4, listen_ip_v6)) => {
            let mut thread_handles = vec![];

            // Prevent memory duplication: since backend is immutable across threads so create Arc and share
            let shareable_arc = DNSBackendWithArc {
                backend: Arc::from(backend),
            };

            debug!("Successfully parsed config");
            debug!("Listen v4 ip {:?}", listen_ip_v4);
            debug!("Listen v6 ip {:?}", listen_ip_v6);

            for (network_name, listen_ip_list) in listen_ip_v4 {
                for ip in listen_ip_list {
                    let network_name_clone = network_name.clone();
                    let backend_arc_clone = shareable_arc.clone();
                    let handle = thread::spawn(move || {
                        if let Err(_e) =
                            start_dns_server(&network_name_clone, IpAddr::V4(ip), backend_arc_clone)
                        {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Error while invoking start_dns_server: {}", _e),
                            ));
                        }

                        Ok(())
                    });

                    thread_handles.push(handle);
                }
            }

            for handle in thread_handles {
                let _ = handle.join().unwrap();
            }
            return Ok(());
        }
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unable to parse config: {}", e),
            ))
        }
    }
}

#[tokio::main]
async fn start_dns_server(
    name: &str,
    addr: IpAddr,
    backend_arc: DNSBackendWithArc,
) -> Result<(), std::io::Error> {
    let forward: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    match CoreDns::new(
        addr,
        5533 as u32,
        name,
        forward,
        53 as u16,
        backend_arc.backend,
    )
    .await
    {
        Ok(mut server) => match server.run().await {
            Ok(_) => Ok(()),
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("unable to start CoreDns server: {}", e),
                ))
            }
        },
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unable to create CoreDns server: {}", e),
            ))
        }
    }
}
