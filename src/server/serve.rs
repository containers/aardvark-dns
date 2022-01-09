use crate::backend::DNSBackend;
use crate::config;
use crate::dns::coredns::CoreDns;
use log::debug;
use std::net::IpAddr;
use std::net::Ipv4Addr;

pub fn serve(_config_path: &str) -> Result<(), std::io::Error> {
    match config::parse_configs(_config_path) {
        Ok((_backend, listen_ip_v4, listen_ip_v6)) => {
            debug!("Successfully parsed config");
            debug!("Listen v4 ip {:?}", listen_ip_v4);
            debug!("Listen v6 ip {:?}", listen_ip_v6);

            // TODO: this is just a placeholder for single config just to make MVP working
            // this will be replaced by actual logic
            let ip_list = listen_ip_v4.get("podman").unwrap();
            if let Err(e) = start_dns_server_v4("podman", ip_list[0], _backend) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Error while invoking start_dns_server: {}", e),
                ));
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
async fn start_dns_server_v4(
    name: &str,
    addr: Ipv4Addr,
    backend: DNSBackend,
) -> Result<(), std::io::Error> {
    let forward = Ipv4Addr::new(1, 1, 1, 1);
    match CoreDns::new(
        IpAddr::V4(addr),
        5533 as u32,
        name,
        IpAddr::V4(forward),
        53 as u16,
        backend,
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
