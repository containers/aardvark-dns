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
            if let Err(e) = start_dns_server() {
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

// todo: this is just a dummy pass actual argument
#[tokio::main]
async fn start_dns_server() -> Result<(), std::io::Error> {
    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let forward = Ipv4Addr::new(1, 1, 1, 1);
    match CoreDns::new(
        IpAddr::V4(localhost),
        5533 as u32,
        "me",
        IpAddr::V4(forward),
        53 as u16,
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
