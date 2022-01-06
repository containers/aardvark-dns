use crate::config;
use crate::dns::coredns::CoreDns;
use log::debug;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;

pub fn serve(_config_path: &str) -> Result<(), std::io::Error> {
    match config::parse_configs(_config_path) {
        Ok((_backend, listen_ip_v4, listen_ip_v6)) => {
            debug!("Successfully parsed config");
            debug!("Backend ip {:?}", _backend.ip_mappings);
            debug!("Backend name {:?}", _backend.name_mappings);
            debug!("Listen v4 ip {:?}", listen_ip_v4);
            debug!("Listen v6 ip {:?}", listen_ip_v6);

            // TODO: this is just a placeholder for single config just to make MVP working
            // this will be replaced by actual logic
            let ip_list = listen_ip_v4.get("podman").unwrap();
            if let Err(e) = start_dns_server_v4("podman", ip_list[0], _backend.name_mappings) {
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
async fn start_dns_server_v4(
    name: &str,
    addr: Ipv4Addr,
    name_mappings: HashMap<String, HashMap<String, Vec<IpAddr>>>,
) -> Result<(), std::io::Error> {
    //let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let forward = Ipv4Addr::new(1, 1, 1, 1);
    match CoreDns::new(
        IpAddr::V4(addr),
        5533 as u32,
        name,
        IpAddr::V4(forward),
        53 as u16,
    )
    .await
    {
        Ok(mut server) => {
            let container_mappings = name_mappings.get(name).unwrap();
            for (key, value) in container_mappings {
                debug!("Adding record for {:?} / {:?}", key, value[0]);
                server.update_record(key, value[0], 86400);
            }
            match server.run().await {
                Ok(_) => Ok(()),
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("unable to start CoreDns server: {}", e),
                    ))
                }
            }
        }
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unable to create CoreDns server: {}", e),
            ))
        }
    }
}
