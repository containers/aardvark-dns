use crate::backend::DNSBackend;
use crate::config;
use crate::config::constants::AARDVARK_PID_FILE;
use crate::dns::coredns::CoreDns;
use log::{debug, error, info};
use signal_hook::consts::signal::SIGHUP;
use signal_hook::iterator::Signals;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process;
use std::str::FromStr;
use std::time::Duration;
use trust_dns_client::client::{Client, SyncClient};
use trust_dns_client::rr::{DNSClass, Name, RecordType};
use trust_dns_client::udp::UdpClientConnection;

// Will be only used by server to share backend
// across threads
#[derive(Clone)]
struct DNSBackendWithArc {
    pub backend: Arc<DNSBackend>,
}

pub fn serve(config_path: &str, port: u32) -> Result<(), std::io::Error> {
    // before serving write its pid to _config_path so other process can notify
    // aardvark of data change.
    let path = Path::new(config_path).join(AARDVARK_PID_FILE);
    let mut pid_file = match File::create(&path) {
        Err(err) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Unable to get process pid: {}", err),
            ));
        }
        Ok(file) => file,
    };

    let server_pid = process::id().to_string();
    match pid_file.write_all(server_pid.as_bytes()) {
        Err(err) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Unable to write pid to file: {}", err),
            ));
        }
        Ok(_) => {}
    }

    loop {
        if let Err(er) = core_serve_loop(config_path, port) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Server Error {}", er),
            ));
        }
    }
}

fn core_serve_loop(_config_path: &str, port: u32) -> Result<(), std::io::Error> {
    let mut signals = Signals::new(&[SIGHUP])?;

    match config::parse_configs(_config_path) {
        Ok((backend, listen_ip_v4, listen_ip_v6)) => {
            let listen_ip_v4_clone = listen_ip_v4.clone();
            let listen_ip_v6_clone = listen_ip_v6.clone();
            let mut thread_handles = vec![];
            let kill_switch = Arc::new(Mutex::new(false));

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
                    let kill_switch_arc_clone = Arc::clone(&kill_switch);
                    let handle = thread::spawn(move || {
                        if let Err(_e) = start_dns_server(
                            &network_name_clone,
                            IpAddr::V4(ip),
                            backend_arc_clone,
                            kill_switch_arc_clone,
                            port,
                        ) {
                            error!("Unable to start server {}", _e);
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

            for (network_name, listen_ip_list) in listen_ip_v6 {
                for ip in listen_ip_list {
                    let network_name_clone = network_name.clone();
                    let backend_arc_clone = shareable_arc.clone();
                    let kill_switch_arc_clone = Arc::clone(&kill_switch);
                    let handle = thread::spawn(move || {
                        if let Err(_e) = start_dns_server(
                            &network_name_clone,
                            IpAddr::V6(ip),
                            backend_arc_clone,
                            kill_switch_arc_clone,
                            port,
                        ) {
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

            let handle_signal = thread::spawn(move || {
                for sig in signals.forever() {
                    info!("Received SIGHUP will refresh servers: {:?}", sig);
                    break;
                }
            });

            if let Ok(_) = handle_signal.join() {
                let mut switch = kill_switch.lock().unwrap();
                *switch = true;

                // kill servers
                for (network_name, listen_ip_list) in listen_ip_v4_clone {
                    debug!("Refreshing all servers for network {:?}", network_name);
                    for ip in listen_ip_list {
                        let address_string = format!("{}:{}", ip, port);
                        server_refresh_request(address_string);
                    }
                }
                for (network_name, listen_ip_list) in listen_ip_v6_clone {
                    debug!("Refreshing all servers for network {:?}", network_name);
                    for ip in listen_ip_list {
                        let address_string = format!("{}:{}", ip, port);
                        server_refresh_request(address_string);
                    }
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
    kill_switch: Arc<Mutex<bool>>,
    port: u32,
) -> Result<(), std::io::Error> {
    let forward: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    match CoreDns::new(
        addr,
        port,
        name,
        forward,
        53 as u16,
        backend_arc.backend,
        kill_switch,
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

fn server_refresh_request(address_string: String) {
    let address = address_string.parse().unwrap();
    let conn = UdpClientConnection::with_timeout(address, Duration::from_millis(5)).unwrap();
    // and then create the Client
    let client = SyncClient::new(conn);
    // server will be killed by last request
    let name = Name::from_str("anything.").unwrap();
    match client.query(&name, DNSClass::IN, RecordType::A) {
        _ => {}
    }
}
