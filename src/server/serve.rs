use crate::backend::DNSBackend;
use crate::config;
use crate::config::constants::AARDVARK_PID_FILE;
use crate::dns::coredns::CoreDns;
use log::{debug, error, info};
use signal_hook::consts::signal::SIGHUP;
use signal_hook::iterator::Signals;
use std::fs;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;

use async_broadcast::broadcast;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process;

// Will be only used by server to share backend
// across threads
#[derive(Clone)]
struct DNSBackendWithArc {
    pub backend: Arc<DNSBackend>,
}

pub fn serve(
    config_path: &str,
    port: u32,
    filter_search_domain: &str,
) -> Result<(), std::io::Error> {
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
    if let Err(err) = pid_file.write_all(server_pid.as_bytes()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Unable to write pid to file: {}", err),
        ));
    }

    // rust closes the fd only when it leaves the scope, since this is
    // the main loop it will never happen so we have to manually close it
    drop(pid_file);

    loop {
        if let Err(er) = core_serve_loop(config_path, port, filter_search_domain) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Server Error {}", er),
            ));
        }
    }
}

fn core_serve_loop(
    config_path: &str,
    port: u32,
    filter_search_domain: &str,
) -> Result<(), std::io::Error> {
    let mut signals = Signals::new(&[SIGHUP])?;

    match config::parse_configs(config_path) {
        Ok((backend, listen_ip_v4, listen_ip_v6)) => {
            let mut thread_handles = vec![];

            // we need mutex so we so threads can still modify lock
            // clippy is only doing linting and asking us to use atomic bool
            // so manually allow this
            #[allow(clippy::mutex_atomic)]
            let kill_switch = Arc::new(Mutex::new(false));

            // kill server if listen_ip's are empty
            if listen_ip_v4.is_empty() && listen_ip_v6.is_empty() {
                //no configuration found kill the server
                info!("No configuration found stopping the sever");
                let path = Path::new(config_path).join(AARDVARK_PID_FILE);
                match fs::remove_file(path) {
                    Ok(_) => {}
                    Err(err) => {
                        error!("failed to remove the pid file: {}", &err);
                        process::exit(1);
                    }
                }
                process::exit(0);
            }

            // Prevent memory duplication: since backend is immutable across threads so create Arc and share
            let shareable_arc = DNSBackendWithArc {
                backend: Arc::from(backend),
            };

            debug!("Successfully parsed config");
            debug!("Listen v4 ip {:?}", listen_ip_v4);
            debug!("Listen v6 ip {:?}", listen_ip_v6);

            // create a receiver and sender for async broadcast channel
            let (tx, rx) = broadcast(1000);

            for (network_name, listen_ip_list) in listen_ip_v4 {
                for ip in listen_ip_list {
                    let network_name_clone = network_name.clone();
                    let filter_search_domain_clone = filter_search_domain.to_owned();
                    let backend_arc_clone = shareable_arc.clone();
                    let kill_switch_arc_clone = Arc::clone(&kill_switch);
                    let receiver = rx.clone();
                    let handle = thread::spawn(move || {
                        if let Err(_e) = start_dns_server(
                            &network_name_clone,
                            IpAddr::V4(ip),
                            backend_arc_clone,
                            kill_switch_arc_clone,
                            port,
                            filter_search_domain_clone.to_string(),
                            receiver,
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
                    let filter_search_domain_clone = filter_search_domain.to_owned();
                    let backend_arc_clone = shareable_arc.clone();
                    let kill_switch_arc_clone = Arc::clone(&kill_switch);
                    let receiver = rx.clone();
                    let handle = thread::spawn(move || {
                        if let Err(_e) = start_dns_server(
                            &network_name_clone,
                            IpAddr::V6(ip),
                            backend_arc_clone,
                            kill_switch_arc_clone,
                            port,
                            filter_search_domain_clone.to_string(),
                            receiver,
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
                if let Some(sig) = signals.forever().next() {
                    info!("Received SIGHUP will refresh servers: {:?}", sig);
                }
            });

            if handle_signal.join().is_ok() {
                send_broadcast(&tx);
                if let Ok(mut switch) = kill_switch.lock() {
                    *switch = true;
                };
            }

            for handle in thread_handles {
                if let Err(e) = handle.join() {
                    error!("Error from thread: {:?}", e);
                }
            }

            // close and drop broadcast channel
            tx.close();
            drop(tx);

            Ok(())
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
    filter_search_domain: String,
    rx: async_broadcast::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let forward: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    match CoreDns::new(
        addr,
        port,
        name,
        forward,
        53_u16,
        backend_arc.backend,
        kill_switch,
        filter_search_domain,
        rx,
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

#[tokio::main]
async fn send_broadcast(tx: &async_broadcast::Sender<bool>) {
    if let Err(e) = tx.broadcast(true).await {
        error!("unable to broadcast to child threads: {:?}", e);
    }
}
