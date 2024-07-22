use crate::backend::DNSBackend;
use crate::config;
use crate::config::constants::AARDVARK_PID_FILE;
use crate::dns::coredns::CoreDns;
use arc_swap::ArcSwap;
use log::{debug, error, info};
use signal_hook::consts::signal::SIGHUP;
use signal_hook::iterator::Signals;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::hash::Hash;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::thread;
use std::thread::JoinHandle;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process;

type Config = (
    DNSBackend,
    HashMap<String, Vec<Ipv4Addr>>,
    HashMap<String, Vec<Ipv6Addr>>,
);
type ThreadHandleMap<Ip> =
    HashMap<(String, Ip), (flume::Sender<()>, JoinHandle<Result<(), std::io::Error>>)>;

pub fn create_pid(config_path: &str) -> Result<(), std::io::Error> {
    // before serving write its pid to _config_path so other process can notify
    // aardvark of data change.
    let path = Path::new(config_path).join(AARDVARK_PID_FILE);
    let mut pid_file = match File::create(path) {
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

    Ok(())
}

pub fn serve(
    config_path: &str,
    port: u32,
    filter_search_domain: &str,
) -> Result<(), std::io::Error> {
    let mut signals = Signals::new([SIGHUP])?;

    let (backend, mut listen_ip_v4, mut listen_ip_v6) =
        parse_configs(config_path, filter_search_domain)?;

    // We store the `DNSBackend` in an `ArcSwap` so we can replace it when the configuration is
    // reloaded.
    static DNSBACKEND: OnceLock<ArcSwap<DNSBackend>> = OnceLock::new();
    let backend = DNSBACKEND.get_or_init(|| ArcSwap::from(Arc::new(backend)));

    let mut handles_v4 = HashMap::new();
    let mut handles_v6 = HashMap::new();

    loop {
        debug!("Successfully parsed config");
        debug!("Listen v4 ip {:?}", listen_ip_v4);
        debug!("Listen v6 ip {:?}", listen_ip_v6);

        // kill server if listen_ip's are empty
        if listen_ip_v4.is_empty() && listen_ip_v6.is_empty() {
            info!("No configuration found stopping the sever");

            let path = Path::new(config_path).join(AARDVARK_PID_FILE);
            if let Err(err) = fs::remove_file(path) {
                error!("failed to remove the pid file: {}", &err);
                process::exit(1);
            }

            // Gracefully stop all server threads first.
            stop_threads(&mut handles_v4, None);
            stop_threads(&mut handles_v6, None);

            process::exit(0);
        }

        stop_and_start_threads(port, backend, listen_ip_v4, &mut handles_v4);

        stop_and_start_threads(port, backend, listen_ip_v6, &mut handles_v6);

        // Block until we receive a SIGHUP.
        loop {
            if signals.wait().next().is_some() {
                break;
            }
        }

        let (new_backend, new_listen_ip_v4, new_listen_ip_v6) =
            parse_configs(config_path, filter_search_domain)?;
        backend.store(Arc::new(new_backend));
        listen_ip_v4 = new_listen_ip_v4;
        listen_ip_v6 = new_listen_ip_v6;
    }
}

fn parse_configs(config_path: &str, filter_search_domain: &str) -> Result<Config, std::io::Error> {
    config::parse_configs(config_path, filter_search_domain).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("unable to parse config: {}", e),
        )
    })
}

/// # Ensure the expected DNS server threads are running
///
/// Stop threads corresponding to listen IPs no longer in the configuration and start threads
/// corresponding to listen IPs that were added.
fn stop_and_start_threads<Ip>(
    port: u32,
    backend: &'static ArcSwap<DNSBackend>,
    listen_ips: HashMap<String, Vec<Ip>>,
    thread_handles: &mut ThreadHandleMap<Ip>,
) where
    Ip: Eq + Hash + Copy + Into<IpAddr> + Send + 'static,
{
    let mut expected_threads = HashSet::new();
    for (network_name, listen_ip_list) in listen_ips {
        for ip in listen_ip_list {
            expected_threads.insert((network_name.clone(), ip));
        }
    }

    // First we shut down any old threads that should no longer be running.  This should be
    // done before starting new ones in case a listen IP was moved from being under one network
    // name to another.
    let to_shut_down: Vec<_> = thread_handles
        .keys()
        .filter(|k| !expected_threads.contains(k))
        .cloned()
        .collect();
    stop_threads(thread_handles, Some(to_shut_down));

    // Then we start any new threads.
    let to_start: Vec<_> = expected_threads
        .iter()
        .filter(|k| !thread_handles.contains_key(*k))
        .cloned()
        .collect();
    for (network_name, ip) in to_start {
        let (shutdown_tx, shutdown_rx) = flume::bounded(0);
        let network_name_ = network_name.clone();
        let handle = thread::spawn(move || {
            if let Err(e) = start_dns_server(network_name_, ip.into(), backend, port, shutdown_rx) {
                error!("Unable to start server: {}", e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Error while invoking start_dns_server: {}", e),
                ));
            }

            Ok(())
        });

        thread_handles.insert((network_name, ip), (shutdown_tx, handle));
    }
}

/// # Stop DNS server threads
///
/// If the `filter` parameter is `Some` only threads in the filter `Vec` will be stopped.
fn stop_threads<Ip>(thread_handles: &mut ThreadHandleMap<Ip>, filter: Option<Vec<(String, Ip)>>)
where
    Ip: Eq + Hash + Copy,
{
    let mut handles = Vec::new();

    let to_shut_down: Vec<_> = filter.unwrap_or_else(|| thread_handles.keys().cloned().collect());

    for key in to_shut_down {
        let (tx, handle) = thread_handles.remove(&key).unwrap();
        handles.push(handle);
        drop(tx);
    }

    for handle in handles {
        if let Err(e) = handle.join() {
            error!("Error from thread: {:?}", e);
        }
    }
}

#[tokio::main]
async fn start_dns_server(
    name: String,
    addr: IpAddr,
    backend: &'static ArcSwap<DNSBackend>,
    port: u32,
    rx: flume::Receiver<()>,
) -> Result<(), std::io::Error> {
    let forward: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    match CoreDns::new(addr, port, name, forward, 53_u16, backend, rx).await {
        Ok(mut server) => match server.run().await {
            Ok(_) => Ok(()),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("unable to start CoreDns server: {}", e),
            )),
        },
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("unable to create CoreDns server: {}", e),
        )),
    }
}
