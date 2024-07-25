use crate::backend::DNSBackend;
use crate::config::constants::AARDVARK_PID_FILE;
use crate::config::parse_configs;
use crate::dns::coredns::CoreDns;
use anyhow::Context;
use arc_swap::ArcSwap;
use log::{debug, error, info};
use nix::unistd;
use nix::unistd::dup2;
use resolv_conf::ScopedIp;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::hash::Hash;
use std::io::Error;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinHandle;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process;

type ThreadHandleMap<Ip> =
    HashMap<(String, Ip), (flume::Sender<()>, JoinHandle<Result<(), anyhow::Error>>)>;

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

#[tokio::main]
pub async fn serve(
    config_path: &str,
    port: u32,
    filter_search_domain: &str,
    ready: OwnedFd,
) -> anyhow::Result<()> {
    let mut signals = signal(SignalKind::hangup())?;
    let no_proxy: bool = env::var("AARDVARK_NO_PROXY").is_ok();

    let mut handles_v4 = HashMap::new();
    let mut handles_v6 = HashMap::new();

    read_config_and_spawn(
        config_path,
        port,
        filter_search_domain,
        &mut handles_v4,
        &mut handles_v6,
        no_proxy,
    )
    .await?;
    // We are ready now, this is far from perfect we should at least wait for the first bind
    // to work but this is not really possible with the current code flow and needs more changes.
    daemonize()?;
    let msg: [u8; 1] = [b'1'];
    unistd::write(&ready, &msg)?;
    drop(ready);

    loop {
        // Block until we receive a SIGHUP.
        signals.recv().await;
        debug!("Received SIGHUP");
        if let Err(e) = read_config_and_spawn(
            config_path,
            port,
            filter_search_domain,
            &mut handles_v4,
            &mut handles_v6,
            no_proxy,
        )
        .await
        {
            // do not exit here, we just keep running even if something failed
            error!("{e:#}");
        };
    }
}

/// # Ensure the expected DNS server threads are running
///
/// Stop threads corresponding to listen IPs no longer in the configuration and start threads
/// corresponding to listen IPs that were added.
async fn stop_and_start_threads<'a, Ip>(
    port: u32,
    backend: &'static ArcSwap<DNSBackend>,
    listen_ips: HashMap<String, Vec<Ip>>,
    thread_handles: &mut ThreadHandleMap<Ip>,
    no_proxy: bool,
    nameservers: &'a [ScopedIp],
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
    stop_threads(thread_handles, Some(to_shut_down)).await;

    // Then we start any new threads.
    let to_start: Vec<_> = expected_threads
        .iter()
        .filter(|k| !thread_handles.contains_key(*k))
        .cloned()
        .collect();
    for (network_name, ip) in to_start {
        let (shutdown_tx, shutdown_rx) = flume::bounded(0);
        let network_name_ = network_name.clone();
        let ns = nameservers.to_owned();
        let handle = tokio::spawn(async move {
            start_dns_server(
                network_name_,
                ip.into(),
                backend,
                port,
                shutdown_rx,
                no_proxy,
                ns,
            )
            .await
        });

        thread_handles.insert((network_name, ip), (shutdown_tx, handle));
    }
}

/// # Stop DNS server threads
///
/// If the `filter` parameter is `Some` only threads in the filter `Vec` will be stopped.
async fn stop_threads<Ip>(
    thread_handles: &mut ThreadHandleMap<Ip>,
    filter: Option<Vec<(String, Ip)>>,
) where
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
        match handle.await {
            Ok(res) => {
                // result returned by the future, i.e. that actual
                // result from start_dns_server()
                if let Err(e) = res {
                    // special anyhow error format to include cause but do not print backtrace
                    error!("Error from dns server: {:#}", e)
                }
            }
            // error from tokio itself
            Err(e) => error!("Error from dns server task: {}", e),
        }
    }
}

async fn start_dns_server(
    name: String,
    addr: IpAddr,
    backend: &'static ArcSwap<DNSBackend>,
    port: u32,
    rx: flume::Receiver<()>,
    no_proxy: bool,
    nameservers: Vec<ScopedIp>,
) -> Result<(), anyhow::Error> {
    let mut server = CoreDns::new(addr, port, name, backend, rx, no_proxy, nameservers);
    server.run().await.context("run dns server")
}

async fn read_config_and_spawn(
    config_path: &str,
    port: u32,
    filter_search_domain: &str,
    handles_v4: &mut ThreadHandleMap<Ipv4Addr>,
    handles_v6: &mut ThreadHandleMap<Ipv6Addr>,
    no_proxy: bool,
) -> anyhow::Result<()> {
    let (conf, listen_ip_v4, listen_ip_v6) =
        parse_configs(config_path, filter_search_domain).context("unable to parse config")?;

    // We store the `DNSBackend` in an `ArcSwap` so we can replace it when the configuration is
    // reloaded.
    static DNSBACKEND: OnceLock<ArcSwap<DNSBackend>> = OnceLock::new();
    let backend = match DNSBACKEND.get() {
        Some(b) => {
            b.store(Arc::new(conf));
            b
        }
        None => DNSBACKEND.get_or_init(|| ArcSwap::from(Arc::new(conf))),
    };

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
        stop_threads(handles_v4, None).await;
        stop_threads(handles_v6, None).await;

        process::exit(0);
    }

    // get host nameservers
    let nameservers = get_upstream_resolvers().context("failed to get upstream nameservers")?;

    stop_and_start_threads(
        port,
        backend,
        listen_ip_v4,
        handles_v4,
        no_proxy,
        &nameservers,
    )
    .await;

    stop_and_start_threads(
        port,
        backend,
        listen_ip_v6,
        handles_v6,
        no_proxy,
        &nameservers,
    )
    .await;

    Ok(())
}

// creates new session and put /dev/null on the stdio streams
fn daemonize() -> Result<(), Error> {
    // remove any controlling terminals
    // but don't hardstop if this fails
    let _ = unsafe { libc::setsid() }; // check https://docs.rs/libc
                                       // close fds -> stdout, stdin and stderr
    let dev_null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| std::io::Error::new(e.kind(), format!("/dev/null: {:#}", e)))?;
    // redirect stdout, stdin and stderr to /dev/null
    let fd = dev_null.as_raw_fd();
    let _ = dup2(fd, 0);
    let _ = dup2(fd, 1);
    let _ = dup2(fd, 2);
    Ok(())
}

// read /etc/resolv.conf and return all nameservers
fn get_upstream_resolvers() -> Result<Vec<ScopedIp>, anyhow::Error> {
    let mut f = File::open("/etc/resolv.conf").context("open resolv.conf")?;
    let mut buf = Vec::with_capacity(4096);
    f.read_to_end(&mut buf).context("read resolv.conf")?;
    let conf = resolv_conf::Config::parse(buf).context("parse resolv.conf")?;
    Ok(conf.nameservers)
}
