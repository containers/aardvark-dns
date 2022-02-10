//! Syslog
//!
//! This crate provides facilities to send log messages via syslog.
//! It supports Unix sockets for local syslog, UDP and TCP for remote servers.
//!
//! Messages can be passed directly without modification, or in RFC 3164 or RFC 5424 format
//!
//! The code is available on [Github](https://github.com/Geal/rust-syslog)
//!
//! # Example
//!
//! ```rust
//! use syslog::{Facility, Formatter3164};
//!
//! let formatter = Formatter3164 {
//!     facility: Facility::LOG_USER,
//!     hostname: None,
//!     process: "myprogram".into(),
//!     pid: 0,
//! };
//!
//! match syslog::unix(formatter) {
//!     Err(e) => println!("impossible to connect to syslog: {:?}", e),
//!     Ok(mut writer) => {
//!         writer.err("hello world").expect("could not write error message");
//!     }
//! }
//! ```
//!
//! It can be used directly with the log crate as follows:
//!
//! ```rust
//! extern crate log;
//!
//! use syslog::{Facility, Formatter3164, BasicLogger};
//! use log::{SetLoggerError, LevelFilter, info};
//!
//! let formatter = Formatter3164 {
//!     facility: Facility::LOG_USER,
//!     hostname: None,
//!     process: "myprogram".into(),
//!     pid: 0,
//! };
//!
//! let logger = match syslog::unix(formatter) {
//!     Err(e) => { println!("impossible to connect to syslog: {:?}", e); return; },
//!     Ok(logger) => logger,
//! };
//! log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
//!         .map(|()| log::set_max_level(LevelFilter::Info));
//!
//! info!("hello world");
//!
#![crate_type = "lib"]

#[macro_use]
extern crate error_chain;
extern crate log;
extern crate time;

use std::env;
use std::fmt::{self, Arguments};
use std::io::{self, BufWriter, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(unix)]
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use std::process;
use std::sync::{Arc, Mutex};

use log::{Level, Log, Metadata, Record};

mod errors;
mod facility;
mod format;
pub use errors::*;
pub use facility::Facility;
pub use format::Severity;

pub use format::{Formatter3164, Formatter5424, LogFormat};

pub type Priority = u8;

/// Main logging structure
pub struct Logger<Backend: Write, Formatter> {
    pub formatter: Formatter,
    pub backend: Backend,
}

impl<W: Write, F> Logger<W, F> {
    pub fn new(backend: W, formatter: F) -> Self {
        Logger { backend, formatter }
    }

    pub fn emerg<T>(&mut self, message: T) -> Result<()>
    where
        F: LogFormat<T>,
    {
        self.formatter.emerg(&mut self.backend, message)
    }

    pub fn alert<T>(&mut self, message: T) -> Result<()>
    where
        F: LogFormat<T>,
    {
        self.formatter.alert(&mut self.backend, message)
    }

    pub fn crit<T>(&mut self, message: T) -> Result<()>
    where
        F: LogFormat<T>,
    {
        self.formatter.crit(&mut self.backend, message)
    }

    pub fn err<T>(&mut self, message: T) -> Result<()>
    where
        F: LogFormat<T>,
    {
        self.formatter.err(&mut self.backend, message)
    }

    pub fn warning<T>(&mut self, message: T) -> Result<()>
    where
        F: LogFormat<T>,
    {
        self.formatter.warning(&mut self.backend, message)
    }

    pub fn notice<T>(&mut self, message: T) -> Result<()>
    where
        F: LogFormat<T>,
    {
        self.formatter.notice(&mut self.backend, message)
    }

    pub fn info<T>(&mut self, message: T) -> Result<()>
    where
        F: LogFormat<T>,
    {
        self.formatter.info(&mut self.backend, message)
    }

    pub fn debug<T>(&mut self, message: T) -> Result<()>
    where
        F: LogFormat<T>,
    {
        self.formatter.debug(&mut self.backend, message)
    }
}

pub enum LoggerBackend {
    /// Unix socket, temp file path, log file path
    #[cfg(unix)]
    Unix(UnixDatagram),
    #[cfg(not(unix))]
    Unix(()),
    #[cfg(unix)]
    UnixStream(BufWriter<UnixStream>),
    #[cfg(not(unix))]
    UnixStream(()),
    Udp(UdpSocket, SocketAddr),
    Tcp(BufWriter<TcpStream>),
}

impl Write for LoggerBackend {
    /// Sends a message directly, without any formatting
    fn write(&mut self, message: &[u8]) -> io::Result<usize> {
        match *self {
            #[cfg(unix)]
            LoggerBackend::Unix(ref dgram) => dgram.send(&message[..]),
            #[cfg(unix)]
            LoggerBackend::UnixStream(ref mut socket) => {
                let null = [0; 1];
                socket
                    .write(&message[..])
                    .and_then(|sz| socket.write(&null).map(|_| sz))
            }
            LoggerBackend::Udp(ref socket, ref addr) => socket.send_to(&message[..], addr),
            LoggerBackend::Tcp(ref mut socket) => socket.write(&message[..]),
            #[cfg(not(unix))]
            LoggerBackend::Unix(_) | LoggerBackend::UnixStream(_) => {
                Err(io::Error::new(io::ErrorKind::Other, "unsupported platform"))
            }
        }
    }

    fn write_fmt(&mut self, args: Arguments) -> io::Result<()> {
        match *self {
            #[cfg(unix)]
            LoggerBackend::Unix(ref dgram) => {
                let message = fmt::format(args);
                dgram.send(message.as_bytes()).map(|_| ())
            }
            #[cfg(unix)]
            LoggerBackend::UnixStream(ref mut socket) => {
                let null = [0; 1];
                socket
                    .write_fmt(args)
                    .and_then(|_| socket.write(&null).map(|_| ()))
            }
            LoggerBackend::Udp(ref socket, ref addr) => {
                let message = fmt::format(args);
                socket.send_to(message.as_bytes(), addr).map(|_| ())
            }
            LoggerBackend::Tcp(ref mut socket) => socket.write_fmt(args),
            #[cfg(not(unix))]
            LoggerBackend::Unix(_) | LoggerBackend::UnixStream(_) => {
                Err(io::Error::new(io::ErrorKind::Other, "unsupported platform"))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self {
            #[cfg(unix)]
            LoggerBackend::Unix(_) => Ok(()),
            #[cfg(unix)]
            LoggerBackend::UnixStream(ref mut socket) => socket.flush(),
            LoggerBackend::Udp(_, _) => Ok(()),
            LoggerBackend::Tcp(ref mut socket) => socket.flush(),
            #[cfg(not(unix))]
            LoggerBackend::Unix(_) | LoggerBackend::UnixStream(_) => {
                Err(io::Error::new(io::ErrorKind::Other, "unsupported platform"))
            }
        }
    }
}

/// Returns a Logger using unix socket to target local syslog ( using /dev/log or /var/run/syslog)
#[cfg(unix)]
pub fn unix<F: Clone>(formatter: F) -> Result<Logger<LoggerBackend, F>> {
    unix_connect(formatter.clone(), "/dev/log")
        .or_else(|e| {
            if let ErrorKind::Io(ref io_err) = *e.kind() {
                if io_err.kind() == io::ErrorKind::NotFound {
                    return unix_connect(formatter, "/var/run/syslog");
                }
            }
            Err(e)
        })
        .chain_err(|| ErrorKind::Initialization)
}

#[cfg(not(unix))]
pub fn unix<F: Clone>(_formatter: F) -> Result<Logger<LoggerBackend, F>> {
    Err(ErrorKind::UnsupportedPlatform)?
}

/// Returns a Logger using unix socket to target local syslog at user provided path
#[cfg(unix)]
pub fn unix_custom<P: AsRef<Path>, F>(formatter: F, path: P) -> Result<Logger<LoggerBackend, F>> {
    unix_connect(formatter, path).chain_err(|| ErrorKind::Initialization)
}

#[cfg(not(unix))]
pub fn unix_custom<P: AsRef<Path>, F>(_formatter: F, _path: P) -> Result<Logger<LoggerBackend, F>> {
    Err(ErrorKind::UnsupportedPlatform)?
}

#[cfg(unix)]
fn unix_connect<P: AsRef<Path>, F>(formatter: F, path: P) -> Result<Logger<LoggerBackend, F>> {
    let sock = UnixDatagram::unbound()?;
    match sock.connect(&path) {
        Ok(()) => Ok(Logger {
            formatter,
            backend: LoggerBackend::Unix(sock),
        }),
        Err(ref e) if e.raw_os_error() == Some(libc::EPROTOTYPE) => {
            let sock = UnixStream::connect(path)?;
            Ok(Logger {
                formatter,
                backend: LoggerBackend::UnixStream(BufWriter::new(sock)),
            })
        }
        Err(e) => Err(e.into()),
    }
}

/// returns a UDP logger connecting `local` and `server`
pub fn udp<T: ToSocketAddrs, F>(
    formatter: F,
    local: T,
    server: T,
) -> Result<Logger<LoggerBackend, F>> {
    server
        .to_socket_addrs()
        .chain_err(|| ErrorKind::Initialization)
        .and_then(|mut server_addr_opt| {
            server_addr_opt
                .next()
                .chain_err(|| ErrorKind::Initialization)
        })
        .and_then(|server_addr| {
            UdpSocket::bind(local)
                .chain_err(|| ErrorKind::Initialization)
                .and_then(|socket| {
                    Ok(Logger {
                        formatter,
                        backend: LoggerBackend::Udp(socket, server_addr),
                    })
                })
        })
}

/// returns a TCP logger connecting `local` and `server`
pub fn tcp<T: ToSocketAddrs, F>(formatter: F, server: T) -> Result<Logger<LoggerBackend, F>> {
    TcpStream::connect(server)
        .chain_err(|| ErrorKind::Initialization)
        .and_then(|socket| {
            Ok(Logger {
                formatter,
                backend: LoggerBackend::Tcp(BufWriter::new(socket)),
            })
        })
}

pub struct BasicLogger {
    logger: Arc<Mutex<Logger<LoggerBackend, Formatter3164>>>,
}

impl BasicLogger {
    pub fn new(logger: Logger<LoggerBackend, Formatter3164>) -> BasicLogger {
        BasicLogger {
            logger: Arc::new(Mutex::new(logger)),
        }
    }
}

#[allow(unused_variables, unused_must_use)]
impl Log for BasicLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level() && metadata.level() <= log::STATIC_MAX_LEVEL
    }

    fn log(&self, record: &Record) {
        //FIXME: temporary patch to compile
        let message = format!("{}", record.args());
        let mut logger = self.logger.lock().unwrap();
        match record.level() {
            Level::Error => logger.err(message),
            Level::Warn => logger.warning(message),
            Level::Info => logger.info(message),
            Level::Debug => logger.debug(message),
            Level::Trace => logger.debug(message),
        };
    }

    fn flush(&self) {
        let _ = self.logger.lock().unwrap().backend.flush();
    }
}

/// Unix socket Logger init function compatible with log crate
#[cfg(unix)]
pub fn init_unix(facility: Facility, log_level: log::LevelFilter) -> Result<()> {
    let (process, pid) = get_process_info()?;
    let formatter = Formatter3164 {
        facility,
        hostname: None,
        process,
        pid,
    };
    unix(formatter).and_then(|logger| {
        log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
            .chain_err(|| ErrorKind::Initialization)
    })?;

    log::set_max_level(log_level);
    Ok(())
}

#[cfg(not(unix))]
pub fn init_unix(_facility: Facility, _log_level: log::LevelFilter) -> Result<()> {
    Err(ErrorKind::UnsupportedPlatform)?
}

/// Unix socket Logger init function compatible with log crate and user provided socket path
#[cfg(unix)]
pub fn init_unix_custom<P: AsRef<Path>>(
    facility: Facility,
    log_level: log::LevelFilter,
    path: P,
) -> Result<()> {
    let (process, pid) = get_process_info()?;
    let formatter = Formatter3164 {
        facility,
        hostname: None,
        process,
        pid,
    };
    unix_custom(formatter, path).and_then(|logger| {
        log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
            .chain_err(|| ErrorKind::Initialization)
    })?;

    log::set_max_level(log_level);
    Ok(())
}

#[cfg(not(unix))]
pub fn init_unix_custom<P: AsRef<Path>>(
    _facility: Facility,
    _log_level: log::LevelFilter,
    _path: P,
) -> Result<()> {
    Err(ErrorKind::UnsupportedPlatform)?
}

/// UDP Logger init function compatible with log crate
pub fn init_udp<T: ToSocketAddrs>(
    local: T,
    server: T,
    hostname: String,
    facility: Facility,
    log_level: log::LevelFilter,
) -> Result<()> {
    let (process, pid) = get_process_info()?;
    let formatter = Formatter3164 {
        facility,
        hostname: Some(hostname),
        process,
        pid,
    };
    udp(formatter, local, server).and_then(|logger| {
        log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
            .chain_err(|| ErrorKind::Initialization)
    })?;

    log::set_max_level(log_level);
    Ok(())
}

/// TCP Logger init function compatible with log crate
pub fn init_tcp<T: ToSocketAddrs>(
    server: T,
    hostname: String,
    facility: Facility,
    log_level: log::LevelFilter,
) -> Result<()> {
    let (process, pid) = get_process_info()?;
    let formatter = Formatter3164 {
        facility,
        hostname: Some(hostname),
        process,
        pid,
    };

    tcp(formatter, server).and_then(|logger| {
        log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
            .chain_err(|| ErrorKind::Initialization)
    })?;

    log::set_max_level(log_level);
    Ok(())
}

/// Initializes logging subsystem for log crate
///
/// This tries to connect to syslog by following ways:
///
/// 1. Unix sockets /dev/log and /var/run/syslog (in this order)
/// 2. Tcp connection to 127.0.0.1:601
/// 3. Udp connection to 127.0.0.1:514
///
/// Note the last option usually (almost) never fails in this method. So
/// this method doesn't return error even if there is no syslog.
///
/// If `application_name` is `None` name is derived from executable name
pub fn init(
    facility: Facility,
    log_level: log::LevelFilter,
    application_name: Option<&str>,
) -> Result<()> {
    let (process_name, pid) = get_process_info()?;
    let process = application_name.map(From::from).unwrap_or(process_name);
    let formatter = Formatter3164 {
        facility,
        hostname: get_hostname().ok(),
        process,
        pid,
    };

    let backend = unix(formatter.clone())
        .map(|logger: Logger<LoggerBackend, Formatter3164>| logger.backend)
        .or_else(|_| {
            TcpStream::connect(("127.0.0.1", 601)).map(|s| LoggerBackend::Tcp(BufWriter::new(s)))
        })
        .or_else(|_| {
            let udp_addr = "127.0.0.1:514".parse().unwrap();
            UdpSocket::bind(("127.0.0.1", 0)).map(|s| LoggerBackend::Udp(s, udp_addr))
        })?;
    log::set_boxed_logger(Box::new(BasicLogger::new(Logger { formatter, backend })))
        .chain_err(|| ErrorKind::Initialization)?;

    log::set_max_level(log_level);
    Ok(())
}

fn get_process_info() -> Result<(String, u32)> {
    env::current_exe()
        .chain_err(|| ErrorKind::Initialization)
        .and_then(|path| {
            path.file_name()
                .and_then(|os_name| os_name.to_str())
                .map(|name| name.to_string())
                .chain_err(|| ErrorKind::Initialization)
        })
        .map(|name| (name, process::id()))
}

fn get_hostname() -> Result<String> {
    Ok(hostname::get()?.to_string_lossy().to_string())
}
