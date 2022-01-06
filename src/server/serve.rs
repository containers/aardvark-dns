use crate::config;
use log::debug;

pub fn serve(_config_path: &str) -> Result<(), std::io::Error> {
    match config::parse_configs(_config_path) {
        Ok((_backend, listen_ip_v4, listen_ip_v6)) => {
            debug!("Successfully parsed config");
            debug!("Listen v4 ip {:?}", listen_ip_v4);
            debug!("Listen v6 ip {:?}", listen_ip_v6);
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
