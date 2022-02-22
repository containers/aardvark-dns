//! Runs the aardvark dns server with provided config
use crate::server::serve;
use clap::Parser;
use log::debug;
use std::io::Error;

#[derive(Parser, Debug)]
pub struct Run {}

impl Run {
    /// The run command runs the aardvark-dns server with the given configuration.
    pub fn new() -> Self {
        Self {}
    }

    pub fn exec(
        &self,
        input_dir: String,
        port: u32,
        filter_search_domain: String,
    ) -> Result<(), Error> {
        debug!(
            "Setting up aardvark server with input directory as {:?}",
            input_dir
        );

        if let Err(er) = serve::serve(&input_dir, port, &filter_search_domain) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Error starting server {}", er),
            ));
        }
        Ok(())
    }
}

impl Default for Run {
    fn default() -> Self {
        Self::new()
    }
}
