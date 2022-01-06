//! Runs the aardvark dns server with provided config
use crate::server::serve;
use clap::{self, Clap};
use log::debug;
use std::io::Error;

#[derive(Clap, Debug)]
pub struct Run {}

impl Run {
    /// The run command runs the aardvark-dns server with the given configuration.
    pub fn new() -> Self {
        Self {}
    }

    pub fn exec(&self, input_dir: String) -> Result<(), Error> {
        debug!(
            "Setting up aardvark server with input directory as {:?}",
            input_dir
        );

        if let Err(er) = serve::serve(&input_dir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Error starting server {}", er),
            ));
        }
        Ok(())
    }
}
