//! Runs the aardvark dns server with provided config
use clap::{self, Clap};
use log::debug;
use core::fmt::Error;

#[derive(Clap, Debug)]
pub struct Run {
}

impl Run {
    /// The run command runs the aardvark-dns server with the given configuration.
    pub fn new() -> Self {
        Self {
        }
    }

    pub fn exec(&self, input_file: String) -> Result<(), Error> {
        debug!("{:?} with input file from {:?}", "Setting up...", input_file);
        Ok(())

    }
}
