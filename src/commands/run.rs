//! Runs the aardvark dns server with provided config
use crate::server::serve;
use clap::Parser;
use nix::unistd;
use nix::unistd::{fork, ForkResult};
use std::io::Error;
use std::os::unix::io::AsRawFd;

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
        port: u16,
        filter_search_domain: String,
    ) -> Result<(), Error> {
        // create a temporary path for unix socket
        // so parent can communicate with child and
        // only exit when child is ready to serve.
        let (ready_pipe_read, ready_pipe_write) = nix::unistd::pipe()?;

        // fork and verify if server is running
        // and exit parent
        // setsid() ensures that there is no controlling terminal on the child process
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                log::debug!("starting aardvark on a child with pid {}", child);
                // close write here to make sure the read does not hang when
                // child never sends message because it exited to early...
                drop(ready_pipe_write);
                // verify aardvark here and block till will start
                let i = unistd::read(ready_pipe_read.as_raw_fd(), &mut [0_u8; 1])?;
                drop(ready_pipe_read);
                if i == 0 {
                    // we did not get nay message -> child exited with error
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Error from child process",
                    ))
                } else {
                    Ok(())
                }
            }
            Ok(ForkResult::Child) => {
                drop(ready_pipe_read);
                // create aardvark pid and then notify parent
                if let Err(er) = serve::create_pid(&input_dir) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error creating aardvark pid {}", er),
                    ));
                }

                if let Err(er) =
                    serve::serve(&input_dir, port, &filter_search_domain, ready_pipe_write)
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error starting server {}", er),
                    ));
                }
                Ok(())
            }
            Err(err) => {
                log::debug!("fork failed with error {}", err);
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("fork failed with error: {}", err),
                ))
            }
        }
    }
}

impl Default for Run {
    fn default() -> Self {
        Self::new()
    }
}
