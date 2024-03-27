//! Runs the aardvark dns server with provided config
use crate::server::serve;
use clap::Parser;
use nix::unistd;
use nix::unistd::{dup2, fork, ForkResult};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Error;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;

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
                // verify aardvark here and block till will start
                unistd::read(ready_pipe_read.as_raw_fd(), &mut [0_u8; 1])?;
                unistd::close(ready_pipe_read.as_raw_fd())?;
                unistd::close(ready_pipe_write.as_raw_fd())?;
                Ok(())
            }
            Ok(ForkResult::Child) => {
                // remove any controlling terminals
                // but don't hardstop if this fails
                let _ = unsafe { libc::setsid() }; // check https://docs.rs/libc
                                                   // close fds -> stdout, stdin and stderr
                let dev_null = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                    .map_err(|e| std::io::Error::new(e.kind(), format!("/dev/null: {}", e)));
                // redirect stdout, stdin and stderr to /dev/null
                if let Ok(dev_null) = dev_null {
                    let fd = dev_null.as_raw_fd();
                    let _ = dup2(fd, 0);
                    let _ = dup2(fd, 1);
                    let _ = dup2(fd, 2);
                    if fd < 2 {
                        std::mem::forget(dev_null);
                    }
                }
                // create aardvark pid and then notify parent
                if let Err(er) = serve::create_pid(&input_dir) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Error creating aardvark pid {}", er),
                    ));
                }
                let mut f = unsafe { File::from_raw_fd(ready_pipe_write.as_raw_fd()) };
                write!(&mut f, "ready")?;
                unistd::close(ready_pipe_read.as_raw_fd())?;
                unistd::close(ready_pipe_write.as_raw_fd())?;
                if let Err(er) = serve::serve(&input_dir, port, &filter_search_domain) {
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
