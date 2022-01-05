use clap::{crate_version, Clap};

use aardvark_dns::commands::run;

#[derive(Clap, Debug)]
#[clap(version = crate_version!())]
struct Opts {
    /// Instead of reading from STDIN, read the configuration from specified file.
    #[clap(short, long)]
    file: Option<String>,
    /// Aardvark-dns trig command
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap, Debug)]
enum SubCommand {
    #[clap(version = crate_version!())]
    /// Runs the aardvark dns server with the specified configuration file.
    Run(run::Run),
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let opts = Opts::parse();

    let file = opts.file.unwrap_or_else(|| String::from("/dev/stdin"));
    let result = match opts.subcmd {
        SubCommand::Run(run) => run.exec(file),
    };

    match result {
        Ok(_) => {}
        Err(err) => {
            println!("{}", err);
            std::process::exit(1);
        }
    }
}
