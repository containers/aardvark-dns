use clap::{Arg, App};

fn main() {
    env_logger::init();

    let _opts = App::new("Aardvark DNS").version("0.0.1").author("The containers/ project maintainers").about("A container-oriented DNS server").arg(Arg::with_name("cfgpath").value_name("PATH").takes_value(true).required(true));
}
