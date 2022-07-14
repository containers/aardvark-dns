# aardvark-dns

Authoritative dns server for `A/AAAA` container records. Forwards other request to configured resolvers.
Read more about configuration in `src/backend/mod.rs`. It is mostly intended to be used with
[Netavark](https://github.com/containers/netavark/) which will launch it automatically if both are
installed.

```console
aardvark-dns 0.1.0

USAGE:
    aardvark-dns [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Print help information
    -V, --version    Print version information

OPTIONS:
    -c, --config <CONFIG>    Path to configuration directory
    -p, --port <PORT>        Host port for aardvark servers, defaults to 5533

SUBCOMMANDS:
    help    Print this message or the help of the given subcommand(s)
    run     Runs the aardvark dns server with the specified configuration directory
```

### Build

```console
make
```

### Run Example

```console
RUST_LOG=trace ./bin/aardvark-dns --config src/test/config/podman/ --port 5533 run
```

TEST EC2
