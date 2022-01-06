# aardvark-dns

Authoritative dns server for `A/AAAA` container records. Forwards other request to configured resolvers.
Read more about configuration in `src/backend/mod.rs`.

```console
aardvark-dns 0.1.0

USAGE:
    aardvark-dns [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Print help information
    -V, --version    Print version information

OPTIONS:
    -p, --path <PATH>    Path to configuration directory

SUBCOMMANDS:
    help    Print this message or the help of the given subcommand(s)
    run     Runs the aardvark dns server with the specified configuration directory
```

### Build

```console
make
```
