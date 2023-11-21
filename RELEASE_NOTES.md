# Release Notes

## v1.9.0
* update trust-dns to hickory
* never report an error when the syslog init fails
* dependency updates

## v1.8.0
* dependency updates

## v1.7.0
* dependency updates

## v1.6.0
* dependency updates
* lower the TTL to 60s for container names

## v1.5.0
* dependency updates
* code of conduct added

## v1.4.0
* Add support for network scoped dns servers; declare DNS at a network level

## v1.3.0
* allow one or more dns servers in the aardvark config

## v1.2.0
* coredns: do not combine results of A and AAAA records
* run,serve: create aardvark pid in child before we notify parent process
* coredns: response message set recursion available if RD is true
* document configuration format

## v1.1.0
* Changed Aardvark to fork on startup to daemonize, as opposed to have this done by callers. This avoids race conditions around startup.
* Name resolution is now case-insensitive.

## v1.0.3
* Updated dependancy libraries
* Reduction in CPU use
* Fixed bug with duplicate network names

## v1.0.2
* Updated dependency libraries
* Removed vergen dependency

## v1.0.1
- Remove vendor directory from upstream github repository
- Vendored libraries updates

## v1.0.0
- First release of aardvark-dns.

## v1.0.0-RC2
- Slew of bug fixes related to reverse lookups, NXDOMAIN returns, and so on. Getting very close to first official release.

## v1.0.0-RC1
- This is the first release candidate of Aardvark's initial release! All major functionality is implemented and working.
