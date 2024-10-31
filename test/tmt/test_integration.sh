#!/usr/bin/env bash

set -exo pipefail

# Remove testing-farm repos if they exist because they interfere with the
# podman-next copr. The default distro repos will not be removed and can be
# used wherever relevant.
rm -f /etc/yum.repos.d/tag-repository.repo

# Install dependencies for running tests
dnf -y install bats bind-utils cargo clippy go-md2man iptables jq make netavark nftables nmap-ncat rustfmt dnsmasq

rpm -q aardvark-dns cargo netavark nftables

# Run tests
make -C ../.. AARDVARK=/usr/libexec/podman/aardvark-dns integration
