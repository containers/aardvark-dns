#!/usr/bin/env bash

set -exo pipefail

# Check Distro
cat /etc/redhat-release

# Remove testing-farm repos if they exist because they interfere with the
# podman-next copr. The default distro repos will not be removed and can be
# used wherever relevant.
rm -f /etc/yum.repos.d/tag-repository.repo

# EPEL10 doesn't exist yet and bats fetched from fedora repos on CS10 envs
# ends up skipping test 5 for whatever reason. So, install from source.
if [[ $(rpm --eval '%{?centos}') -eq 10 ]]; then
    BATS_VERSION=1.11.0
    curl -L https://github.com/bats-core/bats-core/archive/refs/tags/v$BATS_VERSION.tar.gz | tar zx
    pushd bats-core-$BATS_VERSION
    ./install.sh /usr/local
    popd
else
    dnf -y install bats
fi

# Install dependencies for running tests
dnf -y install bind-utils cargo clippy go-md2man iptables jq make netavark nftables nmap-ncat rustfmt slirp4netns

rpm -q aardvark-dns cargo netavark nftables

# Run tests
make -C ../.. AARDVARK=/usr/libexec/podman/aardvark-dns integration
