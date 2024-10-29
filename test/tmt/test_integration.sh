#!/usr/bin/env bash

set -exo pipefail

if [[ $1 == '' ]]; then
    echo -e "Usage: $(basename ${BASH_SOURCE[0]}) STREAM\nSTREAM can be upstream or downstream"
    exit 1
fi

STREAM=$1

# `rhel` macro exists on RHEL, CentOS Stream, and Fedora ELN
# `centos` macro exists only on CentOS Stream
CENTOS_VERSION=$(rpm --eval '%{?centos}')
RHEL_VERSION=$(rpm --eval '%{?rhel}')

# Check Distro
cat /etc/redhat-release

# For upstream tests, we need to test with podman and other packages from the
# podman-next copr. For downstream tests (bodhi, errata), we don't need any
# additional setup
if [[ "$STREAM" == "upstream" ]]; then
    # Use CentOS Stream 10 copr target for RHEL-10 until EPEL 10 becomes
    # available
    # `rhel` macro exists on RHEL, CentOS Stream, and Fedora ELN
    # `centos` macro exists only on CentOS Stream
    if [[ -n $CENTOS_VERSION || $RHEL_VERSION -ge 10 ]]; then
        dnf -y copr enable rhcontainerbot/podman-next centos-stream-"$CENTOS_VERSION"
    else
        dnf -y copr enable rhcontainerbot/podman-next
    fi
    echo "priority=5" >> /etc/yum.repos.d/_copr:copr.fedorainfracloud.org:rhcontainerbot:podman-next.repo
fi

# Remove testing-farm repos if they exist because they interfere with the
# podman-next copr. The default distro repos will not be removed and can be
# used wherever relevant.
rm -f /etc/yum.repos.d/tag-repository.repo

# Enable EPEL on RHEL/CentOS Stream envs to fetch bats
if [[ -n $RHEL_VERSION ]]; then
    # Until EPEL 10 is available use epel-9 for all RHEL and CentOS Stream
    dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
    sed -i 's/$releasever/9/g' /etc/yum.repos.d/epel.repo
fi

# Install dependencies for running tests
dnf -y install bats bind-utils cargo clippy go-md2man iptables jq make netavark nftables nmap-ncat rustfmt dnsmasq

rpm -q aardvark-dns cargo netavark nftables

# Run tests
make -C ../.. AARDVARK=/usr/libexec/podman/aardvark-dns integration
