#!/usr/bin/env bash

set -exo pipefail

# Remove testing-farm repos if they exist because they interfere with the
# podman-next copr. The default distro repos will not be removed and can be
# used wherever relevant.
rm -f /etc/yum.repos.d/tag-repository.repo

# We want the netavark build from podman-next, so we update it after removing
# testing-farm repo.
dnf -y update netavark

rpm -q aardvark-dns cargo netavark nftables

# Run tests
make -C ../.. AARDVARK=/usr/libexec/podman/aardvark-dns integration
