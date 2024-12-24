#!/usr/bin/env bash

set -exo pipefail

rpm -q aardvark-dns aardvark-dns-tests netavark nftables

cd /usr/share/aardvark-dns/
bats test/
