#!/bin/bash

# This script configures the CI runtime environment.  It's intended
# to be used by Cirrus-CI, not humans.

set -e

source $(dirname $0)/lib.sh

# Only do this once
if [[ -r "/etc/ci_environment" ]]; then
    msg "It appears ${BASH_SOURCE[0]} already ran, exiting."
    exit 0
fi
trap "complete_setup" EXIT

msg "************************************************************"
msg "Setting up runtime environment"
msg "************************************************************"
show_env_vars

#req_env_vars NETAVARK_URL

set -x  # show what's happening
#curl --fail --location -o /tmp/netavark.zip "$NETAVARK_URL"
mkdir -p /usr/libexec/podman
cargo install --root /usr/libexec/podman --git https://github.com/containers/netavark
#cd /usr/libexec/podman
#unzip -o /tmp/netavark.zip
#if [[ $(uname -m) != "x86_64" ]]; then
#    mv netavark.$(uname -m)-unknown-linux-gnu netavark
#fi
#chmod a+x /usr/libexec/podman/netavark
# show netavark commit in CI logs
/usr/libexec/podman/netavark version

# Warning, this isn't the end.  An exit-handler is installed to finalize
# setup of env. vars.  This is required for runner.sh to operate properly.
# See complete_setup() in lib.sh for details.
