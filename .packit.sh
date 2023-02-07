#!/usr/bin/env bash

# This script handles any custom processing of the spec file generated using the `post-upstream-clone`
# action and gets used by the fix-spec-file action in .packit.yaml.

set -eo pipefail

# Get Version from Cargo.toml in HEAD
VERSION=$(grep '^version' Cargo.toml | cut -d\" -f2 | sed -e 's/-/~/')

# Generate source tarball from HEAD
git archive --prefix=aardvark-dns-$VERSION/ -o aardvark-dns-$VERSION.tar.gz HEAD

# RPM Spec modifications

# Use the Version from Cargo.toml in rpm spec
sed -i "s/^Version:.*/Version: $VERSION/" aardvark-dns.spec

# Use Packit's supplied variable in the Release field in rpm spec
sed -i "s/^Release:.*/Release: $PACKIT_RPMSPEC_RELEASE%{?dist}/" aardvark-dns.spec

# Use above generated tarball as Source in rpm spec
sed -i "s/^Source:.*.tar.gz/Source: aardvark-dns-$VERSION.tar.gz/" aardvark-dns.spec

# Use the right build dir for autosetup stage in rpm spec
sed -i "s/^%autosetup.*/%autosetup -Sgit -n %{name}-$VERSION/" aardvark-dns.spec
