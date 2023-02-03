#!/usr/bin/env bash

# This script handles any custom processing of the spec file generated using the `post-upstream-clone`
# action and gets used by the fix-spec-file action in .packit.yaml.

set -eo pipefail

# Get Version from HEAD
VERSION=$(grep '^version' Cargo.toml | cut -d\" -f2 | sed -e 's/-/~/')

# Generate source tarball
git archive --prefix=aardvark-dns-$VERSION/ -o aardvark-dns-$VERSION.tar.gz HEAD

# RPM Spec modifications

# Fix Version
sed -i "s/^Version:.*/Version: $VERSION/" aardvark-dns.spec

# Fix Release
sed -i "s/^Release:.*/Release: $PACKIT_RPMSPEC_RELEASE%{?dist}/" aardvark-dns.spec

# Fix Source0
sed -i "s/^Source:.*.tar.gz/Source: aardvark-dns-$VERSION.tar.gz/" aardvark-dns.spec

# Fix autosetup
sed -i "s/^%autosetup.*/%autosetup -Sgit -n %{name}-$VERSION/" aardvark-dns.spec
