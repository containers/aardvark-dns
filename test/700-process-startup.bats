#!/usr/bin/env bats   -*- bats -*-
#
# test aardvark-dns process startup
#

bats_require_minimum_version 1.5.0
load helpers

@test "closes inherited file descriptors" {
	local marker="$AARDVARK_TMPDIR/fd-marker"
	exec 9>"$marker"

	subnet_a=$(random_subnet 5)
	create_config network_name="podman1" container_id=$(random_string 64) container_name="aone" subnet="$subnet_a"
	create_container "$config"

	exec 9>&-

	local aardvark_pid
	aardvark_pid=$(cat "$AARDVARK_TMPDIR/aardvark-dns/aardvark.pid")
	assert "$aardvark_pid" != ""

	run -0 readlink /proc/$aardvark_pid/fd/*
	assert "$output" =~ "/dev/null"
	assert "$output" !~ "fd-marker"
}
