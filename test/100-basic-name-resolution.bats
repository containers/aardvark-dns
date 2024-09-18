#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

# custom DNS server is set to `127.0.0.255` which is invalid DNS server
# hence all the external request must fail, this test is expected to fail
# with exit code 124
@test "basic container - dns itself (custom bad dns server)" {
	setup_slirp4netns

	subnet_a=$(random_subnet 5)
	create_config network_name="podman1" container_id=$(random_string 64) container_name="aone" subnet="$subnet_a" custom_dns_server='"127.0.0.255"' aliases='"a1", "1a"'
	config_a1=$config
	ip_a1=$(echo "$config_a1" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID
	run_in_container_netns "$a1_pid" "dig" "+short" "aone" "@$gw"
	assert "$ip_a1"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"

        # custom dns server is set to 3.3.3.3 which is not a valid DNS server so external DNS request must fail
	expected_rc=124 run_in_container_netns "$a1_pid" "dig" "+short" "google.com" "@$gw"
}

# custom DNS server is set to `8.8.8.8, 1.1.1.1` which is valid DNS server
# hence all the external request must paas.
@test "basic container - dns itself (custom good dns server)" {
	setup_slirp4netns

	subnet_a=$(random_subnet 5)
	create_config network_name="podman1" container_id=$(random_string 64) container_name="aone" subnet="$subnet_a" custom_dns_server='"8.8.8.8","1.1.1.1"' aliases='"a1", "1a"'

	config_a1=$config
	ip_a1=$(echo "$config_a1" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID
	run_in_container_netns "$a1_pid" "dig" "aone" "@$gw"
	# check for TTL 0 here as well
	assert "$output" =~ "aone\.[[:space:]]*0[[:space:]]*IN[[:space:]]*A[[:space:]]*$ip_a1"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"

	run_in_container_netns "$a1_pid" "dig" "+short" "google.com" "@$gw"
	# validate that we get an ipv4
	assert "$output" =~ "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"
}

@test "basic container - dns itself custom" {
	setup_slirp4netns

	subnet_a=$(random_subnet 5)
	create_config network_name="podman1" container_id=$(random_string 64) container_name="aone" subnet="$subnet_a" aliases='"a1", "1a"'
	config_a1=$config
	ip_a1=$(echo "$config_a1" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID
	run_in_container_netns "$a1_pid" "dig" "+short" "aone" "@$gw"
	assert "$ip_a1"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"

	# check TCP support
	run_in_container_netns "$a1_pid" "dig" "+tcp" "+short" "aone" "@$gw"
	assert "$ip_a1"


	run_in_container_netns "$a1_pid" "dig" "+short" "google.com" "@$gw"
	# validate that we get an ipv4
	assert "$output" =~ "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"

	# check TCP support for forwarding
	# note there is no guarantee that the forwarding is happening via TCP though
	# TODO add custom dns record that is to big for udp so we can be sure...
	run_in_container_netns "$a1_pid" "dig" "+tcp" "google.com" "@$gw"
	# validate that we get an ipv4
	assert "$output" =~ "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
	assert "$output" =~ "\(TCP\)" "server used TCP"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"
}

@test "basic container - ndots incomplete bad entry must NXDOMAIN instead of forwarding and timing out" {
	setup_slirp4netns

	subnet_a=$(random_subnet 5)
	create_config network_name="podman1" container_id=$(random_string 64) container_name="aone" subnet="$subnet_a" aliases='"a1", "1a"'
	config_a1=$config
	ip_a1=$(echo "$config_a1" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID
	expected_rc=1 run_in_container_netns "$a1_pid" "host" "-t" "ns" "bone" "$gw"
	assert "$output" =~ "NXDOMAIN"
}

@test "basic container - dns itself on container with ipaddress v6" {
	setup_slirp4netns

	subnet_a=$(random_subnet 6)
	create_config network_name="podman1" container_id=$(random_string 64) container_name="aone" subnet="$subnet_a" aliases='"a1", "1a"'
	config_a1=$config
	ip_a1=$(echo "$config_a1" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID
	run_in_container_netns "$a1_pid" "dig" "+short" "aone" "@$gw" "AAAA"
	assert "$ip_a1"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"

	run_in_container_netns "$a1_pid" "dig" "+short" "google.com" "@$gw" "AAAA"
	# validate that we got valid ipv6
	# check that the output is not empty
	assert "$lines[0]" != "" "got at least one result"
	for ip in "${lines[@]}"; do
		run_helper ipcalc -6c "$ip"
	done
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"
}

@test "basic container - dns itself with long network name" {
	subnet_a=$(random_subnet 5)
	long_name="podman11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	create_config network_name="$long_name" container_id=$(random_string 64) container_name="aone" subnet="$subnet_a" aliases='"a1", "1a"'
	config_a1=$config
	ip_a1=$(echo "$config_a1" | jq -r .networks.$long_name.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.$long_name.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID
	run_in_container_netns "$a1_pid" "dig" "+short" "aone" "@$gw"
	assert "$ip_a1"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"
}

@test "two containers on the same network" {
	# container a1
	subnet_a=$(random_subnet 5)
	create_config network_name="podman1" container_id=$(random_string 64) container_name="aone" subnet="$subnet_a" aliases='"a1", "1a"'
	config_a1="$config"
	a1_ip=$(echo "$config_a1" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID

	# container a2
	create_config network_name="podman1" container_id=$(random_string 64) container_name="atwo" subnet="$subnet_a" aliases='"a2", "2a"'
	config_a2="$config"
	a2_ip=$(echo "$config_a2" | jq -r .networks.podman1.static_ips[0])
	create_container "$config_a2"
	a2_pid="$CONTAINER_NS_PID"

	# Resolve container names to IPs
	dig "$a1_pid" "atwo" "$gw"
	assert "$a2_ip"
	# Set recursion bit
        assert "$output" !~ "WARNING: recursion requested but not available"
	dig "$a2_pid" "aone" "$gw"
	assert "$a1_ip"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"
}

# Internal network, meaning no DNS servers.
# Hence all external requests must fail.
@test "basic container - internal network has no DNS" {
	setup_slirp4netns

	subnet_a=$(random_subnet)
	create_config network_name="podman1" internal=true container_id=$(random_string 64) container_name="aone" subnet="$subnet_a" custom_dns_server='"1.1.1.1","8.8.8.8"' aliases='"a1", "1a"'
	config_a1=$config
	# Network name is still recorded as podman1
	ip_a1=$(echo "$config_a1" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID
	run_in_container_netns "$a1_pid" "dig" "+short" "aone" "@$gw"
	assert "$ip_a1"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"

	# Internal network means no DNS server means this should hard-fail
	expected_rc=1 run_in_container_netns "$a1_pid" "host" "-t" "ns" "google.com" "$gw"
	assert "$output" =~ "Host google.com not found"
	assert "$output" =~ "NXDOMAIN"
}

# Internal network, but this time with IPv6. Same result as above expected.
@test "basic container - internal network has no DNS - ipv6" {
	setup_slirp4netns

	subnet_a=$(random_subnet 6)
	# Cloudflare and Google public anycast DNS v6 nameservers
	create_config network_name="podman1" internal=true container_id=$(random_string 64) container_name="aone" subnet="$subnet_a" custom_dns_server='"2606:4700:4700::1111","2001:4860:4860::8888"' aliases='"a1", "1a"'
	config_a1=$config
	# Network name is still recorded as podman1
	ip_a1=$(echo "$config_a1" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID
	run_in_container_netns "$a1_pid" "dig" "+short" "aone" "@$gw" "AAAA"
	assert "$ip_a1"
	# Set recursion bit is already set if requested so output must not
	# contain unexpected warning.
	assert "$output" !~ "WARNING: recursion requested but not available"

	# Internal network means no DNS server means this should hard-fail
	expected_rc=1 run_in_container_netns "$a1_pid" "host" "-t" "ns" "google.com" "$gw"
	assert "$output" =~ "Host google.com not found"
	assert "$output" =~ "NXDOMAIN"
}
