#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

@test "check reverse lookups" {
	# container a1
	subnet_a=$(random_subnet 5)
	create_config "podman1" $(random_string 64) "aone" "$subnet_a" "a1" "1a"
	a1_config="$config"
	a1_ip=$(echo "$a1_config" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$a1_config" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$a1_config"
	a1_pid=$CONTAINER_NS_PID

	# container a2
	create_config "podman1" $(random_string 64) "atwo" "$subnet_a" "a2" "2a"
	a2_config="$config"
	a2_ip=$(echo "$a2_config" | jq -r .networks.podman1.static_ips[0])
	create_container "$a2_config"
	a2_pid="$CONTAINER_NS_PID"

	echo "$a1_config"
	echo "$a2_config"

	# Resolve IPs to container names
	dig_reverse "$a1_pid" "$a2_ip" "$gw"
	assert "$output" =~ "atwo"
	assert "$output" =~ "a2"
	assert "$output" =~ "2a"
	dig_reverse "$a2_pid" "$a1_ip" "$gw"
	assert "$output" =~ "aone"
	assert "$output" =~ "a1"
	assert "$output" =~ "1a"
}

@test "check reverse lookups on ipaddress v6" {
	# container a1
	subnet_a=$(random_subnet 6)
	create_config "podman1" $(random_string 64) "aone" "$subnet_a" "a1" "1a"
	a1_config="$config"
	a1_ip=$(echo "$a1_config" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$a1_config" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$a1_config"
	a1_pid=$CONTAINER_NS_PID

	# container a2
	create_config "podman1" $(random_string 64) "atwo" "$subnet_a" "a2" "2a"
	a2_config="$config"
	a2_ip=$(echo "$a2_config" | jq -r .networks.podman1.static_ips[0])
	create_container "$a2_config"
	a2_pid="$CONTAINER_NS_PID"

	echo "$a1_config"
	echo "$a2_config"

	# Resolve IPs to container names
	dig_reverse "$a1_pid" "$a2_ip" "$gw"
	assert "$output" =~ "atwo"
	assert "$output" =~ "a2"
	assert "$output" =~ "2a"
	dig_reverse "$a2_pid" "$a1_ip" "$gw"
	assert "$output" =~ "aone"
	assert "$output" =~ "a1"
	assert "$output" =~ "1a"
}
