#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

@test "check reverse lookups" {
	skip
	# container a1
	subnet_a=$(random_subnet 5)
	create_config "podman1" $(random_string 64) "aone" "$subnet_a" "a1" "1a"
	config_a1="$config"
	a1_ip=$(echo "$config_a1" | jq -r .networks.podman1.static_ips[0])
	gw=$(echo "$config_a1" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$config_a1"
	a1_pid=$CONTAINER_NS_PID

	# container a2
	create_config "podman1" $(random_string 64) "atwo" "$subnet_a" "a2" "2a"
	config_a2="$config"
	a2_ip=$(echo "$config_a2" | jq -r .networks.podman1.static_ips[0])
	create_container "$config_a2"
	a2_pid="$CONTAINER_NS_PID"
	
	# Resolve container names to IPs
	dig "$a1_pid" "atwo" "$gw"
	assert "$a2_ip"
	dig "$a2_pid" "aone" "$gw"
	assert "$a1_ip"

	# Resolve IPs to container names
	# Reverse lookups are not supported
	#dig_reverse "$a1_pid" "$a2_ip" "$gw"
	#assert $output "atwo"
	#dig_reverse "$a2_pid" "$a1_ip" "$gw"
	#assert $output "atwo"
}
