#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers

@test "two containers on the same network" {
	
	basic_host_setup
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

@test "two containers on different networks" {
	# container a1 on subnet a
	basic_host_setup
	subnet_a=$(random_subnet 5)
	create_config "podman1" $(random_string 64) "aone" "$subnet_a"
	a1_config="$config"
	a1_ip=$(echo "$a1_config" | jq -r .networks.podman1.static_ips[0])
	a_gw=$(echo "$a1_config" | jq -r .network_info.podman1.subnets[0].gateway)
	create_container "$a1_config"
	a1_pid="$CONTAINER_NS_PID"

	# container b1 on subnet b
	subnet_b=$(random_subnet 5)
	create_config "podman2" $(random_string 64) "bone" "$subnet_b"
	b1_config="$config"
	b1_ip=$(echo "$b1_config" | jq -r .networks.podman2.static_ips[0])
	b_gw=$(echo "$b1_config" | jq -r .network_info.podman2.subnets[0].gateway)
	create_container "$b1_config"
	b1_pid="$CONTAINER_NS_PID"

	# container a1 should not resolve b1
	dig "$a1_pid" "bone" "$a_gw"
	assert ""
	# container b1 should not resolve a1
	dig "$b1_pid" "aone" "$b_gw"
	assert ""

	# a1 should be able to resolve itself
	dig "$a1_pid" "aone" "$a_gw"
	assert $a1_ip
	# b1 should be able to resolve itself
	dig "$b1_pid" "bone" "$b_gw"
	assert $b1_ip
}

@test "two subnets with isolated container and one shared" {
	# container a1 on subnet a
	basic_host_setup
	subnet_a=$(random_subnet 5)
	subnet_b=$(random_subnet 5)

	# A1
	create_config "podman1" $(random_string 64) "aone" "$subnet_a"
	a1_config=$config
	a1_container_id=$(echo "$a1_config" | jq -r .container_id)
	a1_ip=$(echo "$a1_config" | jq -r .networks.podman1.static_ips[0])
	a_gw=$(echo "$a1_config" | jq -r .network_info.podman1.subnets[0].gateway)
	a1_hash=$(echo "$a1_config" | jq -r .network_info.podman1.id)
	create_container "$a1_config"
	a1_pid=$CONTAINER_NS_PID

	# container b1 on subnet b
	create_config "podman2" $(random_string 64) "bone" "$subnet_b"
	b1_config=$config
	b1_ip=$(echo "$b1_config" | jq -r .networks.podman2.static_ips[0])
	b_gw=$(echo "$b1_config" | jq -r .network_info.podman2.subnets[0].gateway)
	b1_hash=$(echo "$b1_config" | jq -r .network_info.podman1.id)
	create_container "$b1_config"
	b1_pid=$CONTAINER_NS_PID
	b_subnets=$(echo $b1_config | jq -r .network_info.podman2.subnets[0])

	# AB2
	create_config "podman1" $(random_string 64) "abtwo" "$subnet_a"
	a2_config=$config
	a2_ip=$(echo "$a2_config" | jq -r .networks.podman1.static_ips[0])

	b2_ip=$(random_ip_in_subnet "$subnet_b")
	create_network "podman2" "$b2_ip" "eth1"
	b2_network="{$new_network}"
	create_network_infos "podman2" "$b1_hash" "$b_subnets"
	b2_network_info="{$new_network_info}"
	ab2_config=$(jq -r ".networks +=  $b2_network" <<<"$a2_config")
	ab2_config=$(jq -r ".network_info += $b2_network_info" <<<"$ab2_config")
	
	create_container "$ab2_config"
	ab2_pid=$CONTAINER_NS_PID

	# aone should be able to resolve AB2 and NOT B1
	dig "$a1_pid" "abtwo" "$a_gw"
	assert "$a2_ip"
	dig "$a1_pid" "bone" "$a_gw"
	assert ""

	# bone should be able to resolve AB2 and NOT A1
	dig "$b1_pid" "abtwo" "$b_gw"
	assert "$b2_ip"
	dig "$b1_pid" "aone" "$b_gw"
	assert ""

	# abtwo should be able to resolve A1, B1, and AB2 on both gws
	dig "$ab2_pid" "aone" "$a_gw"
	assert "$a1_ip"
	dig "$ab2_pid" "bone" "$b_gw"
	assert "$b1_ip"
	# check ab2 from itself, first from the a side
	dig "$ab2_pid" "abtwo" "$a_gw"
	assert "${#lines[@]}"  = 2
	assert "$output" =~  "$a2_ip"
	assert "$output" =~  "$b2_ip"

	# and now from the bside
	dig "$ab2_pid" "abtwo" "$b_gw"
	assert "${#lines[@]}"  = 2
	assert "$output" =~  "$a2_ip"
	assert "$output" =~  "$b2_ip"
}