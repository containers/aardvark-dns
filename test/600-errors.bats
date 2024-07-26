#!/usr/bin/env bats   -*- bats -*-
#
# basic netavark tests
#

load helpers


NCPID=

function teardown() {
    kill -9 $NCPID
    basic_teardown
}

# check bind error on startup
@test "aardvark-dns should fail when port is already bound" {
	# bind the port to force a failure for aardvark-dns
	# we cannot use run_is_host_netns to run in the background
	nsenter -m -n -t $HOST_NS_PID nc -u -l 0.0.0.0 53 </dev/null 3> /dev/null &
	NCPID=$!

	# ensure nc has time to bind the port
	sleep 1

	subnet_a=$(random_subnet 5)
	create_config network_name="podman1" container_id=$(random_string 64) container_name="aone" subnet="$subnet_a"
    gw=$(echo "$config" | jq -r .network_info.podman1.subnets[0].gateway)
	expected_rc=1 create_container "$config"
    assert "$output" =~ "failed to bind udp listener on $gw:53" "bind error message"
}
