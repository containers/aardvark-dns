# -*- bash -*-

# Netavark binary to run
NETAVARK=${NETAVARK:-/usr/libexec/podman/netavark}

TESTSDIR=${TESTSDIR:-$(dirname ${BASH_SOURCE})}

AARDVARK=${AARDVARK:-$TESTSDIR/../bin/aardvark-dns}

# export RUST_BACKTRACE so that we get a helpful stack trace
export RUST_BACKTRACE=full

HOST_NS_PID=
CONTAINER_NS_PID=

CONTAINER_CONFIGS=()
CONTAINER_NS_PIDS=()

#### Functions below are taken from podman and buildah and adapted to netavark.

################
#  run_helper  #  Invoke args, with timeout, using BATS 'run'
################
#
# Second, we use 'timeout' to abort (with a diagnostic) if something
# takes too long; this is preferable to a CI hang.
#
# Third, we log the command run and its output. This doesn't normally
# appear in BATS output, but it will if there's an error.
#
# Next, we check exit status. Since the normal desired code is 0,
# that's the default; but the expected_rc var can override:
#
#     expected_rc=125 run_helper nonexistent-subcommand
#     expected_rc=?   run_helper some-other-command       # let our caller check status
#
# Since we use the BATS 'run' mechanism, $output and $status will be
# defined for our caller.
#
function run_helper() {
    # expected_rc if unset set default to 0
    expected_rc="${expected_rc-0}"
    if [ "$expected_rc" == "?" ]; then
        expected_rc=
    fi
    # Remember command args, for possible use in later diagnostic messages
    MOST_RECENT_COMMAND="$*"

    # stdout is only emitted upon error; this echo is to help a debugger
    echo "$_LOG_PROMPT $*"

    # BATS hangs if a subprocess remains and keeps FD 3 open; this happens
    # if a process crashes unexpectedly without cleaning up subprocesses.
    run timeout --foreground -v --kill=10 10 "$@" 3>&-
    # without "quotes", multiple lines are glommed together into one
    if [ -n "$output" ]; then
        echo "$output"
    fi
    if [ "$status" -ne 0 ]; then
        echo -n "[ rc=$status "
        if [ -n "$expected_rc" ]; then
            if [ "$status" -eq "$expected_rc" ]; then
                echo -n "(expected) "
            else
                echo -n "(** EXPECTED $expected_rc **) "
            fi
        fi
        echo "]"
    fi

    if [ "$status" -eq 124 ]; then
        if expr "$output" : ".*timeout: sending" >/dev/null; then
            # It's possible for a subtest to _want_ a timeout
            if [[ "$expected_rc" != "124" ]]; then
                echo "*** TIMED OUT ***"
                false
            fi
        fi
    fi

    if [ -n "$expected_rc" ]; then
        if [ "$status" -ne "$expected_rc" ]; then
            die "exit code is $status; expected $expected_rc"
        fi
    fi

    # unset
    unset expected_rc
}

#########
#  die  #  Abort with helpful message
#########
function die() {
    # FIXME: handle multi-line output
    echo "#/vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" >&2
    echo "#| FAIL: $*" >&2
    echo "#\\^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" >&2
    false
}
############
#  assert  #  Compare actual vs expected string; fail if mismatch
############
#
# Compares string (default: $output) against the given string argument.
# By default we do an exact-match comparison against $output, but there
# are two different ways to invoke us, each with an optional description:
#
#      xpect               "EXPECT" [DESCRIPTION]
#      xpect "RESULT" "OP" "EXPECT" [DESCRIPTION]
#
# The first form (one or two arguments) does an exact-match comparison
# of "$output" against "EXPECT". The second (three or four args) compares
# the first parameter against EXPECT, using the given OPerator. If present,
# DESCRIPTION will be displayed on test failure.
#
# Examples:
#
#   xpect "this is exactly what we expect"
#   xpect "${lines[0]}" =~ "^abc"  "first line begins with abc"
#
function assert() {
    local actual_string="$output"
    local operator='=='
    local expect_string="$1"
    local testname="$2"

    case "${#*}" in
    0) die "Internal error: 'assert' requires one or more arguments" ;;
    1 | 2) ;;
    3 | 4)
        actual_string="$1"
        operator="$2"
        expect_string="$3"
        testname="$4"
        ;;
    *) die "Internal error: too many arguments to 'assert'" ;;
    esac

    # Comparisons.
    # Special case: there is no !~ operator, so fake it via '! x =~ y'
    local not=
    local actual_op="$operator"
    if [[ $operator == '!~' ]]; then
        not='!'
        actual_op='=~'
    fi
    if [[ $operator == '=' || $operator == '==' ]]; then
        # Special case: we can't use '=' or '==' inside [[ ... ]] because
        # the right-hand side is treated as a pattern... and '[xy]' will
        # not compare literally. There seems to be no way to turn that off.
        if [ "$actual_string" = "$expect_string" ]; then
            return
        fi
    else
        if eval "[[ $not \$actual_string $actual_op \$expect_string ]]"; then
            return
        elif [ $? -gt 1 ]; then
            die "Internal error: could not process 'actual' $operator 'expect'"
        fi
    fi

    # Test has failed. Get a descriptive test name.
    if [ -z "$testname" ]; then
        testname="${MOST_RECENT_BUILDAH_COMMAND:-[no test name given]}"
    fi

    # Display optimization: the typical case for 'expect' is an
    # exact match ('='), but there are also '=~' or '!~' or '-ge'
    # and the like. Omit the '=' but show the others; and always
    # align subsequent output lines for ease of comparison.
    local op=''
    local ws=''
    if [ "$operator" != '==' ]; then
        op="$operator "
        ws=$(printf "%*s" ${#op} "")
    fi

    # This is a multi-line message, which may in turn contain multi-line
    # output, so let's format it ourself, readably
    local actual_split
    IFS=$'\n' read -rd '' -a actual_split <<<"$actual_string" || true
    printf "#/vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n" >&2
    printf "#|     FAIL: %s\n" "$testname" >&2
    printf "#| expected: %s'%s'\n" "$op" "$expect_string" >&2
    printf "#|   actual: %s'%s'\n" "$ws" "${actual_split[0]}" >&2
    local line
    for line in "${actual_split[@]:1}"; do
        printf "#|         > %s'%s'\n" "$ws" "$line" >&2
    done
    printf "#\\^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n" >&2
    false
}

#################
#  assert_json  #  Compare actual json vs expected string; fail if mismatch
#################
# assert_json works like assert except that it accepts one extra parameter,
# the jq query string.
# There are two different ways to invoke us, each with an optional description:
#
#      xpect               "JQ_QUERY"      "EXPECT" [DESCRIPTION]
#      xpect "JSON_STRING" "JQ_QUERY" "OP" "EXPECT" [DESCRIPTION]
# Important this function will overwrite $output, so if you need to use the value
# more than once you need to safe it in another variable.
function assert_json() {
    local actual_json="$output"
    local operator='=='
    local jq_query="$1"
    local expect_string="$2"
    local testname="$3"

    case "${#*}" in
    0 | 1) die "Internal error: 'assert_json' requires two or more arguments" ;;
    2 | 3) ;;
    4 | 5)
        actual_json="$1"
        jq_query="$2"
        operator="$3"
        expect_string="$4"
        testname="$5"
        ;;
    *) die "Internal error: too many arguments to 'assert_json'" ;;
    esac
    run_helper jq -r "$jq_query" <<<"$actual_json"
    assert "$output" "$operator" "$expect_string" "$testname"
}

###################
#  random_string  #  Pseudorandom alphanumeric string of given length
###################
function random_string() {
    local length=${1:-10}
    head /dev/urandom | tr -dc a-zA-Z0-9 | head -c$length
}

###################
#  random_subnet  # generate a random private subnet
###################
#
# by default it will return a 10.x.x.0/24 ipv4 subnet
# if "6" is given as first argument it will return a "fdx:x:x:x::/64" ipv6 subnet
function random_subnet() {
    if [[ "$1" == "6" ]]; then
        printf "fd%x:%x:%x:%x::/64" $((RANDOM % 256)) $((RANDOM % 65535)) $((RANDOM % 65535)) $((RANDOM % 65535))
    else
        printf "10.%d.%d.0/24" $((RANDOM % 256)) $((RANDOM % 256))
    fi
}

#########################
#  random_ip_in_subnet  # get a random from a given subnet
#########################
# the first arg must be an subnet created by random_subnet
# otherwise this function might return an invalid ip
function random_ip_in_subnet() {
    # first trim subnet
    local net_ip=${1%/*}
    local num=
    # if ip has colon it is ipv6
    if [[ "$net_ip" == *":"* ]]; then
        # make sure to not get 0 or 1
        num=$(printf "%x" $((RANDOM % 65533 + 2)))
    else
        # if ipv4 we have to trim the final 0
        net_ip=${net_ip%0}
        # make sure to not get 0, 1 or 255
        num=$(printf "%d" $((RANDOM % 252 + 2)))
    fi
    printf "$net_ip%s" $num
}

#########################
#  gateway_from_subnet  # get the first ip from a given subnet
#########################
# the first arg must be an subnet created by random_subnet
# otherwise this function might return an invalid ip
function gateway_from_subnet() {
    # first trim subnet
    local net_ip=${1%/*}
    # set first ip in network as gateway
    local num=1
    # if ip has dor it is ipv4
    if [[ "$net_ip" == *"."* ]]; then
        # if ipv4 we have to trim the final 0
        net_ip=${net_ip%0}
    fi
    printf "$net_ip%s" $num
}

function create_netns() {
    # create a new netns and mountns and run a sleep process to keep it alive
    # we have to redirect stdout/err to /dev/null otherwise bats will hang
    unshare -mn sleep inf &>/dev/null &
    pid=$!

    # we have to wait for unshare and check that we have a new ns before returning
    local timeout=2
    while [[ $timeout -gt 1 ]]; do
        if [[ "$(ls -l /proc/self/ns/net)" != "$(ls -l /proc/$pid/ns/net)" ]]; then
            echo $pid
            return
        fi
        sleep 1
        let timeout=$timeout-1
    done

    die "Timed out waiting for unshare new netns"
}

function get_container_netns_path() {
    echo /proc/$1/ns/net
}

################
#  run_netavark  #  Invoke $NETAVARK, with timeout, using BATS 'run'
################
#
# This is the preferred mechanism for invoking netavark: first, it
# it joins the test network namespace before it invokes $NETAVARK,
# which may be 'netavark' or '/some/path/netavark'.
function run_netavark() {
    run_in_host_netns $NETAVARK "--config" "$AARDVARK_TMPDIR" "-a" "$AARDVARK" "$@"
}

################
#  run_in_container_netns  #  Run args in container netns
################
#
# first arg must be the container pid
function run_in_container_netns() {
    con_pid=$1
    shift
    run_helper nsenter -n -t $con_pid "$@"
}

################
#  run_in_host_netns  #  Run args in host netns
################
#
function run_in_host_netns() {
    run_helper nsenter -m -n -t $HOST_NS_PID "$@"
}

################
#  create_config#  Creates a config netavark can use
################
#
# first arg is the network name
# second arg is container_id
# third is container name
# fourth is subnet
# fifth and greater are aliases
function create_config() {
    local network_name=$1
    shift
    local container_id=$1
    shift
    local container_name=$1
    shift

    local subnets=""
    local subnet=$1
    shift
    container_ip=$(random_ip_in_subnet $subnet)
    container_gw=$(gateway_from_subnet $subnet)
    subnets="{\"subnet\":\"$subnet\",\"gateway\":\"$container_gw\"}"
    aliases=""
    comma=
    for i; do
        aliases+="$comma \"$i\""
        comma=,
    done

    create_network "$network_name" "$container_ip" "eth0" "$aliases"
    create_network_infos "$network_name" $(random_string 64) "$subnets"

    read -r -d '\0' config <<EOF
{
  "container_id": "$container_id",
  "container_name": "$container_name",
  "networks": {
      $new_network
  },
  "network_info": {
      $new_network_info
  }
}\0
EOF

}

################
#  create_network infos#  Creates a network_info json blob for netavark
################
# arg1 is network name
# arg2 network_id
# arg3 is subnets
function create_network_infos() {
    local net_name=$1
    shift
    local net_id=$1
    shift
    local subnets=$1
    shift
    local interface_name=${net_name:0:7}

    read -r -d '\0' new_network_info <<EOF
    "$net_name": {
      "name": "$net_name",
      "id": "$net_id",
      "driver": "bridge",
      "network_interface": "$interface_name",
      "subnets": [
        $subnets
      ],
      "ipv6_enabled": true,
      "internal": false,
      "dns_enabled": true,
      "ipam_options": {
        "driver": "host-local"
      }
    }\0
EOF

}

################
#  create_network#  Creates a network json blob for netavark
################
# arg is network name
# arg is ip address
# arg is interface (ethX)
# arg are aliases
function create_network() {
    local net_name=$1
    shift
    local ip_address=$1
    shift
    local interface_name=$1
    shift
    local aliases=$1

    read -r -d '\0' new_network <<EOF
    "$net_name": {
      "static_ips": [
        "$ip_address"
	],
	  "aliases": [
		$aliases
	],
      "interface_name": "$interface_name"
    }\0
EOF

}

################
#  create container#  Creates a netns that mimics a container
################
# arg1 is config
function create_container() {
    CONTAINER_NS_PID=$(create_netns)
    CONTAINER_NS_PIDS+=("$CONTAINER_NS_PID")
    create_container_backend "$CONTAINER_NS_PID" "$1"
    CONTAINER_CONFIGS+=("$1")
}

# arg1 is pid
# arg2 is config
function create_container_backend() {
    run_netavark setup $(get_container_netns_path $1) <<<"$2"
}

################
#  connect#  Connects netns to another network
################
# arg1 is pid
# arg2 is config
function connect() {
    create_container_backend "$1" "$2"
}

function basic_host_setup() {
    HOST_NS_PID=$(create_netns)
    # make sure to set DBUS_SYSTEM_BUS_ADDRESS to an empty value
    # netavark will try to use firewalld connection when possible
    # because we run in a separate netns we cannot use firewalld
    # firewalld run in the host netns and not our custom netns
    # thus the firewall rules end up in the wrong netns
    # unsetting does not work, it would use the default address
    export DBUS_SYSTEM_BUS_ADDRESS=
    AARDVARK_TMPDIR=$(mktemp -d --tmpdir=${BATS_TMPDIR:-/tmp} aardvark_bats.XXXXXX)
}

function setup_slirp4netns() {
    command -v slirp4netns || die "slirp4netns not installed"

    slirp4netns -c $HOST_NS_PID tap0 &>"$AARDVARK_TMPDIR/slirp4.log" &
    SLIRP4NETNS_PID=$!

    # create new resolv.conf with slirp4netns dns
    echo "nameserver 10.0.2.3" >"$AARDVARK_TMPDIR/resolv.conf"
    run_in_host_netns mount --bind "$AARDVARK_TMPDIR/resolv.conf" /etc/resolv.conf

    # waiting for slirp4netns to start is uncertain in different environments
    # this is causing flakes in upstream but its not easy to reproduce this flake
    # timeout ensures that we minimize uncertainity of flakes in CI.
    local timeout=10
    while [[ $timeout -gt 1 ]]; do
        run_in_host_netns ip addr
        if [[ "$output" =~ "tap0" ]]; then
            return
        fi
        sleep 1
        let timeout=$timeout-1
    done

    cat "$AARDVARK_TMPDIR/slirp4.log"
    die "Timed out waiting for slirp4netns to start"
}

function basic_teardown() {
    rm -fr "$AARDVARK_TMPDIR"
}

################
#  netavark_teardown#  tears down a network
################
function netavark_teardown() {
    run_netavark teardown $1 <<<"$2"
}

function teardown() {
    # Now call netavark with all the configs and then kill the netns associated with it
    for i in "${!CONTAINER_CONFIGS[@]}"; do
        netavark_teardown $(get_container_netns_path "${CONTAINER_NS_PIDS[$i]}") "${CONTAINER_CONFIGS[$i]}"
        kill -9 "${CONTAINER_NS_PIDS[$i]}"
    done

    if [[ -n "$SLIRP4NETNS_PID" ]]; then
        kill -9 $SLIRP4NETNS_PID
        SLIRP4NETNS_PID=""
    fi

    # Finally kill the host netns
    if [ ! -z "$HOST_NS_PID" ]; then
        echo "$HOST_NS_PID"
        kill -9 "$HOST_NS_PID"
    fi

    basic_teardown
}

function dig() {
    # first arg is container_netns_pid
    # second arg is name
    # third arg is server addr
    run_in_container_netns "$1" "dig" "+short" "$2" "@$3"
}

function dig_reverse() {
    # first arg is container_netns_pid
    # second arg is the IP address
    # third arg is server addr
    #run_in_container_netns "$1" "dig" "-x" "$2" "+short" "@$3"
    run_in_container_netns "$1" "nslookup" "$2" "$3"
}

function setup() {
    basic_host_setup
}
