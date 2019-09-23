#!/usr/bin/env bats -t

load helpers

@test "Podman available" {
	# Run a container to make sure everything's in order
	run podman run --net=host --rm ${ALPINE} ls
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
}

@test "Version check" {
	local version
	version=$(cat ./VERSION)
	run ./bin/oci-seccomp-bpf-hook --version
	[ "$status" -eq 0 ]
	[[ ${lines[0]} =~ "${version}" ]]
}

@test "Trace and check size of generated profile" {
	local tmpFile
	local size

	tmpFile=$(mktemp)
	echo "Temporary file: ${tmpFile}"

	run podman run --net=host --annotation io.containers.trace-syscall=${tmpFile} ${ALPINE} ls
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
	# sleep two seconds to let the hook finish writing the file
	sleep 2

	size=$(du -b ${tmpFile} | awk '{ print $1 }')
	echo "Size of generated file: ${size}"
	[ "${size}" -gt 0 ]
}

@test "Trace and use generated profile" {
	local tmpFile
	local size

	tmpFile=$(mktemp)
	echo "Temporary file: ${tmpFile}"

	run podman run --net=host --annotation io.containers.trace-syscall=${tmpFile} ${ALPINE} ls
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
	# sleep two seconds to let the hook finish writing the file
	sleep 2

	size=$(du -b ${tmpFile} | awk '{ print $1 }')
	echo "Size of generated file: ${size}"
	[ "${size}" -gt 0 ]

	run podman run --net=host --security-opt seccomp=${tmpFile} alpine ls
	[ "$status" -eq 0 ]
}
