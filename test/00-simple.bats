#!/usr/bin/env bats -t

load helpers

@test "Trace and check size of generated profile" {
	local tmpFile
	local size

	tmpFile=$(mktemp)
	echo "Temporary file: ${tmpFile}"

	run podman run  --annotation io.containers.trace-syscall=${tmpFile} ${ALPINE} ls
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

	run podman run  --annotation io.containers.trace-syscall=${tmpFile} ${ALPINE} ls
	[ "$status" -eq 0 ]
	# sleep two seconds to let the hook finish writing the file
	sleep 2

	size=$(du -b ${tmpFile} | awk '{ print $1 }')
	echo "Size of generated file: ${size}"
	[ "${size}" -gt 0 ]

	run podman run --security-opt seccomp=${tmpFile} alpine ls
	[ "$status" -eq 0 ]
}
