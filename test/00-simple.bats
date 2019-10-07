#!/usr/bin/env bats -t

load helpers

@test "Podman available" {
	# Run a container to make sure everything's in order
	showrun $PODMAN_RUN --net=host ${ALPINE} ls
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
}

@test "Version check" {
	local version
	version=$(cat ./VERSION)
	showrun ./bin/oci-seccomp-bpf-hook --version
	[ "$status" -eq 0 ]
	[[ ${lines[0]} =~ "${version}" ]]
}

@test "Trace and check size of generated profile" {
	local tmpFile
	local size

	tmpFile=$(mktemp)
	echo "Temporary file: ${tmpFile}"

	run podman run --net=host --annotation io.containers.trace-syscall=of:${tmpFile} ${ALPINE} ls
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

	run podman run --net=host --annotation io.containers.trace-syscall=of:${tmpFile} ${ALPINE} ls
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
	# sleep two seconds to let the hook finish writing the file
	sleep 2

	size=$(du -b ${tmpFile} | awk '{ print $1 }')
	echo "Size of generated file: ${size}"
	[ "${size}" -gt 0 ]

	run podman run --net=host --security-opt seccomp=${tmpFile} ${ALPINE} ls
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
}

@test "Containers fails to run blocked syscall" {
	local tmpFile
	local size

	tmpFile=$(mktemp)
	echo "Temporary file: ${tmpFile}"

	run podman run --net=host --annotation io.containers.trace-syscall=of:${tmpFile} ${ALPINE} ls
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
	# sleep two seconds to let the hook finish writing the file
	sleep 2

	size=$(du -b ${tmpFile} | awk '{ print $1 }')
	echo "Size of generated file: ${size}"
	[ "${size}" -gt 0 ]

	run podman run --net=host --security-opt seccomp=${tmpFile} ${ALPINE} ls
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]

	run podman run --net=host --security-opt seccomp=${tmpFile} ${ALPINE} ping -c3 google.com
	echo "Podman output: ${lines[*]}"
	[ "$status" -ne 0 ]
}

@test "Extend existing seccomp profile" {
	local tmpFile1
	local tmpFile2
	local size 

	tmpFile1=$(mktemp)
	tmpFile2=$(mktemp)
	echo "Temporary file 1: ${tmpFile1}"
	echo "Temporary file 2: ${tmpFile2}"

	run podman run --net=host --annotation io.containers.trace-syscall=of:${tmpFile1} ${ALPINE} ls /
	[ "$status" -eq 0 ]
	# sleep two seconds to let the hook finish writing the file
	sleep 2

	size=$(du -b ${tmpFile1} | awk '{ print $1 }')
	echo "Size of the first generated file: ${size}"
	[ "${size}" -gt 0 ]

	run podman run --net=host --security-opt seccomp=${tmpFile1} ${ALPINE} ping -c3 google.com
	echo "Podman output: ${lines[*]}"
	[ "$status" -ne 0 ]

	run podman run --net=host --annotation io.containers.trace-syscall="if:${tmpFile1};of:${tmpFile2}" ${ALPINE} ping -c3 google.com
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
	sleep 2	# sleep two seconds to let the hook finish writing the file
	
	size=$(du -b ${tmpFile2} | awk '{ print $1 }')
	echo "Size of the second generated file: ${size}"
	[ "${size}" -gt 0 ]

	run podman run --net=host --security-opt seccomp=${tmpFile2} ${ALPINE} ls /
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]

	run podman run --net=host --security-opt seccomp=${tmpFile2} ${ALPINE} ping -c3 google.com
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
}

@test "Syscall blocked in input profile remains blocked in output profile" {
	local tmpFile
	local size 

	tmpFile=$(mktemp)
	echo "Temporary file : ${tmpFile}"

	run podman run --net=host --annotation io.containers.trace-syscall=of:${tmpFile} ${ALPINE} mkdir /foo
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
	# sleep two seconds to let the hook finish writing the file
	sleep 2

	size=$(du -b ${tmpFile} | awk '{ print $1 }')
	echo "Size of the first generated file: ${size}"
	[ "${size}" -gt 0 ]

	run podman run --net=host --security-opt seccomp=${tmpFile} ${ALPINE} mkdir /foo
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]

	run podman run --net=host --annotation io.containers.trace-syscall="if:${BLOCK_MKDIR};of:${tmpFile}" ${ALPINE} mkdir /foo
	echo "Podman output: ${lines[*]}"
	[ "$status" -eq 0 ]
	# sleep two seconds to let the hook finish writing the file
	sleep 2

	size=$(du -b ${tmpFile} | awk '{ print $1 }')
	echo "Size of the second generated file: ${size}"
	[ "${size}" -gt 0 ]

	run podman run --net=host --security-opt seccomp=${tmpFile} ${ALPINE} mkdir /foo
	echo "Podman output: ${lines[*]}"
	[ "$status" -ne 0 ]
}
