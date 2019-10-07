#!/usr/bin/env bats -t

load helpers

@test "Trace and look for syslogs" {
	local tmpFile
	local size

	since=$(date "+%Y-%m-%d %H:%M:%S")

	tmpFile=$(mktemp)
	echo "Temporary file: ${tmpFile}"

	showrun $PODMAN_RUN --annotation io.containers.trace-syscall=of:${tmpFile} ${ALPINE} ls
	[ "$status" -eq 0 ]
	# sleep two seconds to let the hook finish writing the file
	sleep 2

	journalctl --since "${since}" -t oci-seccomp-bpf-hook -q
	msg=$(journalctl --since "${since}" -t "oci-seccomp-bpf-hook")
	echo "Message: '$msg'"
	[ ! -z "${msg}" ]
}
