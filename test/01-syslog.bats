#!/usr/bin/env bats -t

load helpers

@test "Trace and check size of generated profile" {
	local tmpFile
	local size

	since=$(date "+%Y-%m-%d %H:%M:%S")

	tmpFile=$(mktemp)
	echo "Temporary file: ${tmpFile}"

	run podman run  --annotation io.containers.trace-syscall=${tmpFile} ${ALPINE} ls
	[ "$status" -eq 0 ]
	journalctl --since "${since}" -t oci-seccomp-bpf-hook -q
	msg=$(journalctl --since "${since}" -t oci-seccomp-bpf-hook -q)
	echo $msg
	[ ! -z "${msg}" ]
}
