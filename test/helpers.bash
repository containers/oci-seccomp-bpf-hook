ALPINE="docker.io/library/alpine:latest"
BLOCK_MKDIR=$(realpath ./test/fixtures/block-mkdir.json)
# podman on travis has trouble setting up a network namespace (--net=host)
PODMAN_RUN="podman run -i --rm${TRAVIS:+ --net=host}"
CONN_CHECK_CMD="nc -z 172.217.5.238 80"
TIMEOUT=600

showrun() {
    CMDLINE="timeout --foreground $TIMEOUT"$(printf " %q" "$@")
    echo "Executing: $CMDLINE"
    run $CMDLINE
	echo "Podman output: ${lines[*]}"
    echo "Exit code was: $status"
    if [[ "$status" -eq "124" ]]; then
        echo "Warning: Command timed-out after $TIMEOUT seconds"
    fi
}
