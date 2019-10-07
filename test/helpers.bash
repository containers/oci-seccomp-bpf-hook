ALPINE="docker.io/library/alpine:latest"
BLOCK_MKDIR=$(realpath ./test/fixtures/block-mkdir.json)

PODMAN_RUN="podman run -i --rm"
TIMEOUT=600

showrun() {
    CMDLINE="timeout --foreground $TIMEOUT"$(printf " %q" "$@")
    echo "Executing: $CMDLINE"
    run $CMDLINE
    if [[ "$status" -eq "124" ]]; then
        echo "Warning: Command timed-out after $TIMEOUT seconds"
    fi
    return $status
}
