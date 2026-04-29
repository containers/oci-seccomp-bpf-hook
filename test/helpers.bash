ALPINE="quay.io/libpod/alpine:latest"
BLOCK_MKDIR=$(realpath $(dirname ${BASH_SOURCE[0]})/fixtures/block-mkdir.json)

# IP used to test network syscalls. Use a bare IP to avoid DNS lookups.
# wget over TCP requires no special capabilities (unlike ping with ICMP).
NET_HOST=1.1.1.1
