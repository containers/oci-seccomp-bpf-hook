ALPINE="quay.io/libpod/alpine:latest"
BLOCK_MKDIR=$(realpath $(dirname ${BASH_SOURCE[0]})/fixtures/block-mkdir.json)

# Hostname that should be ping'able from any environment in which we run tests
PINGABLE_HOST=github.com
