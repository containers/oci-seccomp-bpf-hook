ALPINE="quay.io/libpod/alpine:latest"
BLOCK_MKDIR=$(realpath $(dirname ${BASH_SOURCE[0]})/fixtures/block-mkdir.json)

# Hostname that should be ping'able from any environment in which we run tests
PINGABLE_HOST=github.com

# Without giving HOOKS_DIR, the option will not appear, which avoids writing
# default hooks directory in the command.
if [ ! -z $HOOKS_DIR ]; then
	HOOKS_DIR_OPT="--hooks-dir=$HOOKS_DIR"
fi
