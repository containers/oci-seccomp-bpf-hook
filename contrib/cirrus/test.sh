#!/bin/bash

set -e

source $(dirname $0)/lib.sh

cd $GOSRC

[[ -x "bin/oci-seccomp-bpf-hook" ]] || \
    make

echo "Installing oci-seccomp-bpf-hook"
make install PREFIX=/usr

echo "Executing integration tests"
make test-integration BATS_OPTS=--tap
