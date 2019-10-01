#!/bin/bash

set -e

source $(dirname $0)/lib.sh

cd $GOSRC

make binary
make vendor
./hack/tree_status.sh
