#!/bin/bash

set -e

source $(dirname $0)/lib.sh

req_env_vars GOSRC

cd $GOSRC

make validate
