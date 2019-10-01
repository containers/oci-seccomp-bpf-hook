#!/bin/bash

set -e

source $(dirname $0)/lib.sh

echo "${OS_REL_VER}-${CIRRUS_BUILD_ID:-$(date +%d)}"
