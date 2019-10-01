#!/bin/bash

set -e

set -a && eval "$(go env)" && set +a

make validate
