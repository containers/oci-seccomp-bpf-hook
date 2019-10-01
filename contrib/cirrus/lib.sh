#!/bin/bash

set -e

GOSRC="${GOSRC:-$(realpath $(dirname $0)/../../)}"
SCRIPT_BASE="${SCRIPT_BASE:-./contrib/cirrus}"

# GCE image-name compatible string representation of distribution name
OS_RELEASE_ID="$(source /etc/os-release; echo $ID)"
# GCE image-name compatible string representation of distribution _major_ version
OS_RELEASE_VER="$(source /etc/os-release; echo $VERSION_ID | cut -d '.' -f 1)"
# Combined to ease soe usage
OS_REL_VER="${OS_RELEASE_ID}-${OS_RELEASE_VER}"
# Set 'true' when operating inside a container
CONTAINER="${CONTAINER:-false}"

if type -P go &> /dev/null; then
    set -a && eval "$(go env)" && set +a
fi

die() {
    echo "************************************************"
    echo ">>>>> ${1:-FATAL ERROR (but no message given!) in ${FUNCNAME[1]}()}"
    echo "************************************************"
    exit 1
}

# Pass in a list of one or more envariable names; exit non-zero with
# helpful error message if any value is empty
req_env_var() {
    # Provide context. If invoked from function use its name; else script name
    local caller=${FUNCNAME[1]}
    if [[ -n "$caller" ]]; then
        # Indicate that it's a function name
        caller="$caller()"
    else
        # Not called from a function: use script name
        caller=$(basename $0)
    fi

    # Usage check
    [[ -n "$1" ]] || die "FATAL: req_env_var: invoked without arguments"

    # Each input arg is an envariable name, e.g. HOME PATH etc. Expand each.
    # If any is empty, bail out and explain why.
    for i; do
        if [[ -z "${!i}" ]]; then
            die "FATAL: $caller requires \$$i to be non-empty"
        fi
    done
}

# Helper/wrapper script to only show stderr/stdout on non-zero exit
install_ooe() {
    req_env_var GOSRC SCRIPT_BASE
    echo "Installing script to mask stdout/stderr unless non-zero exit."
    sudo install -D -m 755 "$GOSRC/$SCRIPT_BASE/ooe.sh" /usr/local/bin/ooe.sh
}

bad_os_id_ver() {
    echo "Unknown/Unsupported distro. $OS_RELEASE_ID and/or version $OS_RELEASE_VER for $(basename $0)"
    exit 42
}
