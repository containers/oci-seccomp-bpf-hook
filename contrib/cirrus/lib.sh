

# Library of common, shared utility functions.  This file is intended
# to be sourced by other scripts, not called directly.

# BEGIN Global export of all variables
set -a

# Due to differences across platforms and runtime execution environments,
# handling of the (otherwise) default shell setup is non-uniform.  Rather
# than attempt to workaround differences, simply force-load/set required
# items every time this library is utilized.
USER="$(whoami)"
HOME="$(getent passwd $USER | cut -d : -f 6)"
# Some platforms set and make this read-only
[[ -n "$UID" ]] || \
    UID=$(getent passwd $USER | cut -d : -f 3)

# Automation library installed at image-build time,
# defining $AUTOMATION_LIB_PATH in this file.
if [[ -r "/etc/automation_environment" ]]; then
    source /etc/automation_environment
fi
# shellcheck disable=SC2154
if [[ -n "$AUTOMATION_LIB_PATH" ]]; then
        # shellcheck source=/usr/share/automation/lib/common_lib.sh
        source $AUTOMATION_LIB_PATH/common_lib.sh
else
    (
    echo "WARNING: It does not appear that containers/automation was installed."
    echo "         Functionality of most of this library will be negatively impacted"
    echo "         This ${BASH_SOURCE[0]} was loaded by ${BASH_SOURCE[1]}"
    ) > /dev/stderr
fi

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
    eval "$(go env)"
fi

# END Global export of all variables
set +a

bad_os_id_ver() {
    echo "Unknown/Unsupported distro. $OS_RELEASE_ID and/or version $OS_RELEASE_VER for $(basename $0)"
    exit 42
}
