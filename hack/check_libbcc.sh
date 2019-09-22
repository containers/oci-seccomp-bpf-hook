#!/bin/bash
if pkg-config libbcc 2> /dev/null; then
    echo oci_seccomp_bpf_hook
fi