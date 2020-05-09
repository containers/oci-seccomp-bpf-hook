#!/bin/bash

# The Cirrus CI VM images have some setting that forbids us to run the hook.
# While debugging, we found that after running some tools from `bpftool` we can
# run the hook again.  For now, that's good enough but we need to check what's
# going exactly.
/usr/share/bcc/tools/trace probe
