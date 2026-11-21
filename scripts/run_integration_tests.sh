#!/usr/bin/env bash
# Real Mininet + Open vSwitch + controller tests (needs root).  Starts its own controller,
# auth server and lab on separate ports; takes about a minute.
#   CNAUTH_OVS_DATAPATH=user  -> use the userspace datapath if the VM has no OVS kernel module
. "$(dirname "$0")/env.sh"
exec sudo -E env "PATH=$PATH" PYTHONPATH="$PYTHONPATH" python3 -W ignore -m unittest tests.integration.test_e2e -v
