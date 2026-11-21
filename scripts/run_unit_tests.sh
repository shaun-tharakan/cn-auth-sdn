#!/usr/bin/env bash
# Unit tests: no root, no Mininet, no running controller needed.
. "$(dirname "$0")/env.sh"
exec python3 -W ignore -m unittest discover -s tests/unit -t . -v "$@"
