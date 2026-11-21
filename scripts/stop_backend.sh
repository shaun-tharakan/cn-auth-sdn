#!/usr/bin/env bash
# Stops ONLY the processes this project started (via run/*.pid). Nothing else is touched.
. "$(dirname "$0")/env.sh"
for name in dashboard auth controller; do
  if [ -f "run/$name.pid" ]; then
    pid=$(cat "run/$name.pid")
    kill -0 "$pid" 2>/dev/null && kill "$pid" && echo "stopped $name (pid $pid)"
    rm -f "run/$name.pid"
  fi
done
