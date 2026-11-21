#!/usr/bin/env bash
# Full cleanup of this project's runtime state.  Targets only: our pid files, the bridge named in
# config (default s1), its veth ports, and our run/ files.  It does NOT run `mn -c`
# (which deletes every OVS bridge on the machine); use that yourself only as a last resort.
. "$(dirname "$0")/env.sh"
"$ROOT/scripts/stop_backend.sh"
if [ -f run/topology_state.json ]; then
  tpid=$(python3 -c "import json;print(json.load(open('run/topology_state.json'))['pid'])")
  sudo kill "$tpid" 2>/dev/null && echo "asked topology (pid $tpid) to stop" && sleep 2
fi
br="$(cfg lab.switch.name)"
sudo ovs-vsctl --if-exists del-br "$br" && echo "removed bridge $br (if it existed)"
for link in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E "^${br}-eth[0-9]+$|^root-eth0$"); do
  sudo ip link del "$link" 2>/dev/null && echo "removed link $link"
done
rm -f run/topology_state.json run/client_session_*.json
echo "clean. Event log kept at $(cfg paths.events_log)  (delete it for a fresh dashboard timeline)"
