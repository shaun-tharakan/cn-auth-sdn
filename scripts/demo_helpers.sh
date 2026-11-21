#!/usr/bin/env bash
# Usage: scripts/demo_helpers.sh flows | grants | sessions | events | watch
. "$(dirname "$0")/env.sh"
br="$(cfg lab.switch.name)"
case "${1:-}" in
  flows)    sudo ovs-ofctl -O OpenFlow13 dump-flows "$br" ;;
  grants)   sudo ovs-ofctl -O OpenFlow13 dump-flows "$br" | grep "priority=200" || echo "(no grant rules: default-deny only)" ;;
  sessions) python3 -m auth.admin list ;;
  events)   tail -n 25 "$(cfg paths.events_log)" ;;
  watch)    watch -n 1 "sudo ovs-ofctl -O OpenFlow13 dump-flows $br | grep -E 'priority=(200|100)' | cut -c1-170" ;;
  *) echo "usage: $0 flows|grants|sessions|events|watch"; exit 1 ;;
esac
