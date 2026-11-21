#!/usr/bin/env bash
# Usage: scripts/start.sh <controller|auth|dashboard|backend|topology>
#   controller / auth / dashboard / topology run in the FOREGROUND (one terminal each).
#   backend starts controller + auth + dashboard in the background (pid files in run/, logs in logs/).
. "$(dirname "$0")/env.sh"
what="${1:-}"
ensure_certs() {
  if [ "$(cfg auth.tls.enabled 2>/dev/null || echo False)" = "True" ]; then
    bash scripts/gen_certs.sh >/dev/null
  fi
}
run_controller() {
  exec osken-manager --ofp-listen-host "$(cfg controller.openflow_host)" \
       --ofp-tcp-listen-port "$(cfg controller.openflow_port)" controller.sdn_controller
}
case "$what" in
  controller) run_controller ;;
  auth)       ensure_certs; exec python3 -m auth.server ;;
  dashboard)  exec python3 -m dashboard.app ;;
  topology)   exec sudo -E env "PATH=$PATH" python3 network/topology.py "${@:2}" ;;
  backend)
    [ -f "$(cfg paths.users_db)" ] || python3 -m auth.init_users
    ensure_certs
    for name in controller auth dashboard; do
      if [ -f "run/$name.pid" ] && kill -0 "$(cat run/$name.pid)" 2>/dev/null; then echo "$name already running"; continue; fi
      case $name in
        controller) cmd=(osken-manager --ofp-listen-host "$(cfg controller.openflow_host)" --ofp-tcp-listen-port "$(cfg controller.openflow_port)" controller.sdn_controller) ;;
        auth)       cmd=(python3 -m auth.server) ;;
        dashboard)  cmd=(python3 -m dashboard.app) ;;
      esac
      setsid nohup "${cmd[@]}" > "logs/$name.out" 2>&1 &
      echo $! > "run/$name.pid"
      echo "started $name (pid $!, log logs/$name.out)"
      [ "$name" = controller ] && sleep 3
    done
    sleep 2
    echo "dashboard: http://$(cfg dashboard.host):$(cfg dashboard.port)"
    echo "next: scripts/start.sh topology" ;;
  *) echo "usage: $0 controller|auth|dashboard|backend|topology"; exit 1 ;;
esac
