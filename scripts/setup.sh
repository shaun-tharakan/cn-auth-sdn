#!/usr/bin/env bash
# One-time setup inside the Ubuntu VM.  Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== system packages (needs sudo) =="
if ! command -v mn >/dev/null || ! command -v ovs-vsctl >/dev/null; then
  sudo apt-get update
  sudo apt-get install -y mininet openvswitch-switch python3-venv python3-pip openssl
fi
echo "== Python virtualenv (.venv, with system site-packages so it can import the apt 'mininet' module) =="
[ -d .venv ] || python3 -m venv --system-site-packages .venv
. .venv/bin/activate
pip install -r requirements.txt
mkdir -p logs run data certs
echo "== TLS certificates =="
bash scripts/gen_certs.sh
echo "== demo users =="
PYTHONPATH=. python3 -m auth.init_users
echo "== checks =="
python3 --version
for t in mn ovs-vsctl ovs-ofctl osken-manager openssl; do
  command -v "$t" >/dev/null && echo "ok: $t" || echo "MISSING: $t"
done
python3 -c "import mininet" 2>/dev/null && echo "ok: python mininet module" || echo "MISSING: python mininet module"
sudo systemctl is-active openvswitch-switch >/dev/null 2>&1 && echo "ok: openvswitch-switch service active" \
  || echo "WARNING: start it with: sudo systemctl start openvswitch-switch"
echo "Setup finished. Next: scripts/start.sh backend ; then scripts/start.sh topology"
