# Sourced by the other scripts: repo root, PYTHONPATH, virtualenv, config helper.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
[ -f "$ROOT/.venv/bin/activate" ] && . "$ROOT/.venv/bin/activate"
cd "$ROOT"
mkdir -p logs run data
cfg() { python3 -m common.config --get "$1"; }
