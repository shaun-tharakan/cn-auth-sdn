# D1 demonstration script (≈ 8 minutes)

Preparation (once): `scripts/setup.sh`. Optional fresh timeline: `rm -f logs/events.jsonl`.

## Start
1. Terminal A: `scripts/start.sh backend` → prints the dashboard URL.
2. Terminal B: `scripts/start.sh topology` → wait for `switch connected to the controller; lab is ready`, you are at `mininet>`.
3. Browser: <http://127.0.0.1:5050>. *Expected:* five green "running" cards (auth, controller, switch, topology, protected service), no sessions, hosts h1–h3 `denied`, flow table with priority-100 `default-deny` rules.
4. Terminal C (optional): `scripts/demo_helpers.sh watch` – shows the priority-200/100 rules live.

## Scenario
| # | Command (in `mininet>`) | Expected output | What to say / point at |
|---|---|---|---|
| 1 | `h1 python3 network/service_client.py` | `BLOCKED: no response from 10.10.0.100:9000 within 3.0s` | Default deny; dashboard flow table: the `default-deny` packet counter grows; event `access_blocked` |
| 2 | `h1 python3 -m auth.client login --user alice --password alice-demo-pw` | `LOGIN OK: alice (role student) on host h1 [10.10.0.1]` | Session appears (status active); Authentication panel shows success |
| 3 | `h1 python3 network/service_client.py` | still `BLOCKED` | **Authentication is not authorization**; no rule yet |
| 4 | `h1 python3 -m auth.client access --service protected-echo` | `ACCESS GRANTED: protected-echo at 10.10.0.100:9000 …` | Policy decision → controller → two priority-200 rules; Network-access table: h1 `granted` (reason names the session) |
| 5 | `h1 python3 network/service_client.py` | `REACHED 10.10.0.100:9000 … echo: hello from a client` | Real traffic through the new rules; event `service_access` |
| 6 | `h3 python3 network/service_client.py` and `h2 …` | `BLOCKED` | Other hosts stay blocked |
| 7 | `h2 python3 -m auth.client login --user bob --password bob-demo-pw` then `h2 python3 -m auth.client access` | `ACCESS DENIED [role_not_permitted]` | Authenticated yet unauthorised: no rule installed |
| 8 | `sh ovs-ofctl -O OpenFlow13 dump-flows s1` (or `scripts/demo_helpers.sh grants` in Terminal C) | two lines with `priority=200 … nw_src=10.10.0.1 … tp_dst=9000` (and the mirror with `tp_src=9000`) | Same rules the dashboard shows; match = port+MAC+IP+TCP port |
| 9 | `h1 python3 -m auth.client logout` | `LOGGED OUT; network access revoked` | Controller deleted the rules (cookie delete) |
| 10 | `h1 python3 network/service_client.py` | `BLOCKED` | Flow table back to default-deny only; h1 `denied: logout` |

Bonus (expiry): set a short lifetime first (edit `auth.session_ttl_seconds` to 30 in `config/config.json`, then `scripts/stop_backend.sh && scripts/start.sh backend`), log in + access, run the client, wait → session turns `expired` on the dashboard, rules vanish, client `BLOCKED`.
Bonus (admin revoke): `python3 -m auth.admin revoke --user alice` from a normal terminal.
Bonus (fail-closed): stop only the controller (`kill $(cat run/controller.pid)`), then `access` → `controller_unavailable`; the dashboard shows the controller `stopped` and the switch `unknown`.

## Troubleshooting during the demo
* Step 1 returns `REACHED`: stale rules from an older run → `scripts/cleanup.sh`, restart.
* `cannot connect to auth server`: auth server not running or firewall (README §7).
* `h1 python3 …` says module not found: start the topology through `scripts/start.sh topology` (it exports `PYTHONPATH`).
* Dashboard flow table empty with "unavailable": controller or switch is down – that is the honest state, not a bug.
