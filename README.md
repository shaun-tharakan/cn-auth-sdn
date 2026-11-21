# CN-Auth-SDN: TCP/TLS Authentication & Dynamic SDN Access Control

A zero-trust network access control system where hosts must authenticate with a socket-based authentication service before an OS-Ken OpenFlow 1.3 SDN controller dynamically installs time-limited flow rules to grant, restrict, or revoke access to a protected service across a multi-switch Mininet/Open vSwitch fabric.

---

## Project Report

* **PDF Report:** [View Project Report (PDF)](docs/cn_auth_sdn_project_report.pdf)

---

## System Overview

* **Authentication ≠ Authorization:** Logging in verifies identity and issues a 256-bit `session_id` with a 300s TTL, but network packets remain blocked until the policy engine approves the user's role and the controller installs OpenFlow rules.
* **Control & Data Plane Separation:** The TLS auth server (`:5000`), OS-Ken controller (`:6653` OpenFlow / `:8080` Policy API), and read-only Flask dashboard (`:5050`) run in the host root namespace (`10.10.0.254`), while Mininet isolates `h1`–`h3` and `srv:9000` across three Open vSwitch instances (`s1`, `s2`, `s3`).
* **Fail-Closed Design:** Switches run in `failMode="secure"`. If the controller is down, access requests fail closed, pending revocations retry every second, and switch-enforced `hard_timeout` values automatically expire stale grants.

---

## Features Implemented

### Demo 1 — Core Authentication & Dynamic SDN Access
* **Socket Auth Server (`auth/`):** Multi-threaded TCP server with `scrypt` password hashing, 256-bit session tokens, TTL expiry reaper, brute-force lockout, and session-to-IP binding.
* **Policy Engine (`policy/`):** Role-based access control (`alice`/`student` and `carol`/`admin` allowed for `protected-echo`; `bob`/`guest` denied) and fail-closed `ControllerClient` authenticated with `X-Policy-Token`.
* **OS-Ken OpenFlow 1.3 Controller (`controller/`):** Priority ladder (`200` grant > `100` default-deny > `10` L2 forwarding > `0` table-miss), `OFPBarrierReply` confirmation, and 64-bit `cookie`-based revocation.
* **Mininet Lab & Dashboard (`network/`, `dashboard/`):** Protected TCP echo server (`srv:9000`), probe client, and live read-only Flask UI (`http://127.0.0.1:5050`).

### Demo 2 — Security, Scale, Multi-Switch & Admin Control
* **TLS Authentication Channel:** `scripts/gen_certs.sh` generates a local CA (`certs/ca.crt`) and SAN-signed server certificate (`10.10.0.254` and `127.0.0.1`). `auth/server.py` enforces TLS 1.2+ (ephemeral ECDHE + symmetric encryption) and rejects plaintext TCP connections.
* **Multi-Switch Topology (`s1`, `s2`, `s3`):** Access switches `s2` (`h1`, `h2`) and `s3` (`h3`) trunk to core switch `s1` (`srv`, `root`). The controller uses BFS path routing to install priority-`200` rules only on switches along the active path (`s2 → s1` for `h1`; `s3 → s1` for `h3`).
* **Concurrent Users & Load Testing:** `BoundedSemaphore(256)` connection cap, `SessionManager` `RLock`, controller `_op_lock`/`_state_lock` with per-user `user_state`, and `scripts/load_test.py` for multi-threaded TLS benchmarking.
* **Admin Role (`carol`):** In-band TLS commands (`auth.client admin ...`) and local CLI (`auth.admin`) to list active users (`users`), revoke sessions (`revoke`), view audit logs (`logs`), and block/unblock hosts (`block`/`unblock`) across all switches at priority `300`.

---

## Repository Structure

| Directory | Purpose |
|---|---|
| `auth/` | TLS/TCP auth server, CLI client, `scrypt` passwords, session manager, admin CLI & HTTP API |
| `policy/` | Pure authorization engine (`PolicyEngine`) and fail-closed `ControllerClient` |
| `controller/` | OS-Ken OpenFlow 1.3 app, BFS multi-switch rule generator (`flow_rules.py`), `OFPFlowMod` converter |
| `network/` | 3-switch Mininet topology (`topology.py`), protected echo service (`srv:9000`), probe client |
| `dashboard/` | Read-only Flask web UI (`http://127.0.0.1:5050`) polling live server, switch, and log state |
| `common/` | Shared configuration loader/validator (`config.py`) and JSONL event logger (`events.py`) |
| `config/` | Lab topology, switch links, services, roles, TLS paths, and ports (`config.json`) |
| `scripts/` | Setup, TLS cert generation, start/stop helpers, load test, and unit/integration test runners |
| `tests/` | 61 unit tests (`tests/unit/`) and 11 Mininet + OVS integration tests (`tests/integration/`) |
| `docs/` | Project report (PDF & DOCX), architecture notes, protocol spec, and demo guides |

---

## Setup & Three-Terminal Workflow

### First-Time Setup (run once, without `sudo`)
```bash
bash scripts/setup.sh
```

### Terminal 1 — Start Backend (normal Ubuntu/WSL terminal, not `mininet>`)
```bash
cd ~/cn-auth-sdn-d2gem
scripts/start.sh backend
```
Starts the OS-Ken controller, TLS authentication server, and Flask dashboard in the background. Open the dashboard in your browser:
`http://127.0.0.1:5050`

### Terminal 2 — Start Mininet Topology (normal Ubuntu/WSL terminal)
```bash
cd ~/cn-auth-sdn-d2gem
sudo mn -c
scripts/start.sh topology
```
Wait for `switches connected to the controller; lab is ready` and the `mininet>` prompt. All host demo commands below run here.

### Terminal 3 — Watch Flow Rules (optional, normal Ubuntu/WSL terminal)
```bash
cd ~/cn-auth-sdn-d2gem
watch -n 1 "sudo ovs-ofctl -O OpenFlow13 dump-flows s1; echo '--- s2 ---'; sudo ovs-ofctl -O OpenFlow13 dump-flows s2; echo '--- s3 ---'; sudo ovs-ofctl -O OpenFlow13 dump-flows s3"
```

### Pre-Demo Dashboard Checklist (`http://127.0.0.1:5050`)
* **Authentication server:** `running` (`answers ping on TLS port 5000`)
* **SDN controller:** `running` (`OpenFlow 1.3`)
* **Open vSwitch:** `running` (`3/3 switches connected (s1, s2, s3)`)
* **Mininet topology:** `running` (`switches s1,s2,s3, 5 nodes`)
* **Protected service:** `running` (`process alive on 10.10.0.100:9000`)
* **Network access & topology:** `h1`, `h2`, `h3` initially `denied` (dashed red), with priority-`100` `default-deny` rules on all three switches.

---

## Demo 1 Cases (Run at `mininet>`)

### Case 1 — Unauthenticated host tries to access the service
```bash
h1 python3 network/service_client.py
```
* **Expected:** `BLOCKED`. Priority-`100` default-deny rules drop traffic to `10.10.0.100:9000`.

### Case 2 — Alice logs in successfully
```bash
h1 python3 -m auth.client login --user alice --password alice-demo-pw
```
* **Expected:** `LOGIN OK: alice (role student) on host h1 [10.10.0.1]`. Creates a 300s session without granting network access yet.

### Case 3 — Alice tries again before requesting authorization
```bash
h1 python3 network/service_client.py
```
* **Expected:** still `BLOCKED` (authentication ≠ authorization).

### Case 4 — Alice requests authorization & reaches the service
```bash
h1 python3 -m auth.client access --service protected-echo
h1 python3 network/service_client.py
```
* **Expected:** `ACCESS GRANTED`, then `REACHED` (`echo: hello from a client`). The controller installs priority-`200` rules along `s2 → s1`.

### Case 5 — Other hosts remain blocked
```bash
h2 python3 network/service_client.py
h3 python3 network/service_client.py
```
* **Expected:** both `BLOCKED`. Grants are pinned to `h1`'s port, MAC, and IP.

### Case 6 — Bob (`guest`) logs in but is denied authorization
```bash
h2 python3 -m auth.client login --user bob --password bob-demo-pw
h2 python3 -m auth.client access --service protected-echo
```
* **Expected:** `LOGIN OK`, then `ACCESS DENIED [role_not_permitted]`.

### Case 7 — Inspect live switch rules
```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```
* **Expected:** Priority-`100` default-deny rules alongside Alice's priority-`200` allow rules while her grant is active.

### Case 8 — Alice logs out & access is revoked
```bash
h1 python3 -m auth.client logout
h1 python3 network/service_client.py
```
* **Expected:** `LOGGED OUT; network access revoked`, then `BLOCKED`.

### Optional Demo 1 Bonus — Session expiry & local admin revoke
* **Session expiry:** Set `auth.session_ttl_seconds` to `30` in `config/config.json`, restart the backend (`scripts/stop_backend.sh && scripts/start.sh backend`), log in, request access, and wait 30s — the session expires and switch rules are removed.
* **Local admin revoke (Terminal 3):**
  ```bash
  python3 -m auth.admin revoke --user alice
  ```

---

## Demo 2 Cases (TLS, Multi-Switch, Admin Role & Concurrency)

### Case 1 — TLS Plaintext Rejection & Handshake Verification
At `mininet>`:
```bash
h1 python3 -m auth.client --no-tls status
```
* **Expected:** `ERROR: connection error: [Errno 104] Connection reset by peer`.

Optional OpenSSL handshake check (Terminal 3, press `Ctrl+C` to exit):
```bash
echo '{"op":"ping"}' | openssl s_client -connect 127.0.0.1:5000 -CAfile certs/ca.crt -quiet
```
* **Expected:** `verify return:1` and `{"ok":true,"op":"ping","server":"cn-auth","tls":true,...}`.

### Case 2 — Multi-Switch Path (`h1` on `s2 → s1 → srv`)
At `mininet>`:
```bash
h1 python3 -m auth.client login --user alice --password alice-demo-pw
h1 python3 -m auth.client access --service protected-echo
sh ovs-ofctl -O OpenFlow13 dump-flows s2 | grep priority=200
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=200
sh ovs-ofctl -O OpenFlow13 dump-flows s3 | grep priority=200
```
* **Expected:** 2 priority-`200` rules on `s2`, 2 on `s1`, and 0 on `s3`.

### Case 3 — Second Switch Path (`h3` on `s3 → s1 → srv`)
At `mininet>`:
```bash
h3 python3 -m auth.client login --user carol --password carol-demo-pw
h3 python3 -m auth.client access --service protected-echo
h3 python3 network/service_client.py
sh ovs-ofctl -O OpenFlow13 dump-flows s3 | grep priority=200
```
* **Expected:** `REACHED`, 2 priority-`200` rules on `s3`, and `h3 → s3 → s1` turns green on the dashboard.

### Case 4 — Admin Role (`carol` on `h3` vs non-admin `alice` on `h1`)
At `mininet>`:
```bash
# Non-admin denied
h1 python3 -m auth.client admin users
# -> Expected: ADMIN ERROR [forbidden]: admin role required

# Admin lists users & views logs
h3 python3 -m auth.client admin users
h3 python3 -m auth.client admin logs --limit 10

# Admin blocks h1 across all 3 switches (priority 300)
h3 python3 -m auth.client admin block --host h1 --reason "suspicious traffic"
sh ovs-ofctl -O OpenFlow13 dump-flows s2 | grep priority=300
h1 python3 network/service_client.py
h1 python3 -m auth.client login --user alice --password alice-demo-pw
# -> Expected: BLOCKED at OVS, login rejected with host_blocked

# Admin unblocks h1 & revokes a user
h3 python3 -m auth.client admin unblock --host h1
h1 python3 -m auth.client login --user alice --password alice-demo-pw
h1 python3 -m auth.client access --service protected-echo
h3 python3 -m auth.client admin revoke --user alice
h1 python3 network/service_client.py
# -> Expected: h1 recovers after unblock, then revoke drops Alice's session and h1 is BLOCKED again
```

### Case 5 — Concurrent Users & Multi-Threaded TLS Load Test
Launch `h1` (`alice`), `h2` (`bob`), and `h3` (`carol`) concurrently at `mininet>`:
```python
py (lambda ts: ([t.start() for t in ts], [t.join() for t in ts]))([__import__("threading").Thread(target=lambda h,u,p: print(f"=== {h.name} ({u}) ===\n"+h.cmd(f"python3 -m auth.client login --user {u} --password {p} && python3 -m auth.client access --service protected-echo && python3 network/service_client.py")), args=x) for x in [(h1,"alice","alice-demo-pw"),(h2,"bob","bob-demo-pw"),(h3,"carol","carol-demo-pw")]])
```

Run the multi-threaded TLS load test from `h1` at `mininet>` (or from Terminal 3 with `--host 127.0.0.1`):
```bash
h1 python3 scripts/load_test.py --host 10.10.0.254 --clients 20 --iterations 2
```
* **Expected:** `errors: 0` with throughput (`ops/s`) and `p50`/`p95`/`max` latency metrics.

---

## Automated Tests

Run from a normal Ubuntu/WSL terminal:
```bash
scripts/run_unit_tests.sh
scripts/run_integration_tests.sh
```

---

## Maintenance, Counter Reset & Full Cleanup

### Reset Switch Packet Counters (without deleting rules)
```bash
for s in s1 s2 s3; do sudo ovs-ofctl -O OpenFlow13 reset-counters "$s"; done
```

### Clean Reset Between Demo Runs
```bash
scripts/stop_backend.sh
sudo mn -c
truncate -s 0 logs/events.jsonl
rm -f run/client_session_*.json
scripts/start.sh backend
```

### Full Cleanup Before Packaging / Sharing
```bash
cd ~/cn-auth-sdn-d2gem
scripts/stop_backend.sh
pkill -f osken-manager || true
pkill -f "auth.server" || true
pkill -f "dashboard.app" || true
sudo mn -c
rm -rf .venv logs/* run/* certs/* data/*
find . -name '__pycache__' -exec rm -rf {} +
find . -name '*:Zone.Identifier' -delete
```