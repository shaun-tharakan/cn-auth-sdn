# Authentication and Network Access Control Using SDN  (D1)

A TCP authentication service whose decisions are enforced **inside the network**: a Mininet host can
only reach the protected service after it has authenticated, been authorised, and the SDN controller has
installed OpenFlow rules on Open vSwitch. Logout, expiry or revocation removes those rules again.

```
 h1 h2 h3 ──TCP login/access──▶ Auth server ──HTTP (token)──▶ SDN controller ──OpenFlow 1.3──▶ Open vSwitch s1
 (clients)    (10.10.0.254:5000)  sessions+policy               (OS-Ken)                          │
    └───────── TCP :9000 (only after a grant) ───────────────────────────────────────────▶ srv (protected service)
                                     Dashboard (Flask, read-only) ◀── auth admin API, controller API, event log
```

## 1. What is implemented (D1) and what is not

| D1 requirement | Where |
|---|---|
| TCP auth server, multiple concurrent clients, newline-JSON protocol | `auth/server.py`, `docs/protocol.md` |
| CLI client (login, access, status, logout, shell) | `auth/client.py` |
| scrypt password hashing, random session ids, expiry, logout, revocation, lockout | `auth/passwords.py`, `auth/sessions.py`, `auth/server.py` |
| Authorization (authentication ≠ authorization) | `policy/engine.py` |
| Real SDN controller + dynamic OpenFlow install/remove | `controller/` (OS-Ken, OpenFlow 1.3) |
| Auth → controller integration (trusted token API, fail-closed) | `policy/controller_client.py`, controller HTTP API |
| Mininet topology + protected service | `network/` |
| Dashboard on real state | `dashboard/` |
| Logs, unit tests, Mininet integration tests, docs | `common/events.py`, `tests/`, `docs/` |

**Reserved for D2 (not implemented):** see `docs/extension_plan.md` (richer roles/policies, stronger identity binding,
idle timeouts and renewal, TLS for the auth channel, performance evaluation, etc.).

## 2. Verified environment

Everything below was executed (not just written) in an Ubuntu **24.04.4 LTS** environment with **Python 3.12.3**,
**Open vSwitch 3.3.9**, **Mininet 2.3.0**, **OS-Ken 3.0.1** (eventlet 0.41.3), **Flask 3.1.3**.

* Controller choice: OS-Ken is the maintained Ryu fork. Newer OS-Ken releases (4.x) removed the `osken-manager`
  launcher and the WSGI helper, so `requirements.txt` **pins `os-ken==3.0.1`**; the controller's HTTP API uses
  `eventlet.wsgi` directly. Original Ryu 4.34 is not used (known breakage on Python ≥ 3.10).
* OpenFlow **1.3** only (switch is started with `protocols=OpenFlow13`, controller declares `OFP_VERSIONS=[1.3]`).
* **Other Ubuntu/Python versions are not verified.** Ubuntu 22.04 (Python 3.10) should work with the same pins but I did not test it.
* My test sandbox had no OVS *kernel* module, so the end-to-end tests ran with the OVS **userspace datapath**
  (`CNAUTH_OVS_DATAPATH=user`). Your VM will normally use the kernel datapath (the default). The control-plane code
  path (OpenFlow messages, flow tables) is identical; see "Honest test report" below.

## 3. Setup (in the Ubuntu VM)

Edit on Windows with VS Code, then either (a) use **VS Code Remote - SSH** to open the folder inside the VM, or (b) copy the ZIP into the VM.

```bash
unzip cn-auth-sdn.zip && cd cn-auth-sdn
scripts/setup.sh          # apt: mininet + openvswitch-switch; .venv (system-site-packages); pip install; demo users; checks
sudo systemctl start openvswitch-switch      # if setup.sh warns that it is not running
```

`.venv` is created with `--system-site-packages` on purpose: Mininet's Python module comes from apt and must stay importable.

## 4. Configuration

Everything (IPs, MACs, switch ports, service port, timeouts, secrets, paths) is in `config/config.json`.
Defaults: subnet `10.10.0.0/24`, h1/h2/h3 = `.1/.2/.3`, `srv` = `.100` (service port `9000`), VM root namespace = `.254`
(auth server `:5000`), controller OpenFlow `:6653`, controller API `127.0.0.1:8080`, auth admin API `127.0.0.1:5001`,
dashboard `127.0.0.1:5050`, session lifetime 300 s. Override secrets without editing the file:
`CNAUTH_API_TOKEN`, `CNAUTH_ADMIN_TOKEN`; alternative config: `CNAUTH_CONFIG=/path/to/config.json`.

Demo users (created by `python3 -m auth.init_users`, stored hashed in `data/users.json`):

| user | password | role | may use `protected-echo`? |
|---|---|---|---|
| alice | `alice-demo-pw` | student | yes |
| carol | `carol-demo-pw` | admin | yes |
| bob | `bob-demo-pw` | guest | **no** (can log in, authorization denied) |

## 5. Run it (exact order)

```bash
# terminal 1 – controller + auth server + dashboard in the background (pid files in run/, logs in logs/)
scripts/start.sh backend
# terminal 2 – the Mininet lab (asks for sudo, opens the Mininet CLI)
scripts/start.sh topology
```
(or run `scripts/start.sh controller`, `auth`, `dashboard` in three separate terminals to watch each log).
Start the **controller before the topology**; the topology prints a warning if the switch never connects.

Open the dashboard at <http://127.0.0.1:5050> (from Windows: VS Code forwards the port automatically, or
`ssh -L 5050:127.0.0.1:5050 user@vm`).

### Using the CLI (inside the Mininet CLI)

```text
mininet> h1 python3 network/service_client.py                         # BLOCKED (default deny)
mininet> h1 python3 -m auth.client login --user alice --password alice-demo-pw
mininet> h1 python3 network/service_client.py                         # still BLOCKED: authenticated is not authorised
mininet> h1 python3 -m auth.client access --service protected-echo    # ACCESS GRANTED
mininet> h1 python3 network/service_client.py                         # REACHED ... echo
mininet> h3 python3 network/service_client.py                         # BLOCKED (h3 never logged in)
mininet> h1 python3 -m auth.client logout                             # network access revoked
mininet> h1 python3 network/service_client.py                         # BLOCKED again
```
Interactive menu instead: `h1 python3 -m auth.client shell` (works from an `xterm h1`). Omit `--password` to be prompted
(passwords on the command line are visible in `ps`; the flag exists for scripted demos).

Other tools (second terminal in the VM): `python3 -m auth.admin list`, `python3 -m auth.admin revoke --user alice`,
`scripts/demo_helpers.sh flows|grants|sessions|events|watch`.

### Inspect OpenFlow rules

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1          # the switch's real flow table
scripts/demo_helpers.sh grants                       # only the priority-200 allow rules
```
Granted state shows two `priority=200` rules (client→service and the reply path); denied state shows none.

### Shut down and clean up

```bash
# leave the Mininet CLI with `exit`, then
scripts/stop_backend.sh      # stops only the processes in run/*.pid
scripts/cleanup.sh           # + removes bridge s1, its veth ports and run/ files; never runs `mn -c`
```
Last resort if Mininet was killed uncleanly: `sudo mn -c` (**note:** this deletes *every* OVS bridge on the VM and kills `controller`/`ovs-openflowd` processes).

## 6. Tests

```bash
scripts/run_unit_tests.sh          # no root; 50 tests (auth, sessions, policy, flow rules, controller logic, dashboard)
scripts/run_integration_tests.sh   # needs sudo; real Mininet + OVS + controller; ~1 minute
CNAUTH_OVS_DATAPATH=user scripts/run_integration_tests.sh   # only if the VM lacks the OVS kernel module
```
The integration test builds its own lab on different ports and a 10 s session lifetime. It proves: default deny,
authorised access, other hosts blocked, a stolen session id rejected, authenticated-but-unauthorised denied, logout
revocation, expiry revocation, admin revocation, flow-table changes, event log contents, and fail-closed behaviour when the
controller dies.

### Honest test report (what I actually ran)

| Suite | Result |
|---|---|
| Unit tests (50) | **all passed** (Ubuntu 24.04, Python 3.12.3) |
| Mininet integration tests (10) | **all passed** on real Mininet 2.3.0 + Open vSwitch 3.3.9 + OS-Ken 3.0.1, using the OVS **userspace** datapath because the test machine has no OVS kernel module |
| Same integration tests with the OVS *kernel* datapath, on VirtualBox, VS Code Remote-SSH, Windows-side browser | **not run by me** – please run `scripts/run_integration_tests.sh` in your VM and report failures |
| Dashboard in a real browser (visual check) | **not run**; the dashboard's JSON endpoints were verified against the live stack, the HTML/JS/CSS were not opened in a browser |

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| Topology says the switch did not connect | Start the controller first (`scripts/start.sh backend`); check `logs/controller.out`; `sudo systemctl start openvswitch-switch` |
| `ERROR: cannot connect to auth server 10.10.0.254:5000` | Auth server not running, or a firewall (`sudo ufw status`) blocks the `root-eth0` interface; `sudo ufw disable` for the lab |
| `Exception: Error creating interface pair` / stale bridge | `scripts/cleanup.sh`, then retry (last resort `sudo mn -c`) |
| Dashboard shows "controller stopped / unknown" | It is honest: that process is not answering. `logs/controller.out`, `logs/auth.out` |
| `ModuleNotFoundError: mininet` in the venv | Recreate with `python3 -m venv --system-site-packages .venv` |
| ACCESS DENIED `controller_unavailable` | Controller or switch is down; access is deliberately not granted (fail-closed) |
| TCP hangs on the *userspace* datapath | Checksum offload on veth; the topology disables it automatically in `user` mode (needs `ethtool`) |
| Port already in use | A stale process from an earlier run: `scripts/stop_backend.sh`; check `ss -ltnp` |

## 8. Known limitations (honest security notes)

* Host↔session binding is a **controlled lab association**: the session is bound to the client's TCP source IP, and
  the controller's allow rules additionally pin the **switch port + MAC + IP** from a static inventory in the config.
  A host cannot borrow another host's session (different source IP) or use its rules from another port. It is *not*
  a cryptographic identity: someone with root on the *same* Mininet host can act as that host, and a real network would need 802.1X/certificates.
* The auth channel is plaintext TCP (a lab sniffer could read the password). TLS is a D2 proposal.
* Controller API and auth admin API are protected by shared tokens in `config/config.json` and bound to 127.0.0.1; change the tokens for anything beyond a lab.
* Sessions live in memory: restarting the auth server ends them (it also clears stale grants on startup).
* If the switch reconnects, the controller wipes the flow table (all grants vanish; users must request access again).
* If the controller dies, installed rules stay in the switch until their **hard timeout** (= remaining session time). That timeout is the backstop; the auth server also retries revocation until the controller returns.
* Only IPv4/TCP to the protected service is modelled; IPv6 is dropped lab-wide.
* ARP and traffic between clients and the management node are not restricted (only the protected host is).

## 9. Documentation map

`docs/architecture.md` (diagrams, flow) · `docs/protocol.md` · `docs/component_explanations.md` (every file explained) ·
`docs/demo_guide.md` (evaluation script) · `docs/viva_questions.md` · `docs/extension_plan.md` (D2 proposals).
