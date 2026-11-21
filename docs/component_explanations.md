# Component explanations (read this before the viva)

Written for a student who knows TCP/IP but is new to sockets-in-practice, SDN and OpenFlow. All examples are taken from the real code.

## 1. Map of the repository

| Path | What it does | Entry point / depends on |
|---|---|---|
| `config/config.json` | The single source of truth: IPs, MACs, ports, services, roles, timeouts, secrets, paths | read by `common/config.py` |
| `common/config.py` | `load_config()`, validation, helpers (`host_by_ip`) | everything |
| `common/events.py` | `EventLog.emit()` / `read_recent()` – shared JSON-lines log | every component, dashboard |
| `auth/server.py` | TCP authentication server (raw sockets + threads) | `python3 -m auth.server`; uses sessions, users, policy, controller_client, admin_api |
| `auth/client.py` | CLI client | `python3 -m auth.client …` |
| `auth/sessions.py` | Thread-safe session store with expiry/revoke callbacks | server |
| `auth/passwords.py`, `auth/users.py`, `auth/init_users.py` | scrypt hashing, user DB, demo-user creation | server |
| `auth/admin_api.py`, `auth/admin.py` | Local HTTP admin API and its CLI (list/revoke sessions) | server, dashboard |
| `policy/engine.py`, `policy/models.py` | Authorization decisions (pure functions) | server |
| `policy/controller_client.py` | HTTP client for the controller's trusted API | server |
| `controller/flow_rules.py` | *Which* OpenFlow rules should exist (pure data) | controller, tests |
| `controller/ofp_convert.py` | Rule → OpenFlow 1.3 FlowMod messages | controller |
| `controller/sdn_controller.py` | The OS-Ken app: OpenFlow handlers + HTTP API + polling | `osken-manager controller.sdn_controller` |
| `network/topology.py` | Mininet lab (`Lab` class) | `sudo python3 network/topology.py` |
| `network/protected_service.py`, `network/service_client.py` | The protected TCP echo service and a probing client | run on srv / h1.. |
| `dashboard/app.py`, `backends.py`, `templates/`, `static/` | Read-only web UI (JSON API + JS rendering) | `python3 -m dashboard.app` |
| `scripts/` | start/stop/cleanup/test helpers | `scripts/start.sh …` |
| `tests/unit`, `tests/integration` | unit tests; real Mininet tests | `scripts/run_*_tests.sh` |

## 2. How the system starts and communicates

1. `scripts/start.sh backend` launches `osken-manager … controller.sdn_controller` (listens for OpenFlow on 6653, API on 8080), `python3 -m auth.server` (TCP 5000, admin 5001) and the dashboard (5050).
2. `scripts/start.sh topology` runs `network/topology.py` as root. It builds the switch `s1` (OpenFlow 1.3, `fail_mode=secure`), hosts, links with **fixed port numbers and MACs from the config**, points the switch at the controller (`RemoteController`, 127.0.0.1:6653), and starts the service process inside `srv`.
3. When `s1` connects, the controller (`_state_change` → `_reset_switch`) deletes all flows and installs the default-deny base rules.
4. Communication paths: client ⇄ auth server (TCP/JSON), auth server → controller (HTTP + token), controller ⇄ switch (OpenFlow), dashboard → auth admin API / controller API / event log (read-only HTTP + file).

## 3. How a TCP connection is created, handled and closed (`auth/server.py`)

```python
sock = socket.socket(AF_INET, SOCK_STREAM); sock.bind((host, port)); sock.listen(128)   # start()
conn, addr = self._sock.accept()                                                          # _accept_loop
threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()      # one thread per client
```
`bind` claims the port, `listen` queues incoming handshakes, `accept` returns a new connected socket per client. Each client runs in its own thread, which is how many clients are served *concurrently*. `_handle_client` sets a socket timeout (idle clients are dropped), reads **one line** with `stream.readline(limit+1)` (a message longer than `max_message_bytes` is refused), answers, and loops. It leaves on EOF (client closed), timeout, oversize or send error; the `finally:` block closes the socket and frees a connection slot (a semaphore caps simultaneous connections). `SO_REUSEADDR` allows quick restarts.

**Demonstrates:** TCP stream sockets, framing a byte stream into messages (newline), thread-per-connection concurrency, timeouts and cleanup.

## 4. Successful login

`_op_login` → validates types/format → checks lockout → `UserStore.authenticate` (scrypt with the stored salt, constant-time compare) → `SessionManager.create` (256-bit token, `expires_at = now + ttl`, bound to the source IP, host name looked up from the inventory) → emits `login_success` + `session_created` → returns `session_id`. The client stores it in `run/client_session_<its IP>.json` (mode 0600).

## 5. Unsuccessful login

Wrong password **or** unknown user → identical `invalid_credentials` message (unknown users still burn one scrypt computation, so timing does not leak which usernames exist). The failure is counted per `(IP, username)`; after `max_failed_logins` (5) the pair is locked for `lockout_seconds`. Event `login_failure` (with reason, never the password) appears on the dashboard.

## 6. Sessions: creation and expiry (`auth/sessions.py`)

A `Session` holds username, role, `client_ip`, `host`, `created_at`, `expires_at`, `status`. Lifetime is **absolute** (no renewal in D1). Expiry is enforced twice: lazily in `get_active` (a request with an expired id is rejected and the session is ended), and by the **reaper thread** (`_reaper_loop` → `expire_due()` every second) so a session expires even if its owner never calls again. Any transition out of `active` (logout / expired / revoked) fires the `on_end` callback → `AuthServer._on_session_end` → network revocation. Only a hash fingerprint (`s-ab12cd34ef56`) is shown on the dashboard and sent to the controller.

## 7. Authentication vs authorization

* **Authentication** = proving who you are (password → session). Done in `_op_login`.
* **Authorization** = what that identity may do. Done in `policy/engine.py::PolicyEngine.decide`, called from `_op_access`.

Example: `bob` (role `guest`) logs in successfully, but `decide` returns `role_not_permitted` because `policy.roles.guest` is `[]`; no rule is ever installed. Also denied: unknown service, a request whose source IP differs from the session's IP, a source that is not a registered client host.

## 8. Associating a user with a Mininet host

The session stores `client_ip` (from `accept()`), and `host_by_ip` maps it to `h1/h2/h3`, which the config ties to a MAC and a switch port. See `docs/architecture.md` ("Identity ↔ host binding") and README §8 for the limits.

## 9. How the policy interface talks to the controller

`policy/controller_client.py::ControllerClient` sends `POST /policy/grant|revoke` with the `X-Policy-Token` header (compared with `hmac.compare_digest` in the controller). 4xx → `ControllerRejected`; network error or 5xx → `ControllerUnavailable`. `_op_access` treats *any* failure as "not granted" (**fail-closed**). The controller's API validates every field (`_api_grant`): host must be a registered client, service must exist, ttl must be a positive integer; the `username` field is stored for the audit log only and never used for a decision.

## 10. How OpenFlow rules are installed and removed (`controller/*`)

* `flow_rules.grant_rules()` returns two `RuleSpec`s (request path + reply path). `ofp_convert.flow_add()` turns each into `OFPFlowMod(command=ADD, priority=200, cookie=N, hard_timeout=ttl, flags=SEND_FLOW_REM, match=OFPMatch(...), instructions=[ApplyActions(output)])`.
* `grant_access()` sends both messages, then a **barrier request** and waits for the barrier reply (the switch confirms it processed everything). Errors reported by the switch (`_on_error`) cause a rollback and a refusal.
* Revocation: `flow_delete_cookie()` = `OFPFlowMod(command=DELETE, cookie=N, cookie_mask=0xFFFF…)` removes exactly the rules of that grant. The **cookie** is the grant's id.
* Defense in depth: the switch deletes the rule itself at `hard_timeout`; the controller hears about it via `EventOFPFlowRemoved` and cleans its books.

## 11. How Open vSwitch processes a packet

A frame arrives on a port → OVS looks in table 0 for the **highest-priority matching entry** → executes its actions (output / drop / send to controller) and updates counters. Example: h2 sending TCP to srv:9000 matches the priority-100 `ip,nw_dst=10.10.0.100 actions=drop` (nothing higher matches); h1 after a grant matches the priority-200 rule first and is forwarded to port 4. This is the **data plane**; the controller that wrote the rules is the **control plane**. No packet to the protected service is ever sent to the controller: the rules are installed *proactively*.

## 12. Mininet, hosts, switch and service

Mininet creates network namespaces (hosts), veth pairs (links) and an OVS bridge. `topology.py` pins MAC and port numbers (`addHost(..., mac=...)`, `addLink(..., port2=...)`) so `flow_rules.py` can match on them. The VM's root namespace is attached with `Node('root', inNamespace=False)` + a link, giving it 10.10.0.254 so the auth server (a normal process) is reachable by hosts. The service runs via `srv.popen(...)` so it listens inside `srv`'s namespace.

## 13. How the dashboard gets real state (`dashboard/backends.py`)

`/api/overview` really probes: TCP `ping` to the auth server (speaks the protocol), HTTP health of the controller, the controller's list of connected switches, the Mininet topology process (pid in `run/topology_state.json`, checked with `os.kill(pid, 0)` and `/proc/<pid>/cmdline`), the service process. Refused → `stopped`; no answer/unknown → `unknown`; controller up but no switch → `disconnected`. `/api/sessions` = auth admin API; `/api/access` + `/api/flows` = controller (the flows are what the **switch** reported in a flow-stats reply, with its packet counters); `/api/events` = tail of the event log. If a source is down the endpoint returns `available:false` + an error text; the JS shows it instead of inventing rows.

## 14. Logging (`common/events.py`)

`EventLog(path, "auth").emit("login_failure", username=..., reason=...)` appends one JSON line using a single `os.write` on an `O_APPEND` descriptor (safe across processes). Keys named `password`, `session_id`, `token`… are stripped automatically. Components: `auth`, `controller`, `service`, `topology`. Key events: `login_success/failure`, `session_created/expired/logout/revoked`, `authorization_decision`, `access_granted/denied`, `grant_installed`, `flow_rule_installed`, `grant_revoked`, `flow_expired`, `switch_connected/disconnected`, `base_rules_installed`, `access_blocked` (switch counter on a deny rule grew), `service_access` (service really reached).

## 15. Key files in detail

**`auth/server.py`** – *Purpose:* authentication + session + access orchestration. *Key:* `AuthServer.start/stop`, `_accept_loop`, `_handle_client`, `_op_login/_op_access/_op_status/_op_logout`, `_on_session_end`, `_reaper_loop`, `_retry_pending`. *Input:* JSON lines; *output:* JSON lines, events, controller calls. *Depends on:* sessions, users, engine, controller_client, admin_api, events. *Concept:* sockets, concurrency, orchestration.

**`auth/sessions.py`** – `SessionManager.create/get_active/logout/revoke*/expire_due/snapshot`; lock-protected dicts; callback outside the lock to avoid deadlocks. *Concept:* session lifecycle.

**`policy/engine.py`** – `PolicyEngine.decide(...) -> Decision`. Pure → easy to unit test. *Concept:* authorization, default deny.

**`controller/flow_rules.py`** – `base_rules(cfg)`, `grant_rules(cfg, host, service, hard_timeout, cookie)`, priority constants. *Concept:* match/action rules, priorities.

**`controller/sdn_controller.py`** – `PolicyController`: `_state_change` (switch up/down), `_reset_switch`, `grant_access`, `revoke_access`, `_confirm` (barrier), `_poll_loop` + `_on_flow_stats` (real flow table), `_on_flow_removed`, `_on_packet_in` (unknown MAC logging), `_wsgi_app/_route` (HTTP API). *Depends on:* os-ken, flow_rules, ofp_convert. *Concept:* control plane, OpenFlow messages, barrier, cookies.

**`network/topology.py`** – `Lab.start/stop`, state file. *Concept:* emulated topologies, namespaces.

## 16. Running tests

`scripts/run_unit_tests.sh` – no root; sockets on loopback and a recording fake controller (only in unit tests; the product code has no mocks). `scripts/run_integration_tests.sh` – root; it starts a controller, an auth server and a Mininet lab on other ports and asserts real reachability with `service_client.py` and real flow tables with `ovs-ofctl dump-flows`.

## 17. Diagnosing common failures

1. **Nothing reachable, even after access granted:** `sudo ovs-ofctl -O OpenFlow13 dump-flows s1` – are there `priority=200` rules with the right `in_port`? If not, check `logs/controller.out`/the event log for `openflow_error`.
2. **Client cannot reach the auth server:** `h1 ping 10.10.0.254`; then `ss -ltn | grep 5000`; firewall.
3. **Dashboard says `unknown`:** that component's API did not answer; `curl 127.0.0.1:8080/policy/health` and `curl 127.0.0.1:5001/health`.
4. **`controller_unavailable`:** controller down or switch not connected (`switch_connected` in `/policy/health`).
5. **Switch won't connect:** controller must be started first and listen on `openflow_port`; OVS must be `OpenFlow13`.
