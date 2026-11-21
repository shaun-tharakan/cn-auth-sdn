# D2 extension plan (proposals only – NOT implemented in D1)

The D1 modules were split so each of these changes stays local. Every item below is a **proposal**.

| Proposal | Where it would plug in | Notes |
|---|---|---|
| Richer authorization (per-service rules, time windows, per-host allow lists, deny lists) | `policy/engine.py`, `policy` section of the config | `Decision` and `decide()` signatures can stay the same |
| Additional protected services / ports | `services` in the config; `flow_rules.py` already loops over services | add another service host to the topology |
| Stronger identity↔host binding (certificates, challenge-response, ARP/DHCP binding, 802.1X style) | `_op_login` / `PolicyEngine`; controller inventory | replaces the "controlled lab association" |
| TLS for the auth channel; token rotation; mutual auth between auth server and controller | `auth/server.py` (wrap socket with `ssl`), `policy/controller_client.py` | |
| Idle timeout + session renewal; max sessions per user | `auth/sessions.py` | use OpenFlow `idle_timeout` too |
| Persistent sessions/audit trail (SQLite) | `auth/sessions.py`, `common/events.py` | survive auth-server restarts |
| Dynamic SDN behaviour for the D2 rubric: rate limiting / meters, blocking repeated offenders by installing drop rules, rerouting/recovery on link failure, multi-switch topology | `controller/` (new rule kinds in `flow_rules.py`) | brute-force lockout currently lives in the auth server |
| Challenging scenarios: server overload/failure, controller failover, packet loss, link failure, many clients | `network/topology.py` (TCLink), tests | |
| Performance evaluation vs a static-ACL baseline: login latency, grant latency, time-to-revoke, throughput, flow-table size | new `scripts/benchmark_*.py`, `docs/results.md` | iperf/own client; compare "static allow-all-authenticated ACL" vs dynamic grants |
| Dashboard controls (revoke button through the admin API), charts, filters | `dashboard/` | keep the API/render separation |
| More integration tests (multi-client races, flow-table assertions, restarts) | `tests/integration/` | |
| Packaging: Docker/Vagrant for a reproducible VM, CI for unit tests | repo root | |
