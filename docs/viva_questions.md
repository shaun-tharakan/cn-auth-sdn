# Likely viva questions and answers (based on this implementation)

## TCP sockets and concurrency
**Q: Walk me through your server's socket calls.** `socket()` → `setsockopt(SO_REUSEADDR)` → `bind((host, port))` → `listen(128)` → loop `accept()`; each accepted socket is handled in its own thread (`auth/server.py::_accept_loop/_handle_client`). The client does `create_connection()` (`socket`+`connect`).
**Q: TCP is a byte stream – how do you know where a message ends?** Newline-delimited JSON; `readline(limit+1)` reads one line, and a line longer than 4096 bytes without a newline is rejected (`message_too_large`).
**Q: How do you support multiple clients?** Thread per connection plus a semaphore capping connections (`max_connections`). Shared state (sessions, lockout counters, pending revocations) is protected by locks. Test: 25 concurrent logins produce 25 unique sessions.
**Q: What if a client disconnects or hangs?** `socket.settimeout` closes idle connections; `readline` returning `b""` means EOF; `OSError`s end the handler and the `finally:` frees the socket and the slot. Test: half-sent request then disconnect, server keeps working.
**Q: Why threads, not asyncio/select?** Simple, readable, enough for a lab; alternatives scale better (asyncio/epoll). Python's GIL is irrelevant here because the work is I/O bound (scrypt releases the GIL).
**Q: Why TCP and not UDP?** Login/session messages need reliable, ordered delivery; the protected service is TCP too, and TCP flows are easy to match in OpenFlow (`ip_proto=6`, `tcp_dst`).

## Authentication, authorization, sessions
**Q: Authentication vs authorization?** Who you are vs what you may do. `bob` authenticates but his role `guest` has no services → `role_not_permitted`, no rules.
**Q: How are passwords stored?** scrypt (n=2^14, r=8, p=1) with a random 16-byte salt, constant-time comparison (`hmac.compare_digest`); never logged. Unknown users still cost one hash to prevent username enumeration by timing.
**Q: Session identifiers?** `secrets.token_urlsafe(32)` = 256 random bits. The dashboard/controller only see a SHA-256 fingerprint.
**Q: How do sessions expire?** Absolute `expires_at`; checked lazily and by a reaper thread each second; expiry triggers a network revocation. Lifetime default 300 s.
**Q: Brute force?** Per (IP, username) lockout: 5 failures → 30 s.
**Q: Can a stolen session id be used from another host?** Not for network access: `access` must come from the session's source IP (`session_ip_mismatch`), tested in the integration suite.

## SDN, OpenFlow, OVS, Mininet
**Q: Control plane vs data plane?** The controller (OS-Ken) decides and programs rules; Open vSwitch forwards packets using its flow table at line speed without asking the controller (for the protected service, no packet ever goes to the controller).
**Q: What is OpenFlow?** The protocol between controller and switch (here 1.3): FlowMod (add/delete), Barrier, FlowStats, FlowRemoved, PacketIn, ErrorMsg.
**Q: What is a flow rule?** Match (fields like in_port, eth, IPv4, TCP port) + priority + actions + timeouts + cookie + counters.
**Q: Explain your rules.** Priority 200 per-grant allow (port+MAC+IP+TCP port, both directions); 100 drop all IPv4 to/from the protected host and all IPv6; 10 L2 forwarding by MAC; 0 table-miss to controller. Highest priority wins, so nothing bypasses the deny.
**Q: What is default-deny and how do you implement it?** Drop rules at priority 100 for traffic to and from `srv`; permissions are only exceptions installed at 200.
**Q: Why a cookie?** A 64-bit tag per grant; delete-by-cookie removes exactly that grant's rules, and flow-removed events can be mapped back.
**Q: Why a barrier request?** FlowMods are asynchronous. The barrier reply proves the switch processed them, so the auth server only tells the user "granted" after the rules exist (and detects errors).
**Q: Why hard_timeout?** Backstop: even if the controller/auth server crash, the switch removes the rule when the session would have expired.
**Q: Why OpenFlow 1.3 and OS-Ken?** 1.3 is widely supported by OVS/Mininet; OS-Ken is the maintained Ryu successor (Ryu has Python ≥3.10 problems). Version 3.0.1 is pinned because later releases dropped the `osken-manager` launcher; alternatives: Ryu, ONOS, ODL, POX.
**Q: What does Mininet do?** Emulates hosts (network namespaces), links (veth pairs) and OVS switches on one machine; real kernel TCP stacks, so tests are real.
**Q: Why is the VM attached as `root` on 10.10.0.254?** So the auth server and controller can be ordinary processes yet reachable by the hosts over the lab network.
**Q: `fail_mode=secure`?** If the controller disconnects the switch does not fall back to a learning-switch mode that would ignore the policy.

## Integration and revocation
**Q: How do auth server and controller integrate?** HTTP API on 127.0.0.1 with a shared token; the auth server sends `session_ref`, host, service, ttl. The controller validates inputs, installs rules, confirms with a barrier. Only this path can change policy; the dashboard is read-only.
**Q: Why does the controller not trust the username?** Any host could claim any name. Identity is established by the auth server; the controller trusts only the token holder and uses the *host* (from the verified source IP) for rule matching.
**Q: How does revocation work?** Logout, expiry, admin revoke or shutdown → `SessionManager.on_end` → `controller.revoke(session_ref)` → cookie-delete FlowMod. If the controller is down, revocation stays pending and is retried every second; the hard timeout is the backstop.
**Q: What if the controller is unavailable when granting?** Access is *not* granted (fail-closed): `controller_unavailable`; tested.
**Q: How is a session tied to a host?** Source IP of the TCP connection → inventory (host/MAC/port). Rules pin port+MAC+IP.

## Dashboard
**Q: How does it show real state?** It probes components (TCP ping to the auth server, controller health, switch registration, process checks) and reads sessions (admin API), grants and flow table (controller, which polls OVS via OpenFlow flow-stats) and the event log. Unreachable → `stopped/unknown` + `unavailable` messages; no fake data. Read-only.
**Q: Why not let the dashboard revoke?** Monitoring must not hold power over access control; revocation goes through the authenticated admin API (`auth.admin`).

## Security limitations and design choices
* Plain TCP auth channel (no TLS); shared-secret tokens in a config file; static inventory binding (not cryptographic identity); in-memory sessions; IP/MAC spoofing by root on the same host. Mitigations/alternatives: TLS, 802.1X, certificates, per-host keys, persistent session store, RBAC service.
* Reactive vs proactive: we install rules proactively when access is granted instead of sending packets to the controller (lower latency, simpler, no packet-in load).
* Why per-host rules rather than per-user? Packets carry addresses, not usernames; the controller can only match network fields, so the user→host binding is established during login.
* Why JSON lines? Human-readable, debuggable with `nc`; alternatives: length-prefixed binary, protobuf.
