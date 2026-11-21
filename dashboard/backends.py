"""Live data sources for the dashboard.  Everything here is read-only and honest:
if a component cannot be reached the result says so; nothing is invented."""
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request

from common.events import read_recent

AUTH_EVENTS = {"login_success", "login_failure"}
CATEGORY = {
    "auth": {"login_success", "login_failure", "auth_server_started", "auth_server_stopped", "internal_error",
             "tls_handshake_failed"},
    "session": {"session_created", "session_expired", "session_logout", "session_revoked"},
    "policy": {"authorization_decision", "access_granted", "access_denied", "grant_installed", "grant_revoked",
               "revocation_failed", "flow_expired", "policy_api_forbidden", "grants_cleared",
               "host_blocked", "host_unblocked", "admin_block_host", "admin_unblock_host", "admin_revoke", "admin_denied"},
    "network": {"switch_connected", "switch_disconnected", "base_rules_installed", "flow_rule_installed",
                "access_blocked", "unknown_host_seen", "openflow_error", "unexpected_switch"},
    "service": {"service_access", "service_started", "service_stopped"},
}


def category(event):
    for name, members in CATEGORY.items():
        if event in members:
            return name
    return "system"


def summarize(e):
    ev = e["event"]
    g = e.get
    table = {
        "login_success": lambda: f"{g('username')} signed in from {g('host') or g('client_ip')} ({g('client_ip')})",
        "login_failure": lambda: f"failed sign-in for {g('username')} from {g('host') or g('client_ip')}: {g('reason')}",
        "session_created": lambda: f"session {g('session')} created for {g('username')}",
        "session_expired": lambda: f"session {g('session')} of {g('username')} expired",
        "session_logout": lambda: f"{g('username')} logged out (session {g('session')})",
        "session_revoked": lambda: f"session {g('session')} of {g('username')} revoked: {g('reason')}",
        "authorization_decision": lambda: f"{'allowed' if g('allowed') else 'denied'}: {g('username')} on {g('host')} "
                                          f"-> {g('service')} ({g('reason')})",
        "access_granted": lambda: f"network access granted to {g('host')} for {g('service')} (user {g('username')})",
        "access_denied": lambda: f"access NOT granted to {g('host')}: {g('code')}",
        "grant_installed": lambda: f"flow rules installed: {g('host')} -> {g('service')}, hard timeout {g('hard_timeout')}s",
        "grant_revoked": lambda: f"flow rules removed: {g('host')} -> {g('service')} ({g('reason')})",
        "flow_rule_installed": lambda: f"rule p{g('priority')} {g('kind')}: {g('match')} -> {g('actions')}",
        "switch_connected": lambda: f"switch {g('switch') or g('dpid')} ({g('dpid')}) connected to the controller",
        "switch_disconnected": lambda: f"switch {g('switch') or g('dpid')} ({g('dpid')}) disconnected from the controller",
        "base_rules_installed": lambda: f"{g('count')} base rules installed on {g('switch') or 'switch'} (default-deny posture)",
        "access_blocked": lambda: f"switch {g('switch') or ''} dropped {g('packets')} packet(s) at a drop rule ({g('rule')})",
        "host_blocked": lambda: f"host {g('host')} blocked by admin ({g('reason')})",
        "host_unblocked": lambda: f"host {g('host')} unblocked by admin",
        "service_access": lambda: f"protected service reached by {g('client_ip')}",
        "unknown_host_seen": lambda: f"unknown MAC {g('mac')} seen on port {g('in_port')}",
        "revocation_failed": lambda: f"could not revoke network access for {g('session')}; will retry",
    }
    try:
        return table[ev]()
    except KeyError:
        skip = {"ts", "time", "component", "event", "level"}
        rest = ", ".join(f"{k}={v}" for k, v in e.items() if k not in skip)
        return rest or ev.replace("_", " ")


def _get_json(url, timeout=1.5):
    """Return (data, error_kind): error_kind in None | 'refused' | 'error'."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        return None, ("refused" if isinstance(reason, ConnectionRefusedError) else f"error: {reason}")
    except (socket.timeout, ConnectionError, OSError, ValueError) as exc:
        return None, f"error: {exc}"


def controller_url(cfg, path):
    c = cfg["controller"]
    return f"http://{c['api_host']}:{c['api_port']}{path}"


def admin_url(cfg, path):
    a = cfg["auth"]
    return f"http://{a['admin_host']}:{a['admin_port']}{path}"


def _ping_auth_tcp(cfg):
    """Speak the real TLS/TCP protocol to the auth server: send {"op":"ping"}, expect a pong."""
    host = "127.0.0.1" if cfg["auth"]["bind_host"] in ("0.0.0.0", "") else cfg["auth"]["bind_host"]
    tls_cfg = cfg["auth"].get("tls") or {}
    tls_on = bool(tls_cfg.get("enabled"))
    try:
        with socket.create_connection((host, cfg["auth"]["port"]), timeout=1.5) as raw:
            if tls_on:
                ca = tls_cfg.get("ca_cert")
                ctx = ssl.create_default_context(cafile=ca) if ca else ssl._create_unverified_context()
                sock = ctx.wrap_socket(raw, server_hostname=host)
            else:
                sock = raw
            sock.sendall(b'{"op":"ping"}\n')
            reply = json.loads(sock.makefile("rb").readline().decode())
            proto = "TLS" if tls_on else "TCP"
            return ("running", f"answers ping on {proto} port {cfg['auth']['port']}") if reply.get("ok") else \
                   ("unknown", "port open but unexpected reply")
    except ConnectionRefusedError:
        return "stopped", "connection refused"
    except (OSError, ssl.SSLError, ValueError) as exc:
        return "unknown", f"cannot tell: {exc}"


def _pid_alive(pid, needle=None):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # process exists (owned by root)
    if needle:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                return needle.encode() in fh.read()
        except OSError:
            return True
    return True


def topology_state(cfg):
    path = os.path.join(cfg["paths"]["run_dir"], "topology_state.json")
    try:
        with open(path) as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, "missing"
    except (OSError, ValueError) as exc:
        return None, f"error: {exc}"


def overview(cfg):
    now = time.time()
    items = []
    state, detail = _ping_auth_tcp(cfg)
    health, _ = _get_json(admin_url(cfg, "/health"))
    if health and state == "running":
        detail += f"; {health['active_sessions']} active session(s)"
    items.append({"key": "auth", "name": "Authentication server", "state": state, "detail": detail})

    ctl, err = _get_json(controller_url(cfg, "/policy/health"))
    if ctl:
        items.append({"key": "controller", "name": "SDN controller", "state": "running",
                      "detail": f"OpenFlow {ctl['openflow']}; {ctl['active_grants']} active grant(s)"})
        switches = ctl.get("switches", [])
        expected = ctl.get("expected_switches", 1)
        items.append({"key": "switch", "name": "Open vSwitch",
                      "state": "running" if ctl.get("switch_connected") else ("degraded" if switches else "disconnected"),
                      "detail": f"{len(switches)}/{expected} switches connected ({', '.join(s.get('name', s['dpid']) for s in switches)})"
                      if switches else "no switch is connected to the controller"})
    else:
        items.append({"key": "controller", "name": "SDN controller",
                      "state": "stopped" if err == "refused" else "unknown",
                      "detail": "connection refused" if err == "refused" else f"cannot tell ({err})"})
        items.append({"key": "switch", "name": "Open vSwitch", "state": "unknown",
                      "detail": "cannot tell: the controller is not reachable"})

    topo, terr = topology_state(cfg)
    if topo and _pid_alive(topo["pid"]):
        sw_list = topo.get("switches") or [topo.get("switch")]
        items.append({"key": "topology", "name": "Mininet topology", "state": "running",
                      "detail": f"switches {','.join(sw_list)}, {len(topo['hosts'])} nodes (pid {topo['pid']})"})
        svc_ok = _pid_alive(topo["service_pid"], "protected_service")
        items.append({"key": "service", "name": "Protected service", "state": "running" if svc_ok else "stopped",
                      "detail": (f"process alive on {topo['hosts']['srv']['ip']}:{topo['service']['port']} "
                                 "(reachability is policy-gated by design)") if svc_ok else "service process not found"})
    else:
        why = "no topology process found" if terr == "missing" or topo else f"cannot tell ({terr})"
        state = "stopped" if (terr == "missing" or topo) else "unknown"
        items.append({"key": "topology", "name": "Mininet topology", "state": state, "detail": why})
        items.append({"key": "service", "name": "Protected service", "state": state,
                      "detail": "runs inside the topology; " + why})
    return {"available": True, "generated_at": now, "components": items}


def sessions(cfg):
    data, err = _get_json(admin_url(cfg, "/sessions"))
    if data is None:
        return {"available": False, "error": "auth server admin API unreachable" if err == "refused" else err,
                "sessions": []}
    return {"available": True, "generated_at": data["generated_at"], "sessions": data["sessions"]}


def access(cfg):
    data, err = _get_json(controller_url(cfg, "/policy/state"))
    if data is None:
        return {"available": False, "error": "controller unreachable" if err == "refused" else err, "access": [],
                "hosts": []}
    return {"available": True, "generated_at": data["generated_at"], "access": data["access"],
            "grants": data["grants"], "hosts": data["hosts"], "switch_connected": data["health"]["switch_connected"]}


def flows(cfg):
    data, err = _get_json(controller_url(cfg, "/policy/flows"))
    if data is None:
        return {"available": False, "error": "controller unreachable" if err == "refused" else err, "flows": []}
    if not data["switch_connected"]:
        return {"available": False, "error": "switch not connected: no flow table to show", "flows": []}
    if data["updated_at"] is None:
        return {"available": False, "error": "flow table not read from the switch yet", "flows": []}
    stale = data["age_seconds"] is not None and data["age_seconds"] > 3 * max(1.0, cfg["controller"].get("flow_poll_seconds", 2))
    return {"available": True, "flows": data["flows"], "age_seconds": data["age_seconds"], "stale": stale,
            "updated_at": data["updated_at"]}


def events(cfg, limit=80, only=None):
    """Newest-first events. ``only`` is a set holding one category name, or {"auth_activity"}."""
    limit = max(1, min(int(limit), 300))
    out = []
    for e in reversed(read_recent(cfg["paths"]["events_log"], 600)):
        cat = category(e["event"])
        if only == {"auth_activity"}:
            if e["event"] not in AUTH_EVENTS:
                continue
        elif only and cat not in only:
            continue
        out.append({"ts": e["ts"], "component": e["component"], "event": e["event"], "level": e.get("level", "info"),
                    "category": cat, "summary": summarize(e), "username": e.get("username"), "host": e.get("host"),
                    "client_ip": e.get("client_ip"), "reason": e.get("reason")})
        if len(out) >= limit:
            break
    return {"available": True, "events": out}
