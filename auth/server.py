"""TLS-capable TCP authentication server (raw sockets + threads).

Protocol: newline-delimited JSON over TLS/TCP, one request -> one response (docs/protocol.md).
Operations: ping, login, access, status, logout, and admin_* (admin role only).

Responsibilities
  * validate credentials (scrypt) and create sessions bound to the client's source IP
  * authorise access requests through the policy engine
  * ask the SDN controller (trusted HTTP API) to grant / revoke / block network access
  * expire sessions in a reaper thread and revoke their network access
Run:  python3 -m auth.server [--config config/config.json]
"""
import argparse
import json
import logging
import math
import re
import signal
import socket
import ssl
import sys
import threading
import time

from auth.admin_api import AdminAPI
from auth.sessions import SessionManager
from auth.users import UserStore
from common.config import ConfigError, client_hosts, host_by_ip, load_config
from common.events import EventLog, read_recent
from policy.controller_client import ControllerClient, ControllerRejected, ControllerUnavailable
from policy.engine import PolicyEngine

log = logging.getLogger("auth.server")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
SERVICE_RE = re.compile(r"^[a-z0-9_-]{1,64}$")


def _err(error, message, **extra):
    return {"ok": False, "error": error, "message": message, **extra}


class AuthServer:
    def __init__(self, cfg, users=None, controller=None, clock=time.time, events=None):
        self.cfg, self.a, self.clock = cfg, cfg["auth"], clock
        c = cfg["controller"]
        self.events = events or EventLog(cfg["paths"]["events_log"], "auth")
        self.users = users or UserStore(cfg["paths"]["users_db"])
        self.engine = PolicyEngine(cfg)
        self.controller = controller or ControllerClient(f"http://{c['api_host']}:{c['api_port']}", c["api_token"])
        self.sessions = SessionManager(self.a["session_ttl_seconds"], clock=clock,
                                       history=self.a.get("session_history", 50), on_end=self._on_session_end)
        self.port = None
        self.started_at = None
        self._sock = None
        self._ssl_ctx = self._build_ssl_context()
        self._tls_enabled = self._ssl_ctx is not None
        self._stop = threading.Event()
        self._threads = []
        self._slots = threading.BoundedSemaphore(self.a.get("max_connections", 256))
        self._connections = 0
        self._conn_lock = threading.Lock()
        self._failures = {}          # (ip, username) -> [count, locked_until]
        self._fail_lock = threading.Lock()
        self._blocked_hosts = {}     # host -> {"host", "reason", "blocked_by", "blocked_at"}
        self._block_lock = threading.Lock()
        self._pending = {}           # session ref -> session whose network revocation must be retried
        self._pending_all = False    # a "revoke everything" request still has to reach the controller
        self._pending_lock = threading.Lock()

    def _build_ssl_context(self):
        tls = self.a.get("tls") or {}
        if not tls.get("enabled"):
            return None
        cert, key = tls.get("cert"), tls.get("key")
        if not cert or not key:
            raise ConfigError("auth.tls.enabled is true but cert/key paths are missing")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.a["bind_host"], self.a["port"]))
        sock.listen(256)
        sock.settimeout(1.0)  # lets the accept loop notice shutdown
        self._sock, self.port, self.started_at = sock, sock.getsockname()[1], self.clock()
        self.events.emit("auth_server_started", port=self.port, tls=self._tls_enabled,
                         session_ttl=self.a["session_ttl_seconds"])
        self._attempt_revoke_all("auth server started: clearing stale network grants")
        for target, name in ((self._accept_loop, "accept"), (self._reaper_loop, "reaper")):
            t = threading.Thread(target=target, name=f"auth-{name}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop.set()
        self.sessions.end_all("auth server shutdown")
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=3)
        self.events.emit("auth_server_stopped")

    # ------------------------------------------------------------------ socket layer
    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                try:
                    if not self._tls_enabled:
                        conn.sendall(json.dumps(_err("server_busy", "too many connections")).encode() + b"\n")
                except OSError:
                    pass
                conn.close()
                continue
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def _handle_client(self, conn, addr):
        peer_ip = addr[0]
        with self._conn_lock:
            self._connections += 1
        try:
            conn.settimeout(self.a["socket_timeout_seconds"])
            if self._ssl_ctx is not None:
                try:
                    conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    self.events.emit("tls_handshake_failed", level="warn", client_ip=peer_ip, detail=str(exc))
                    return
            limit = self.a["max_message_bytes"]
            with conn.makefile("rwb") as stream:
                while not self._stop.is_set():
                    try:
                        line = stream.readline(limit + 1)
                    except socket.timeout:
                        self._send(stream, _err("timeout", "connection idle for too long"))
                        break
                    except OSError:
                        break
                    if not line:
                        break  # client closed the connection
                    if len(line) > limit and not line.endswith(b"\n"):
                        self._send(stream, _err("message_too_large", f"message exceeds {limit} bytes"))
                        break
                    if not self._send(stream, self._process(line, peer_ip)):
                        break
        finally:
            try:
                conn.close()
            except OSError:
                pass
            with self._conn_lock:
                self._connections -= 1
            self._slots.release()

    @staticmethod
    def _send(stream, obj):
        try:
            stream.write(json.dumps(obj, separators=(",", ":")).encode() + b"\n")
            stream.flush()
            return True
        except (OSError, ValueError):
            return False

    def _process(self, line, peer_ip):
        try:
            req = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return _err("bad_json", "message is not valid JSON")
        try:
            return self._dispatch(req, peer_ip)
        except Exception:  # never leak internals to the client
            log.exception("unhandled error while processing request")
            self.events.emit("internal_error", level="error", client_ip=peer_ip)
            return _err("internal_error", "unexpected server error")

    # ------------------------------------------------------------------ operations
    def _dispatch(self, req, peer_ip):
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            return _err("bad_request", "request must be a JSON object with a string 'op'")
        handlers = {
            "ping": self._op_ping,
            "login": self._op_login,
            "access": self._op_access,
            "status": self._op_status,
            "logout": self._op_logout,
            "admin_list_users": self._op_admin_list_users,
            "admin_revoke": self._op_admin_revoke,
            "admin_block_host": self._op_admin_block_host,
            "admin_unblock_host": self._op_admin_unblock_host,
            "admin_list_blocked": self._op_admin_list_blocked,
            "admin_logs": self._op_admin_logs,
        }
        handler = handlers.get(req["op"])
        if handler is None:
            return _err("unknown_op", f"unknown operation {req['op'][:32]!r}")
        return handler(req, peer_ip)

    def _op_ping(self, req, peer_ip):
        return {"ok": True, "op": "ping", "server": "cn-auth", "tls": self._tls_enabled, "time": self.clock()}

    def _is_host_blocked(self, host):
        if not host:
            return None
        with self._block_lock:
            return self._blocked_hosts.get(host)

    def _op_login(self, req, peer_ip):
        username, password = req.get("username"), req.get("password")
        if not (isinstance(username, str) and USERNAME_RE.match(username)
                and isinstance(password, str) and 0 < len(password) <= 256):
            return _err("bad_request", "username and password are required (username: letters, digits, _ . @ -)")
        host, _ = host_by_ip(self.cfg, peer_ip)
        blocked = self._is_host_blocked(host)
        if blocked:
            self.events.emit("login_failure", level="warn", username=username, client_ip=peer_ip, host=host,
                             reason="host_blocked")
            return _err("host_blocked", f"host {host} is blocked: {blocked['reason']}")
        key = (peer_ip, username)
        wait = self._lockout_remaining(key)
        if wait > 0:
            self.events.emit("login_failure", level="warn", username=username, client_ip=peer_ip, host=host,
                             reason="locked_out")
            return _err("locked_out", f"too many failed attempts; retry in {math.ceil(wait)}s", retry_after=math.ceil(wait))
        user = self.users.authenticate(username, password)
        if user is None:
            self._record_failure(key)
            self.events.emit("login_failure", level="warn", username=username, client_ip=peer_ip, host=host,
                             reason="invalid_credentials")
            return _err("invalid_credentials", "invalid username or password")
        self._clear_failures(key)
        session = self.sessions.create(user.username, user.role, peer_ip, host)
        self.events.emit("login_success", username=user.username, role=user.role, client_ip=peer_ip, host=host)
        self.events.emit("session_created", username=user.username, session=session.ref, client_ip=peer_ip,
                         host=host, expires_at=session.expires_at)
        return {"ok": True, "session_id": session.session_id, "username": user.username, "role": user.role,
                "host": host, "client_ip": peer_ip, "expires_at": session.expires_at,
                "ttl_seconds": self.a["session_ttl_seconds"],
                "allowed_services": self.engine.allowed_services(user.role)}

    def _op_access(self, req, peer_ip):
        sid, service = req.get("session_id"), req.get("service")
        if not (isinstance(sid, str) and 0 < len(sid) <= 128 and isinstance(service, str) and SERVICE_RE.match(service)):
            return _err("bad_request", "session_id and service are required")
        session, error = self.sessions.get_active(sid)
        if error:
            return _err(error, "session has expired; please log in again" if error == "session_expired"
                        else "no such active session; please log in")
        blocked = self._is_host_blocked(session.host)
        if blocked:
            return _err("host_blocked", f"host {session.host} is blocked: {blocked['reason']}")
        decision = self.engine.decide(username=session.username, role=session.role, session_ip=session.client_ip,
                                      request_ip=peer_ip, service=service)
        self.events.emit("authorization_decision", level="info" if decision.allowed else "warn",
                         username=session.username, session=session.ref, client_ip=peer_ip,
                         host=decision.host or host_by_ip(self.cfg, peer_ip)[0], service=service,
                         allowed=decision.allowed, code=decision.code, reason=decision.reason)
        if not decision.allowed:
            return _err("access_denied", decision.reason, code=decision.code)
        remaining = max(1, int(math.ceil(session.expires_at - self.clock())))
        self.sessions.mark_grant_attempt(sid)
        try:
            result = self.controller.grant(session.ref, session.username, decision.host, service, remaining)
        except ControllerUnavailable as exc:
            self.events.emit("access_denied", level="error", username=session.username, session=session.ref,
                             host=decision.host, service=service, code="controller_unavailable", detail=str(exc))
            return _err("controller_unavailable", "network controller unavailable; access NOT granted")
        except ControllerRejected as exc:
            self.events.emit("access_denied", level="error", username=session.username, session=session.ref,
                             host=decision.host, service=service, code="controller_rejected", detail=str(exc))
            return _err("controller_rejected", f"controller refused the request: {exc.message}")
        if not self.sessions.record_grant(sid, service, {"host": decision.host, "granted_at": self.clock()}):
            self._revoke_network(session.ref, "session ended while granting access")
            return _err("invalid_session", "session ended while the request was processed")
        self.events.emit("access_granted", username=session.username, session=session.ref, host=decision.host,
                         service=service, expires_at=session.expires_at)
        svc = self.cfg["services"][service]
        return {"ok": True, "granted": True, "service": service, "host": decision.host,
                "service_ip": self.cfg["lab"]["hosts"][svc["host"]]["ip"], "service_port": svc["port"],
                "expires_at": session.expires_at, "reason": decision.reason, "flows": result.get("flows", [])}

    def _op_status(self, req, peer_ip):
        sid = req.get("session_id")
        if not isinstance(sid, str):
            return _err("bad_request", "session_id is required")
        session, error = self.sessions.get_active(sid)
        if error:
            return _err(error, "session is not active")
        return {"ok": True, "username": session.username, "role": session.role, "host": session.host,
                "client_ip": session.client_ip, "expires_at": session.expires_at,
                "seconds_remaining": max(0, round(session.expires_at - self.clock())),
                "services": sorted(session.services), "allowed_services": self.engine.allowed_services(session.role)}

    def _op_logout(self, req, peer_ip):
        sid = req.get("session_id")
        if not isinstance(sid, str):
            return _err("bad_request", "session_id is required")
        session = self.sessions.logout(sid)  # fires _on_session_end -> network revocation
        if session is None:
            return _err("invalid_session", "no such active session")
        return {"ok": True, "message": "logged out", "network_access_revoked": session.revocation != "pending"}

    # ------------------------------------------------------------------ admin protocol operations
    def _require_admin(self, req, peer_ip):
        sid = req.get("session_id")
        if not isinstance(sid, str) or not sid:
            return None, _err("bad_request", "session_id is required")
        session, error = self.sessions.get_active(sid)
        if error:
            return None, _err(error, "session is not active")
        if session.client_ip != peer_ip:
            return None, _err("session_ip_mismatch", "session was created on a different host")
        if session.role != "admin":
            self.events.emit("admin_denied", level="warn", username=session.username, role=session.role,
                             op=req.get("op"), client_ip=peer_ip)
            return None, _err("forbidden", "admin role required")
        return session, None

    def _op_admin_list_users(self, req, peer_ip):
        session, err = self._require_admin(req, peer_ip)
        if err:
            return err
        return {"ok": True, "users": self.admin_list_users()}

    def _op_admin_revoke(self, req, peer_ip):
        session, err = self._require_admin(req, peer_ip)
        if err:
            return err
        username, ref = req.get("username"), req.get("session_ref")
        if not (isinstance(username, str) or isinstance(ref, str)):
            return _err("bad_request", "username or session_ref is required")
        revoked = self.admin_revoke(username=username, ref=ref)
        self.events.emit("admin_revoke", admin=session.username, target_user=username, target_ref=ref, revoked=revoked)
        return {"ok": True, "revoked": revoked}

    def _op_admin_block_host(self, req, peer_ip):
        session, err = self._require_admin(req, peer_ip)
        if err:
            return err
        host = req.get("host")
        if host not in client_hosts(self.cfg):
            by_ip, info = host_by_ip(self.cfg, host)
            if by_ip and info["role"] == "client":
                host = by_ip
        if host not in client_hosts(self.cfg):
            by_ip, info = host_by_ip(self.cfg, host)
            if by_ip and info["role"] == "client":
                host = by_ip
        reason = str(req.get("reason") or f"blocked by {session.username}")[:200]
        if host not in client_hosts(self.cfg):
            return _err("unknown_host", f"{host!r} is not a registered client host")
        try:
            self.admin_block_host(host, reason, blocked_by=session.username)
        except ControllerUnavailable as exc:
            return _err("controller_unavailable", f"controller unavailable; host {host} NOT blocked: {exc}")
        except ControllerRejected as exc:
            return _err("controller_rejected", f"controller refused block: {exc.message}")
        return {"ok": True, "host": host, "blocked": True, "reason": reason}

    def _op_admin_unblock_host(self, req, peer_ip):
        session, err = self._require_admin(req, peer_ip)
        if err:
            return err
        host = req.get("host")
        if host not in client_hosts(self.cfg):
            by_ip, info = host_by_ip(self.cfg, host)
            if by_ip and info["role"] == "client":
                host = by_ip
        if host not in client_hosts(self.cfg):
            return _err("unknown_host", f"{host!r} is not a registered client host")
        try:
            was_blocked = self.admin_unblock_host(host, unblocked_by=session.username)
        except ControllerUnavailable as exc:
            return _err("controller_unavailable", f"controller unavailable; host {host} NOT unblocked: {exc}")
        except ControllerRejected as exc:
            return _err("controller_rejected", f"controller refused unblock: {exc.message}")
        return {"ok": True, "host": host, "blocked": False, "was_blocked": was_blocked}

    def _op_admin_list_blocked(self, req, peer_ip):
        session, err = self._require_admin(req, peer_ip)
        if err:
            return err
        return {"ok": True, "blocked_hosts": self.admin_list_blocked()}

    def _op_admin_logs(self, req, peer_ip):
        session, err = self._require_admin(req, peer_ip)
        if err:
            return err
        limit = req.get("limit", 50)
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            limit = 50
        level = req.get("level")
        return {"ok": True, "events": self.admin_logs(limit=limit, level=level)}

    # ------------------------------------------------------------------ admin helpers (also used by AdminAPI)
    def admin_list_users(self):
        return [s for s in self.sessions.snapshot() if s["status"] == "active"]

    def admin_revoke(self, username=None, ref=None):
        if username:
            ended = self.sessions.revoke_user(username)
        elif ref:
            ended = self.sessions.revoke_ref(ref)
        else:
            ended = []
        return [s.ref for s in ended]

    def admin_block_host(self, host, reason="blocked by administrator", blocked_by="admin"):
        if host not in client_hosts(self.cfg):
            raise ValueError(f"{host!r} is not a registered client host")
        # End active sessions on that host first
        for row in self.sessions.snapshot():
            if row["status"] == "active" and row["host"] == host:
                self.sessions.revoke_ref(row["ref"], f"host blocked: {reason}")
        self.controller.block_host(host, reason)
        entry = {"host": host, "reason": reason, "blocked_by": blocked_by, "blocked_at": self.clock()}
        with self._block_lock:
            self._blocked_hosts[host] = entry
        self.events.emit("admin_block_host", level="warn", admin=blocked_by, host=host, reason=reason)
        return entry

    def admin_unblock_host(self, host, unblocked_by="admin"):
        if host not in client_hosts(self.cfg):
            raise ValueError(f"{host!r} is not a registered client host")
        self.controller.unblock_host(host, f"unblocked by {unblocked_by}")
        with self._block_lock:
            removed = self._blocked_hosts.pop(host, None)
        self.events.emit("admin_unblock_host", admin=unblocked_by, host=host)
        return removed is not None

    def admin_list_blocked(self):
        with self._block_lock:
            return sorted(self._blocked_hosts.values(), key=lambda b: b["host"])

    def admin_logs(self, limit=50, level=None):
        limit = max(1, min(int(limit), 300))
        events = list(reversed(read_recent(self.cfg["paths"]["events_log"], limit * 2)))
        if level:
            events = [e for e in events if e.get("level") == level]
        return events[:limit]

    def health(self):
        with self._pending_lock:
            pending = len(self._pending) + (1 if self._pending_all else 0)
        with self._conn_lock:
            connections = self._connections
        with self._block_lock:
            blocked = sorted(self._blocked_hosts)
        return {"ok": True, "service": "auth", "port": self.port, "tls": self._tls_enabled,
                "uptime": round(self.clock() - self.started_at, 1),
                "active_sessions": self.sessions.active_count(), "connections": connections,
                "pending_revocations": pending, "blocked_hosts": blocked,
                "session_ttl_seconds": self.a["session_ttl_seconds"]}

    # ------------------------------------------------------------------ session end -> network revoke
    def _on_session_end(self, session):
        event = {"expired": "session_expired", "logged_out": "session_logout", "revoked": "session_revoked"}[session.status]
        self.events.emit(event, username=session.username, session=session.ref, host=session.host,
                         reason=session.end_reason, services=sorted(session.services))
        if session.needs_revocation:
            self._revoke_for(session)

    def _revoke_for(self, session):
        if self._revoke_network(session.ref, f"{session.status}: {session.end_reason}"):
            session.revocation = "done"
        else:
            session.revocation = "pending"
            with self._pending_lock:
                self._pending[session.ref] = session

    def _revoke_network(self, ref, reason):
        try:
            self.controller.revoke(ref, reason)
            return True
        except (ControllerUnavailable, ControllerRejected) as exc:
            self.events.emit("revocation_failed", level="error", session=ref, detail=str(exc),
                             note="will retry; flow hard timeout is the backstop")
            return False

    def _attempt_revoke_all(self, reason):
        try:
            self.controller.revoke_all(reason)
            self._pending_all = False
        except (ControllerUnavailable, ControllerRejected):
            self._pending_all = True  # retried by the reaper until the controller answers

    def _reaper_loop(self):
        while not self._stop.wait(self.a.get("reaper_interval_seconds", 1.0)):
            try:
                self.sessions.expire_due()
                self._retry_pending()
            except Exception:
                log.exception("reaper iteration failed")

    def _retry_pending(self):
        if self._pending_all:
            self._attempt_revoke_all("retry: clear stale network grants")
        with self._pending_lock:
            items = list(self._pending.items())
        for ref, session in items:
            if self._revoke_network(ref, f"{session.status}: {session.end_reason} (retry)"):
                session.revocation = "done"
                with self._pending_lock:
                    self._pending.pop(ref, None)

    # ------------------------------------------------------------------ brute-force protection
    def _lockout_remaining(self, key):
        with self._fail_lock:
            entry = self._failures.get(key)
            return max(0.0, entry[1] - self.clock()) if entry else 0.0

    def _record_failure(self, key):
        with self._fail_lock:
            entry = self._failures.setdefault(key, [0, 0.0])
            entry[0] += 1
            if entry[0] >= self.a.get("max_failed_logins", 5):
                entry[0], entry[1] = 0, self.clock() + self.a.get("lockout_seconds", 30)

    def _clear_failures(self, key):
        with self._fail_lock:
            self._failures.pop(key, None)


def main():
    parser = argparse.ArgumentParser(description="TLS-capable TCP authentication server")
    parser.add_argument("--config")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        cfg = load_config(args.config)
        server = AuthServer(cfg)
    except (ConfigError, OSError) as exc:
        print(f"error: {exc}\nhint: run `python3 -m auth.init_users` and `scripts/gen_certs.sh`", file=sys.stderr)
        return 1
    server.start()
    admin = AdminAPI(server, cfg["auth"]["admin_host"], cfg["auth"]["admin_port"], cfg["auth"]["admin_token"])
    admin.start()
    proto = "TLS" if server._tls_enabled else "TCP"
    print(f"auth server ({proto}) listening on {cfg['auth']['bind_host']}:{server.port}  "
          f"(admin API {cfg['auth']['admin_host']}:{cfg['auth']['admin_port']})")
    done = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: done.set())
    done.wait()
    print("shutting down: revoking all sessions ...")
    admin.stop()
    server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
