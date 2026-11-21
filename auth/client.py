"""Command-line authentication client (run it on a Mininet host).

    python3 -m auth.client login  --user alice          (password is prompted)
    python3 -m auth.client access --service protected-echo
    python3 -m auth.client status
    python3 -m auth.client logout
    python3 -m auth.client admin users                   (admin role only)
    python3 -m auth.client admin revoke --user alice     (admin role only)
    python3 -m auth.client admin block --host h2         (admin role only)
    python3 -m auth.client admin unblock --host h2       (admin role only)
    python3 -m auth.client admin logs --limit 20         (admin role only)
    python3 -m auth.client shell                         (interactive menu)

The session id returned by the server is stored in run/client_session_<local-ip>.json
(mode 0600) so that the following commands can reuse it.  Exit codes:
0 success, 1 server refused the request, 2 cannot reach the server.
"""
import argparse
import getpass
import json
import os
import socket
import ssl
import sys
import time

from common.config import auth_server_address, load_config


class ConnectionProblem(Exception):
    pass


class AuthClient:
    """One TLS/TCP connection to the auth server; send a JSON line, read a JSON line."""

    def __init__(self, host, port, timeout=5.0, tls=False, ca_cert=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.tls, self.ca_cert = tls, ca_cert
        self.sock = self.stream = None

    def __enter__(self):
        try:
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.tls:
                ctx = ssl.create_default_context(cafile=self.ca_cert) if self.ca_cert else ssl._create_unverified_context()
                self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
            else:
                self.sock = raw
        except (OSError, ssl.SSLError) as exc:
            raise ConnectionProblem(f"cannot connect to auth server {self.host}:{self.port}: {exc}")
        self.stream = self.sock.makefile("rwb")
        return self

    def __exit__(self, *exc):
        for obj in (self.stream, self.sock):
            try:
                obj.close()
            except (OSError, AttributeError):
                pass

    @property
    def local_ip(self):
        return self.sock.getsockname()[0]

    def request(self, payload):
        try:
            self.stream.write(json.dumps(payload).encode() + b"\n")
            self.stream.flush()
            line = self.stream.readline(1024 * 1024)
        except OSError as exc:
            raise ConnectionProblem(f"connection error: {exc}")
        if not line:
            raise ConnectionProblem("server closed the connection")
        try:
            return json.loads(line.decode())
        except ValueError:
            raise ConnectionProblem("server sent an invalid response")


class StateFile:
    def __init__(self, cfg, local_ip, directory=None):
        self.path = os.path.join(directory or cfg["paths"]["run_dir"], f"client_session_{local_ip}.json")

    def load(self):
        try:
            with open(self.path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def save(self, data):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)

    def clear(self):
        try:
            os.remove(self.path)
        except OSError:
            pass


def fmt_time(epoch):
    return time.strftime("%H:%M:%S", time.localtime(epoch))


def cmd_login(client, state, args):
    user = args.user or input("username: ")
    password = args.password if args.password is not None else getpass.getpass("password: ")
    resp = client.request({"op": "login", "username": user, "password": password})
    if not resp.get("ok"):
        print(f"LOGIN FAILED: {resp.get('message', resp.get('error'))}")
        return 1
    state.save({"session_id": resp["session_id"], "username": resp["username"]})
    print(f"LOGIN OK: {resp['username']} (role {resp['role']}) on host {resp['host'] or 'unregistered'} [{resp['client_ip']}]")
    print(f"  session id : {resp['session_id'][:8]}... (stored in {state.path})")
    print(f"  expires at : {fmt_time(resp['expires_at'])} ({resp['ttl_seconds']}s)")
    print(f"  your role may request: {', '.join(resp['allowed_services']) or 'nothing (authenticated only)'}")
    return 0


def _need_session(state):
    data = state.load()
    if not data:
        print("not logged in on this host: run `login` first")
        return None
    return data["session_id"]


def _handle_session_error(resp, state):
    if resp.get("error") in ("session_expired", "invalid_session"):
        state.clear()
        print(f"SESSION PROBLEM: {resp.get('message')}")
        return True
    return False


def cmd_access(client, state, args):
    sid = _need_session(state)
    if not sid:
        return 1
    resp = client.request({"op": "access", "session_id": sid, "service": args.service})
    if resp.get("ok"):
        print(f"ACCESS GRANTED: {resp['service']} at {resp['service_ip']}:{resp['service_port']} "
              f"(from host {resp['host']}, until {fmt_time(resp['expires_at'])})")
        print(f"  reason: {resp['reason']}")
        return 0
    if _handle_session_error(resp, state):
        return 1
    print(f"ACCESS DENIED [{resp.get('code', resp.get('error'))}]: {resp.get('message')}")
    return 1


def cmd_status(client, state, args):
    sid = _need_session(state)
    if not sid:
        return 1
    resp = client.request({"op": "status", "session_id": sid})
    if not resp.get("ok"):
        _handle_session_error(resp, state) or print(f"error: {resp.get('message')}")
        return 1
    print(f"user {resp['username']} (role {resp['role']}) on {resp['host']} [{resp['client_ip']}]")
    print(f"  {resp['seconds_remaining']}s remaining; granted services: {', '.join(resp['services']) or 'none'}")
    return 0


def cmd_logout(client, state, args):
    sid = _need_session(state)
    if not sid:
        return 1
    resp = client.request({"op": "logout", "session_id": sid})
    state.clear()
    if resp.get("ok"):
        print("LOGGED OUT" + ("; network access revoked" if resp.get("network_access_revoked") else
                               "; WARNING: network revocation pending (controller unreachable, will retry)"))
        return 0
    print(f"logout: {resp.get('message')}")
    return 1


def cmd_admin(client, state, args):
    sid = _need_session(state)
    if not sid:
        return 1
    acmd = args.admin_cmd
    if acmd == "users":
        resp = client.request({"op": "admin_list_users", "session_id": sid})
        if not resp.get("ok"):
            print(f"ADMIN ERROR [{resp.get('error')}]: {resp.get('message')}")
            return 1
        rows = resp["users"]
        print(f"{'REF':16s} {'USER':8s} {'ROLE':8s} {'HOST':5s} {'LEFT':>6s}  SERVICES")
        for r in rows:
            print(f"{r['ref']:16s} {r['username']:8s} {r['role']:8s} {str(r['host']):5s} "
                  f"{r['seconds_remaining']:>5d}s  {','.join(r['services']) or '-'}")
        if not rows:
            print("(no active users)")
        return 0
    if acmd == "revoke":
        if not (args.user or args.ref):
            print("revoke needs --user or --ref")
            return 1
        resp = client.request({"op": "admin_revoke", "session_id": sid, "username": args.user, "session_ref": args.ref})
        if not resp.get("ok"):
            print(f"ADMIN ERROR [{resp.get('error')}]: {resp.get('message')}")
            return 1
        print(f"revoked sessions: {resp['revoked'] or 'none matched'}")
        return 0
    if acmd == "block":
        resp = client.request({"op": "admin_block_host", "session_id": sid, "host": args.host, "reason": args.reason})
        if not resp.get("ok"):
            print(f"ADMIN ERROR [{resp.get('error')}]: {resp.get('message')}")
            return 1
        print(f"BLOCKED host {resp['host']}: {resp['reason']}")
        return 0
    if acmd == "unblock":
        resp = client.request({"op": "admin_unblock_host", "session_id": sid, "host": args.host})
        if not resp.get("ok"):
            print(f"ADMIN ERROR [{resp.get('error')}]: {resp.get('message')}")
            return 1
        print(f"UNBLOCKED host {resp['host']}")
        return 0
    if acmd == "blocked":
        resp = client.request({"op": "admin_list_blocked", "session_id": sid})
        if not resp.get("ok"):
            print(f"ADMIN ERROR [{resp.get('error')}]: {resp.get('message')}")
            return 1
        for b in resp["blocked_hosts"]:
            print(f"{b['host']:6s} by={b['blocked_by']} reason={b['reason']}")
        if not resp["blocked_hosts"]:
            print("(no blocked hosts)")
        return 0
    if acmd == "logs":
        resp = client.request({"op": "admin_logs", "session_id": sid, "limit": args.limit, "level": args.level})
        if not resp.get("ok"):
            print(f"ADMIN ERROR [{resp.get('error')}]: {resp.get('message')}")
            return 1
        for e in resp["events"]:
            print(f"{e.get('time','')} [{e.get('level','info')}] {e.get('component')}.{e.get('event')}")
        return 0
    return 1


COMMANDS = {"login": cmd_login, "access": cmd_access, "status": cmd_status, "logout": cmd_logout, "admin": cmd_admin}


def _tls_settings(args, cfg):
    tls_cfg = cfg["auth"].get("tls") or {}
    if getattr(args, "no_tls", False):
        return False, None
    enabled = bool(tls_cfg.get("enabled", False))
    ca = getattr(args, "ca_cert", None) or tls_cfg.get("ca_cert")
    return enabled, ca


def run(args, cfg):
    host, port = args.server or auth_server_address(cfg)[0], args.port or auth_server_address(cfg)[1]
    tls, ca_cert = _tls_settings(args, cfg)
    try:
        with AuthClient(host, port, args.timeout, tls=tls, ca_cert=ca_cert) as client:
            return COMMANDS[args.command](client, StateFile(cfg, client.local_ip, args.state_dir), args)
    except ConnectionProblem as exc:
        print(f"ERROR: {exc}")
        return 2


def shell(args, cfg):
    print("cn-auth shell. commands: login <user> | access [service] | status | logout | quit")
    while True:
        try:
            parts = input("cn-auth> ").split()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not parts:
            continue
        if parts[0] in ("quit", "exit"):
            return 0
        if parts[0] not in ("login", "access", "status", "logout"):
            print("unknown command")
            continue
        ns = argparse.Namespace(**vars(args))
        ns.command, ns.user, ns.password = parts[0], (parts[1] if parts[0] == "login" and len(parts) > 1 else None), None
        ns.service = parts[1] if parts[0] == "access" and len(parts) > 1 else "protected-echo"
        run(ns, cfg)


def main():
    parser = argparse.ArgumentParser(description="Authentication client", formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__)
    parser.add_argument("--config")
    parser.add_argument("--server", help="auth server IP (default: from config)")
    parser.add_argument("--port", type=int)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--state-dir", help="where the session file is stored (default: run/)")
    parser.add_argument("--no-tls", action="store_true", help="disable TLS even if enabled in config")
    parser.add_argument("--ca-cert", help="CA certificate path for TLS verification")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("login")
    p.add_argument("--user")
    p.add_argument("--password", help="demo convenience; omit to be prompted (command lines are visible in `ps`)")
    p = sub.add_parser("access")
    p.add_argument("--service", default="protected-echo")
    sub.add_parser("status")
    sub.add_parser("logout")
    sub.add_parser("shell")

    adm = sub.add_parser("admin", help="admin role operations (must be logged in as admin)")
    admsub = adm.add_subparsers(dest="admin_cmd", required=True)
    admsub.add_parser("users")
    rv = admsub.add_parser("revoke")
    rv.add_argument("--user")
    rv.add_argument("--ref")
    bk = admsub.add_parser("block")
    bk.add_argument("--host", required=True)
    bk.add_argument("--reason", default="blocked by administrator")
    ub = admsub.add_parser("unblock")
    ub.add_argument("--host", required=True)
    admsub.add_parser("blocked")
    lg = admsub.add_parser("logs")
    lg.add_argument("--limit", type=int, default=30)
    lg.add_argument("--level")

    args = parser.parse_args()
    cfg = load_config(args.config)
    return shell(args, cfg) if args.command == "shell" else run(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
