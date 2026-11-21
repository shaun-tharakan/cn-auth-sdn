"""Local admin HTTP API of the auth server (stdlib http.server).

    GET  /health    liveness + counters                      (read-only)
    GET  /sessions  active and recently ended sessions        (read-only, secret-free)
    GET  /users     currently active users/sessions           (read-only, secret-free)
    GET  /blocked   currently blocked hosts                   (read-only)
    GET  /logs      recent event log entries                  (read-only)
    POST /revoke    {"username": ..} or {"session_ref": ..}   (needs X-Admin-Token)
    POST /block     {"host": .., "reason": ..}                (needs X-Admin-Token)
    POST /unblock   {"host": ..}                              (needs X-Admin-Token)

Bound to 127.0.0.1 by default: the dashboard (read) and ``auth.admin`` (admin CLI)
run on the same machine.  This is NOT reachable from Mininet hosts' lab network
unless the bind address is changed deliberately.
"""
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from policy.controller_client import ControllerRejected, ControllerUnavailable


class AdminAPI:
    def __init__(self, server, host, port, token):
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, status, obj):
                body = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                if path == "/health":
                    self._reply(200, api.server.health())
                elif path == "/sessions":
                    self._reply(200, {"sessions": api.server.sessions.snapshot(), "generated_at": api.server.clock()})
                elif path == "/users":
                    self._reply(200, {"users": api.server.admin_list_users(), "generated_at": api.server.clock()})
                elif path == "/blocked":
                    self._reply(200, {"blocked_hosts": api.server.admin_list_blocked()})
                elif path == "/logs":
                    qs = parse_qs(parsed.query)
                    try:
                        limit = int(qs.get("limit", ["50"])[0])
                    except ValueError:
                        limit = 50
                    level = qs.get("level", [None])[0]
                    self._reply(200, {"events": api.server.admin_logs(limit=limit, level=level)})
                else:
                    self._reply(404, {"ok": False, "error": "not_found"})

            def do_POST(self):
                if self.path not in ("/revoke", "/block", "/unblock"):
                    return self._reply(404, {"ok": False, "error": "not_found"})
                if not hmac.compare_digest(self.headers.get("X-Admin-Token", ""), api.token):
                    return self._reply(403, {"ok": False, "error": "forbidden", "message": "bad admin token"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    body = json.loads(self.rfile.read(min(length, 4096)).decode() or "{}")
                except (ValueError, UnicodeDecodeError) as exc:
                    return self._reply(400, {"ok": False, "error": "bad_request", "message": str(exc)})

                if self.path == "/revoke":
                    username, ref = body.get("username"), body.get("session_ref")
                    if not (isinstance(username, str) or isinstance(ref, str)):
                        return self._reply(400, {"ok": False, "error": "bad_request",
                                                 "message": "username or session_ref required"})
                    revoked = api.server.admin_revoke(username=username, ref=ref)
                    return self._reply(200, {"ok": True, "revoked": revoked})

                host = body.get("host")
                if not isinstance(host, str):
                    return self._reply(400, {"ok": False, "error": "bad_request", "message": "host required"})
                try:
                    if self.path == "/block":
                        reason = str(body.get("reason") or "blocked by administrator")[:200]
                        entry = api.server.admin_block_host(host, reason, blocked_by="admin-api")
                        return self._reply(200, {"ok": True, "blocked": True, **entry})
                    was_blocked = api.server.admin_unblock_host(host, unblocked_by="admin-api")
                    return self._reply(200, {"ok": True, "host": host, "blocked": False, "was_blocked": was_blocked})
                except ValueError as exc:
                    return self._reply(400, {"ok": False, "error": "unknown_host", "message": str(exc)})
                except ControllerUnavailable as exc:
                    return self._reply(503, {"ok": False, "error": "controller_unavailable", "message": str(exc)})
                except ControllerRejected as exc:
                    return self._reply(exc.status, {"ok": False, "error": exc.code, "message": exc.message})

        self.server, self.token = server, token
        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True, name="auth-admin")

    def start(self):
        self._thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
