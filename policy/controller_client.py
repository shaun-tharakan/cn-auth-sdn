"""Client for the controller's trusted policy API (used only by the auth server).

The auth server is the *only* component allowed to change network policy.  It
authenticates to the controller with a shared secret in the ``X-Policy-Token``
header.  The controller never trusts a username supplied by a client host.

Failure handling is fail-closed: if the controller cannot be reached the caller
receives :class:`ControllerUnavailable` and must NOT report access as granted.
"""
import json
import socket
import urllib.error
import urllib.request


class ControllerUnavailable(Exception):
    """Controller (or its switch) cannot be reached right now."""


class ControllerRejected(Exception):
    """Controller answered but refused the request (HTTP 4xx)."""

    def __init__(self, status, code, message):
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


class ControllerClient:
    def __init__(self, base_url, token, timeout=3.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json", "X-Policy-Token": self.token})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode())
            except (ValueError, OSError):
                payload = {}
            code, msg = payload.get("error", "http_error"), payload.get("message", str(exc))
            if exc.code >= 500:
                raise ControllerUnavailable(f"controller error {exc.code} {code}: {msg}")
            raise ControllerRejected(exc.code, code, msg)
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as exc:
            raise ControllerUnavailable(f"cannot reach controller at {self.base_url}: {exc}")
        except ValueError as exc:
            raise ControllerUnavailable(f"controller sent an invalid response: {exc}")

    def health(self):
        return self._request("GET", "/policy/health")

    def grant(self, session_ref, username, host, service, ttl_seconds):
        return self._request("POST", "/policy/grant", {
            "session_ref": session_ref, "username": username, "host": host,
            "service": service, "ttl_seconds": int(ttl_seconds)})

    def revoke(self, session_ref, reason):
        return self._request("POST", "/policy/revoke", {"session_ref": session_ref, "reason": reason})

    def revoke_all(self, reason):
        return self._request("POST", "/policy/revoke", {"all": True, "reason": reason})

    def block_host(self, host, reason="blocked by administrator"):
        return self._request("POST", "/policy/block", {"host": host, "reason": reason})

    def unblock_host(self, host, reason="unblocked by administrator"):
        return self._request("POST", "/policy/unblock", {"host": host, "reason": reason})
