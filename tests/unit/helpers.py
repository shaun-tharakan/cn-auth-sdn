"""Shared helpers for unit tests."""
import json
import os

from common.config import REPO_ROOT, load_config


def make_cfg(tmpdir, **auth_overrides):
    """Config clone: host h1 is 127.0.0.1 so loopback test connections count as lab host h1."""
    cfg = json.loads((REPO_ROOT / "config" / "config.json").read_text())
    cfg["lab"]["hosts"]["h1"]["ip"] = "127.0.0.1"
    cfg["lab"]["subnet"] = "0.0.0.0/0"          # loopback is not inside the lab subnet
    auth_overrides.setdefault("tls", {"enabled": False})
    cfg["auth"].update(port=0, bind_host="127.0.0.1", admin_port=0, session_ttl_seconds=60,
                       reaper_interval_seconds=0.1, **auth_overrides)
    cfg["paths"] = {"events_log": os.path.join(tmpdir, "events.jsonl"), "users_db": os.path.join(tmpdir, "users.json"),
                    "run_dir": os.path.join(tmpdir, "run"), "log_dir": tmpdir}
    path = os.path.join(tmpdir, "config.json")
    with open(path, "w") as fh:
        json.dump(cfg, fh)
    return load_config(path)


class FakeController:
    """Records calls; can be switched 'down' to simulate an unreachable controller."""

    def __init__(self):
        self.up, self.calls, self.blocked = True, [], {}

    def _check(self):
        from policy.controller_client import ControllerUnavailable
        if not self.up:
            raise ControllerUnavailable("fake controller is down")

    def grant(self, session_ref, username, host, service, ttl_seconds):
        self._check()
        self.calls.append(("grant", session_ref, host, service, ttl_seconds))
        return {"ok": True, "flows": ["fake"]}

    def revoke(self, session_ref, reason):
        self._check()
        self.calls.append(("revoke", session_ref, reason))
        return {"ok": True}

    def revoke_all(self, reason):
        self._check()
        self.calls.append(("revoke_all", reason))
        return {"ok": True}

    def block_host(self, host, reason="blocked by administrator"):
        self._check()
        self.blocked[host] = reason
        self.calls.append(("block_host", host, reason))
        return {"ok": True, "host": host}

    def unblock_host(self, host, reason="unblocked by administrator"):
        self._check()
        self.blocked.pop(host, None)
        self.calls.append(("unblock_host", host, reason))
        return {"ok": True, "host": host}
