"""Shared event log (JSON Lines).

Every component (auth server, controller, protected service, topology) appends
one JSON object per line to the same file.  The dashboard tails that file to build
its event timeline.  One line = one ``os.write`` on an ``O_APPEND`` descriptor, so
lines written by different processes never interleave.

Secrets are never logged: keys such as ``password`` or ``session_id`` are stripped
before writing (see ``SENSITIVE_KEYS``).
"""
import json
import os
import time
from datetime import datetime, timezone

SENSITIVE_KEYS = {"password", "passwd", "secret", "session_id", "token", "api_token", "admin_token", "password_hash"}


class EventLog:
    def __init__(self, path, component):
        self.path = str(path)
        self.component = component

    def emit(self, event, level="info", **fields):
        now = time.time()
        record = {
            "ts": round(now, 3),
            "time": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "component": self.component,
            "event": event,
            "level": level,
        }
        for key, value in fields.items():
            if key.lower() not in SENSITIVE_KEYS:
                record[key] = value
        line = (json.dumps(record, default=str, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o666)
            try:
                os.write(fd, line)
                try:
                    os.fchmod(fd, 0o666)  # processes run as different users (root for Mininet)
                except OSError:
                    pass
            finally:
                os.close(fd)
        except OSError:
            pass  # logging must never crash the component being observed
        return record


def read_recent(path, limit=100, max_bytes=512 * 1024):
    """Return up to ``limit`` most recent events (oldest first). Missing file -> []."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            data = fh.read()
    except OSError:
        return []
    events = []
    for raw in data.splitlines()[-limit * 3:]:
        try:
            events.append(json.loads(raw))
        except (ValueError, UnicodeDecodeError):
            continue  # partial first line of the tail window, or corrupt line
    return events[-limit:]
