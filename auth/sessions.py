"""Thread-safe session manager.

A session ties together: username, role, the client IP it was created from, and an
absolute expiry time.  Session ids are 256-bit random tokens from ``secrets``.
Only a short SHA-256 fingerprint (``ref``) is ever shown on the dashboard, in logs,
or sent to the SDN controller -- the raw session id stays between the auth server
and the client.

Status values: active -> expired | logged_out | revoked  (terminal states).
Whenever a session leaves ``active`` the ``on_end`` callback fires (outside the
lock); the auth server uses it to remove the matching network access.
"""
import hashlib
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Session:
    session_id: str
    username: str
    role: str
    client_ip: str
    host: Optional[str]
    created_at: float
    expires_at: float
    status: str = "active"
    ended_at: Optional[float] = None
    end_reason: Optional[str] = None
    services: dict = field(default_factory=dict)   # service -> grant info
    needs_revocation: bool = False                  # a grant was requested at some point
    revocation: str = "none"                        # none | done | pending

    @property
    def ref(self):
        return "s-" + hashlib.sha256(self.session_id.encode()).hexdigest()[:12]


class SessionManager:
    def __init__(self, ttl_seconds, clock=time.time, history=50, on_end=None):
        self.ttl = ttl_seconds
        self.clock = clock
        self.on_end = on_end
        self._lock = threading.RLock()
        self._active = {}
        self._ended = deque(maxlen=history)

    # ---- creation / lookup -------------------------------------------------
    def create(self, username, role, client_ip, host):
        now = self.clock()
        session = Session(secrets.token_urlsafe(32), username, role, client_ip, host, now, now + self.ttl)
        with self._lock:
            self._active[session.session_id] = session
        return session

    def get_active(self, session_id):
        """Return ``(session, error)``; error is None, "invalid_session" or "session_expired"."""
        with self._lock:
            session = self._active.get(session_id)
            if session is None:
                return None, "invalid_session"
            if self.clock() >= session.expires_at:
                ended = self._end_locked(session, "expired", "session timeout")
            else:
                return session, None
        self._notify([ended])
        return None, "session_expired"

    # ---- state changes -----------------------------------------------------
    def record_grant(self, session_id, service, info):
        """Remember a grant; False if the session ended in the meantime."""
        with self._lock:
            session = self._active.get(session_id)
            if session is None:
                return False
            session.services[service] = info
            return True

    def mark_grant_attempt(self, session_id):
        with self._lock:
            session = self._active.get(session_id)
            if session:
                session.needs_revocation = True

    def logout(self, session_id):
        return self._end(session_id, "logged_out", "user logout")

    def revoke(self, session_id, reason="revoked by administrator"):
        return self._end(session_id, "revoked", reason)

    def revoke_user(self, username, reason="revoked by administrator"):
        with self._lock:
            ids = [s.session_id for s in self._active.values() if s.username == username]
        return [s for s in (self.revoke(i, reason) for i in ids) if s]

    def revoke_ref(self, ref, reason="revoked by administrator"):
        with self._lock:
            ids = [s.session_id for s in self._active.values() if s.ref == ref]
        return [s for s in (self.revoke(i, reason) for i in ids) if s]

    def end_all(self, reason):
        with self._lock:
            ids = list(self._active)
        return [s for s in (self._end(i, "revoked", reason) for i in ids) if s]

    def expire_due(self):
        with self._lock:
            now = self.clock()
            ended = [self._end_locked(s, "expired", "session timeout")
                     for s in list(self._active.values()) if now >= s.expires_at]
        self._notify(ended)
        return ended

    # ---- views -------------------------------------------------------------
    def snapshot(self):
        """Public, secret-free view of active + recently ended sessions."""
        with self._lock:
            now = self.clock()
            rows = [self._public(s, now) for s in self._active.values()]
            rows += [self._public(s, now) for s in self._ended]
        rows.sort(key=lambda r: r["created_at"], reverse=True)
        return rows

    def active_count(self):
        with self._lock:
            return len(self._active)

    # ---- internals ---------------------------------------------------------
    def _end(self, session_id, status, reason):
        with self._lock:
            session = self._active.get(session_id)
            if session is None:
                return None
            ended = self._end_locked(session, status, reason)
        self._notify([ended])
        return ended

    def _end_locked(self, session, status, reason):
        session.status, session.end_reason, session.ended_at = status, reason, self.clock()
        self._active.pop(session.session_id, None)
        self._ended.append(session)
        return session

    def _notify(self, sessions):
        if self.on_end:
            for s in sessions:
                self.on_end(s)

    @staticmethod
    def _public(s, now):
        return {
            "ref": s.ref, "username": s.username, "role": s.role, "host": s.host, "client_ip": s.client_ip,
            "status": s.status, "created_at": s.created_at, "expires_at": s.expires_at,
            "ended_at": s.ended_at, "end_reason": s.end_reason,
            "services": sorted(s.services), "revocation": s.revocation,
            "seconds_remaining": max(0, round(s.expires_at - now)) if s.status == "active" else 0,
        }
