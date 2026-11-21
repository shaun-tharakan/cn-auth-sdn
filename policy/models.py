"""Small data models for the authorization layer."""
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Decision:
    """Result of an authorization check.

    ``code`` is machine readable ("allowed", "role_not_permitted", ...),
    ``reason`` is the human readable explanation shown to users and the dashboard.
    """
    allowed: bool
    code: str
    reason: str
    host: Optional[str] = None
    service: Optional[str] = None
    service_port: Optional[int] = None

    def to_dict(self):
        return {"allowed": self.allowed, "code": self.code, "reason": self.reason,
                "host": self.host, "service": self.service, "service_port": self.service_port}
