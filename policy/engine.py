"""Authorization decisions (pure logic, no sockets, no OpenFlow).

Authentication answers "who are you?" (password check, done by the auth server).
Authorization answers "what may you do?" -- implemented here.

A request is allowed only when ALL of these hold:
  1. the service exists,
  2. the request really comes from the host the session was created on
     (session <-> source IP binding),
  3. that source IP belongs to a known lab *client* host,
  4. the user's role is allowed to use that service.
Anything else is denied (default deny).
"""
from common.config import host_by_ip
from policy.models import Decision


class PolicyEngine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.roles = cfg["policy"]["roles"]
        self.services = cfg["services"]

    def allowed_services(self, role):
        return list(self.roles.get(role, []))

    def decide(self, *, username, role, session_ip, request_ip, service):
        svc = self.services.get(service)
        if svc is None:
            return Decision(False, "unknown_service", f"service {service!r} does not exist", service=service)
        if request_ip != session_ip:
            return Decision(False, "session_ip_mismatch",
                            "session was created on a different host than the one making this request",
                            service=service)
        host, info = host_by_ip(self.cfg, request_ip)
        if host is None or info["role"] != "client":
            return Decision(False, "unknown_host",
                            f"source address {request_ip} is not a registered client host", service=service)
        if service not in self.roles.get(role, []):
            return Decision(False, "role_not_permitted",
                            f"role {role!r} is not permitted to use {service!r}", host=host, service=service)
        return Decision(True, "allowed", f"role {role!r} may use {service!r} from {host} ({request_ip})",
                        host=host, service=service, service_port=int(svc["port"]))
