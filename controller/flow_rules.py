"""Pure rule generation: what OpenFlow rules should exist? (no os-ken imports)

Keeping this separate from the controller makes the policy testable without a
switch and keeps the rule *design* readable in one place.

Priority ladder (higher number wins; the switch evaluates the highest match first):

    300  block       admin host block: drop ALL IPv4 traffic from/to a blocked host
    200  grant       allow ONE client host -> ONE service (and the reply path)
    100  default-deny drop every IPv4 packet to/from a protected service host, drop IPv6
     10  l2-forward  plain Ethernet forwarding by destination MAC (+ broadcast flood)
      0  table-miss  anything else is sent to the controller for logging (never forwarded)

Because block rules (300) beat grants (200), grants (200) beat default-deny (100),
and default-deny beats L2 forwarding (10), no forwarding rule can ever bypass policy.
"""
from collections import deque
from dataclasses import dataclass, field

from common.config import client_hosts, lab_switches

PRIO_TABLE_MISS, PRIO_L2, PRIO_DENY, PRIO_GRANT, PRIO_BLOCK = 0, 10, 100, 200, 300
ETH_IPV4, ETH_ARP, ETH_IPV6 = 0x0800, 0x0806, 0x86DD
BROADCAST = "ff:ff:ff:ff:ff:ff"
MAX_HARD_TIMEOUT = 65535  # OpenFlow hard_timeout is a 16-bit field


@dataclass
class RuleSpec:
    kind: str                     # table-miss | l2-flood | l2-forward | default-deny | grant | block
    priority: int
    match: dict
    actions: list = field(default_factory=list)   # [("output", port | "FLOOD" | "CONTROLLER")]; [] = drop
    hard_timeout: int = 0
    cookie: int = 0
    notify_on_removal: bool = False
    description: str = ""


def match_text(match):
    return " ".join(f"{k}={v}" for k, v in match.items()) or "any"


def _service_hosts(cfg):
    return sorted({svc["host"] for svc in cfg["services"].values()})


def _default_switch(cfg):
    return lab_switches(cfg)[0]["name"]


def _host_switch(cfg, host_name):
    return cfg["lab"]["hosts"][host_name].get("switch", _default_switch(cfg))


def _adjacency(cfg):
    """Return {sw: {neighbor_sw: local_port}} from ``lab.links``."""
    adj = {sw["name"]: {} for sw in lab_switches(cfg)}
    for link in cfg["lab"].get("links", []):
        s1, p1, s2, p2 = link["s1"], link["p1"], link["s2"], link["p2"]
        adj.setdefault(s1, {})[s2] = p1
        adj.setdefault(s2, {})[s1] = p2
    return adj


def switch_path(cfg, src_sw, dst_sw):
    """Shortest switch path ``[src_sw, ..., dst_sw]`` via BFS."""
    if src_sw == dst_sw:
        return [src_sw]
    adj = _adjacency(cfg)
    queue = deque([[src_sw]])
    seen = {src_sw}
    while queue:
        path = queue.popleft()
        cur = path[-1]
        for nxt in sorted(adj.get(cur, {})):
            if nxt == dst_sw:
                return path + [nxt]
            if nxt not in seen:
                seen.add(nxt)
                queue.append(path + [nxt])
    raise ValueError(f"no switch path between {src_sw!r} and {dst_sw!r}")


def _port_toward(cfg, from_sw, target_sw):
    path = switch_path(cfg, from_sw, target_sw)
    if len(path) < 2:
        raise ValueError(f"{from_sw!r} == {target_sw!r}")
    return _adjacency(cfg)[from_sw][path[1]]


def base_rules_for_switch(cfg, switch_name):
    """Rules installed on ``switch_name`` when it connects (default-deny posture)."""
    hosts = cfg["lab"]["hosts"]
    rules = [
        RuleSpec("table-miss", PRIO_TABLE_MISS, {}, [("output", "CONTROLLER")],
                 description="unmatched traffic is reported to the controller, never forwarded"),
        RuleSpec("l2-flood", PRIO_L2, {"eth_dst": BROADCAST}, [("output", "FLOOD")],
                 description="broadcast (ARP requests) is flooded"),
    ]
    for name, h in sorted(hosts.items()):
        h_sw = h.get("switch", _default_switch(cfg))
        if h_sw == switch_name:
            out_port = h["port"]
            desc = f"frames for {name} ({h['mac']}) leave via port {out_port}"
        else:
            out_port = _port_toward(cfg, switch_name, h_sw)
            desc = f"frames for {name} ({h['mac']}) forward toward {h_sw} via trunk port {out_port}"
        rules.append(RuleSpec("l2-forward", PRIO_L2, {"eth_dst": h["mac"]}, [("output", out_port)],
                              description=desc))
    for name in _service_hosts(cfg):
        ip = hosts[name]["ip"]
        rules.append(RuleSpec("default-deny", PRIO_DENY, {"eth_type": ETH_IPV4, "ipv4_dst": ip}, [],
                              description=f"DROP all IPv4 traffic to protected host {name} ({ip})"))
        rules.append(RuleSpec("default-deny", PRIO_DENY, {"eth_type": ETH_IPV4, "ipv4_src": ip}, [],
                              description=f"DROP all IPv4 traffic from protected host {name} ({ip})"))
    rules.append(RuleSpec("default-deny", PRIO_DENY, {"eth_type": ETH_IPV6}, [],
                          description="DROP IPv6 (not used in the lab; closes a bypass path)"))
    return rules


def base_rules(cfg):
    """Backward-compatible wrapper returning base rules for the primary switch."""
    return base_rules_for_switch(cfg, _default_switch(cfg))


def grant_rules_for_switch(cfg, switch_name, host, service, hard_timeout, cookie):
    """The two rules on ``switch_name`` that let ``host`` talk to ``service``.

    Returns [] if ``switch_name`` is not on the path between ``host`` and ``service``.
    Both rules match in_port, MACs, IPs, protocol and TCP port so a host cannot
    spoof another host's address from a different port.
    """
    hosts = cfg["lab"]["hosts"]
    svc = cfg["services"][service]
    c, s = hosts[host], hosts[svc["host"]]
    c_sw, s_sw = _host_switch(cfg, host), _host_switch(cfg, svc["host"])
    path = switch_path(cfg, c_sw, s_sw)
    if switch_name not in path:
        return []

    in_port_fwd = c["port"] if switch_name == c_sw else _port_toward(cfg, switch_name, c_sw)
    out_port_fwd = s["port"] if switch_name == s_sw else _port_toward(cfg, switch_name, s_sw)

    timeout = max(1, min(int(hard_timeout), MAX_HARD_TIMEOUT))
    common = dict(priority=PRIO_GRANT, hard_timeout=timeout, cookie=cookie, notify_on_removal=True, kind="grant")
    forward = RuleSpec(
        match={"in_port": in_port_fwd, "eth_src": c["mac"], "eth_dst": s["mac"], "eth_type": ETH_IPV4,
               "ipv4_src": c["ip"], "ipv4_dst": s["ip"], "ip_proto": 6, "tcp_dst": svc["port"]},
        actions=[("output", out_port_fwd)],
        description=f"[{switch_name}] ALLOW {host} -> {svc['host']}:{svc['port']} ({service})", **common)
    reverse = RuleSpec(
        match={"in_port": out_port_fwd, "eth_src": s["mac"], "eth_dst": c["mac"], "eth_type": ETH_IPV4,
               "ipv4_src": s["ip"], "ipv4_dst": c["ip"], "ip_proto": 6, "tcp_src": svc["port"]},
        actions=[("output", in_port_fwd)],
        description=f"[{switch_name}] ALLOW replies {svc['host']}:{svc['port']} -> {host} ({service})", **common)
    return [forward, reverse]


def grant_rules(cfg, host, service, hard_timeout, cookie):
    """Backward-compatible wrapper returning grant rules for the client host's switch."""
    return grant_rules_for_switch(cfg, _host_switch(cfg, host), host, service, hard_timeout, cookie)


def grant_switches_for(cfg, host, service):
    """Ordered list of switch names on the path from ``host`` to ``service``."""
    svc = cfg["services"][service]
    return switch_path(cfg, _host_switch(cfg, host), _host_switch(cfg, svc["host"]))


def block_host_rules(cfg, host, cookie):
    """High-priority drop rules for a blocked host (installed on every switch)."""
    h = cfg["lab"]["hosts"][host]
    common = dict(priority=PRIO_BLOCK, hard_timeout=0, cookie=cookie, notify_on_removal=False, kind="block")
    return [
        RuleSpec(match={"eth_type": ETH_IPV4, "ipv4_src": h["ip"]}, actions=[],
                 description=f"BLOCK all IPv4 from {host} ({h['ip']})", **common),
        RuleSpec(match={"eth_type": ETH_IPV4, "ipv4_dst": h["ip"]}, actions=[],
                 description=f"BLOCK all IPv4 to {host} ({h['ip']})", **common),
    ]


def grantable_hosts(cfg):
    return sorted(client_hosts(cfg))
