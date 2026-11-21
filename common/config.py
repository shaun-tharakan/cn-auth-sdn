"""Central configuration loader shared by every component.

All ports, IP addresses, MAC addresses, service definitions, timeouts and file
paths live in ``config/config.json``.  Every component calls
:func:`load_config` so the whole lab stays consistent.

Environment overrides (handy for tests and for keeping secrets out of git):
    CNAUTH_CONFIG        path to an alternative config file
    CNAUTH_API_TOKEN     shared secret the auth server uses to talk to the controller
    CNAUTH_ADMIN_TOKEN   secret for the auth server's admin API
    CNAUTH_OVS_DATAPATH  "kernel" (default) or "user" (VMs without the OVS kernel module)
"""
import argparse
import ipaddress
import json
import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = REPO_ROOT / "config" / "config.json"
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class ConfigError(Exception):
    """Raised when the configuration is missing or inconsistent."""


def lab_switches(cfg):
    """Return list of switch dicts (supports both ``lab.switches`` and legacy ``lab.switch``)."""
    lab = cfg["lab"]
    if "switches" in lab and lab["switches"]:
        return list(lab["switches"])
    return [lab["switch"]]


def switch_by_name(cfg, name):
    for sw in lab_switches(cfg):
        if sw["name"] == name:
            return sw
    return None


def load_config(path=None):
    path = Path(path or os.environ.get("CNAUTH_CONFIG") or DEFAULT_CONFIG)
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}")
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file {path} is not valid JSON: {exc}")
    if os.environ.get("CNAUTH_API_TOKEN"):
        cfg["controller"]["api_token"] = os.environ["CNAUTH_API_TOKEN"]
    if os.environ.get("CNAUTH_ADMIN_TOKEN"):
        cfg["auth"]["admin_token"] = os.environ["CNAUTH_ADMIN_TOKEN"]
    if os.environ.get("CNAUTH_OVS_DATAPATH"):
        dp = os.environ["CNAUTH_OVS_DATAPATH"]
        cfg["lab"]["switch"]["datapath"] = dp
        for sw in cfg["lab"].get("switches", []):
            sw["datapath"] = dp
    cfg["_config_path"] = str(path)
    for key, value in list(cfg["paths"].items()):
        p = Path(value)
        cfg["paths"][key] = str(p if p.is_absolute() else REPO_ROOT / p)
    tls = cfg["auth"].get("tls")
    if isinstance(tls, dict):
        for key in ("cert", "key", "ca_cert"):
            if tls.get(key):
                p = Path(tls[key])
                tls[key] = str(p if p.is_absolute() else REPO_ROOT / p)
    validate_config(cfg)
    return cfg


def validate_config(cfg):
    """Fail early (and clearly) on an inconsistent configuration."""
    try:
        hosts = cfg["lab"]["hosts"]
        subnet = ipaddress.ip_network(cfg["lab"]["subnet"])
        switches = lab_switches(cfg)
        sw_names = {sw["name"] for sw in switches}
        dpids = set()
        for sw in switches:
            if sw["dpid"] in dpids:
                raise ConfigError(f"duplicate switch dpid {sw['dpid']}")
            dpids.add(sw["dpid"])
        default_sw = switches[0]["name"]

        used_ports = {sw["name"]: set() for sw in switches}
        ips, macs = set(), set()
        for name, h in hosts.items():
            if h["role"] not in ("client", "service", "management"):
                raise ConfigError(f"host {name}: unknown role {h['role']!r}")
            if ipaddress.ip_address(h["ip"]) not in subnet:
                raise ConfigError(f"host {name}: ip {h['ip']} outside {subnet}")
            if not MAC_RE.match(h["mac"]):
                raise ConfigError(f"host {name}: mac must be lowercase aa:bb:.. form")
            sw_name = h.get("switch", default_sw)
            if sw_name not in sw_names:
                raise ConfigError(f"host {name}: unknown switch {sw_name!r}")
            if h["port"] in used_ports[sw_name]:
                raise ConfigError(f"duplicate port {h['port']} on switch {sw_name}")
            used_ports[sw_name].add(h["port"])
            for seen, val, what in ((ips, h["ip"], "ip"), (macs, h["mac"], "mac")):
                if val in seen:
                    raise ConfigError(f"duplicate {what} {val} in lab.hosts")
                seen.add(val)

        for link in cfg["lab"].get("links", []):
            s1, p1, s2, p2 = link["s1"], link["p1"], link["s2"], link["p2"]
            if s1 not in sw_names or s2 not in sw_names or s1 == s2:
                raise ConfigError(f"invalid switch link {link}")
            if p1 in used_ports[s1]:
                raise ConfigError(f"duplicate port {p1} on switch {s1} (link)")
            if p2 in used_ports[s2]:
                raise ConfigError(f"duplicate port {p2} on switch {s2} (link)")
            used_ports[s1].add(p1)
            used_ports[s2].add(p2)

        for sname, svc in cfg["services"].items():
            if svc["host"] not in hosts or hosts[svc["host"]]["role"] != "service":
                raise ConfigError(f"service {sname}: host {svc['host']!r} must have role 'service'")
            if not 0 < int(svc["port"]) < 65536:
                raise ConfigError(f"service {sname}: bad port")
        for role, allowed in cfg["policy"]["roles"].items():
            for sname in allowed:
                if sname not in cfg["services"]:
                    raise ConfigError(f"policy role {role}: unknown service {sname!r}")
        cfg["auth"]["port"], cfg["controller"]["api_port"], cfg["controller"]["openflow_port"]
        cfg["auth"]["session_ttl_seconds"]
    except KeyError as exc:
        raise ConfigError(f"missing configuration key: {exc}")


def client_hosts(cfg):
    return {n: h for n, h in cfg["lab"]["hosts"].items() if h["role"] == "client"}


def host_by_ip(cfg, ip):
    """Return (name, info) for a lab host IP, or (None, None)."""
    for name, h in cfg["lab"]["hosts"].items():
        if h["ip"] == ip:
            return name, h
    return None, None


def auth_server_address(cfg):
    """Address clients inside Mininet use to reach the auth server (the root namespace)."""
    return cfg["lab"]["hosts"]["root"]["ip"], cfg["auth"]["port"]


def main():
    parser = argparse.ArgumentParser(description="Print a configuration value (used by shell scripts)")
    parser.add_argument("--config")
    parser.add_argument("--get", required=True, help="dotted key, e.g. controller.api_port")
    args = parser.parse_args()
    value = load_config(args.config)
    for part in args.get.split("."):
        value = value[part]
    print(value)


if __name__ == "__main__":
    main()
