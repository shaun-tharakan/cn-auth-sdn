"""SDN controller application (OS-Ken, OpenFlow 1.3).

Start with:   osken-manager --ofp-listen-host 127.0.0.1 controller.sdn_controller
(scripts/start.sh does this with the ports from config/config.json).

What it does
  * accepts OpenFlow 1.3 connections from all configured switches (datapaths)
  * on connect: wipes the switch flow table and installs default-deny base rules
    (+ any active admin host-block rules)
  * exposes a small trusted HTTP API (127.0.0.1) used ONLY by the auth server:
        POST /policy/grant   install per-host/per-service allow rules across path switches
        POST /policy/revoke  delete those rules (by session, or everything)
        POST /policy/block   install priority-300 drop rules for a host across all switches
        POST /policy/unblock remove host block rules across all switches
        GET  /policy/health | /policy/state | /policy/flows   (read-only, for the dashboard)
  * maintains thread/greenlet-safe per-user and per-host access state
  * polls every connected switch for its real flow table
  * logs every policy decision / rule change to the shared event log
"""
import hmac
import itertools
import json
import logging
import os
import re
import sys
import time
from http import HTTPStatus

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import eventlet.wsgi  # noqa: E402
from os_ken.base import app_manager  # noqa: E402
from os_ken.controller import ofp_event  # noqa: E402
from os_ken.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls  # noqa: E402
from os_ken.lib import hub  # noqa: E402
from os_ken.lib.packet import ethernet, packet  # noqa: E402
from os_ken.ofproto import ofproto_v1_3  # noqa: E402

from common.config import client_hosts, lab_switches, load_config  # noqa: E402
from common.events import EventLog  # noqa: E402
from controller import flow_rules, ofp_convert  # noqa: E402

REF_RE = re.compile(r"^[A-Za-z0-9_-]{4,64}$")
SPECIAL_PORT_NAMES = {0xfffffffb: "FLOOD", 0xfffffffd: "CONTROLLER", 0xfffffff8: "IN_PORT", 0xfffffffc: "ALL"}


class PolicyError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class _NullLog:
    def write(self, *_):
        pass

    def flush(self):
        pass


class PolicyController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cfg = load_config()
        self.elog = EventLog(self.cfg["paths"]["events_log"], "controller")
        self.log = logging.getLogger("policy-controller")
        switches = lab_switches(self.cfg)
        self.expected_dpids = {int(sw["dpid"], 16): sw["name"] for sw in switches}
        self.dpid_by_name = {sw["name"]: int(sw["dpid"], 16) for sw in switches}
        self.dpid = int(switches[0]["dpid"], 16)
        self.started_at = time.time()
        self.datapaths = {}                     # dpid -> datapath
        self.connected_at = {}                  # dpid -> timestamp
        self.grants = {}                        # cookie -> dict
        self.by_cookie = {}
        self.blocked_hosts = {}                 # host -> {"host", "cookie", "reason", "blocked_at"}
        self._cookies = itertools.count(1)
        self.host_state = {}                    # "host|service" -> dict
        self.user_state = {}                    # username -> {"username", "grants", "services", "hosts", "updated_at"}
        self.flow_cache_by_dpid = {}            # dpid_hex -> list[flow]
        self.flow_cache = {"flows": [], "updated_at": None}
        self._stats_buf = {}                    # dpid -> list[OFPFlowStats]
        self._last_deny_counts = {}
        self._barriers, self._errors = {}, {}
        self._unknown_seen = {}
        self._known_macs = {h["mac"] for h in self.cfg["lab"]["hosts"].values()}
        self._op_lock = hub.Semaphore(1)        # serializes OpenFlow policy mutations
        self._state_lock = hub.Semaphore(1)     # guards in-memory state dicts for concurrent reads
        for host in client_hosts(self.cfg):
            for service in self.cfg["services"]:
                self._set_state(host, service, "denied", "default-deny: no valid grant")

    def start(self):
        thread = super().start()
        hub.spawn(self._serve_api)
        hub.spawn(self._poll_loop)
        self.elog.emit("controller_started", api_port=self.cfg["controller"]["api_port"], openflow="1.3",
                       expected_switches=sorted(self.dpid_by_name))
        return thread

    # =============================================================== OpenFlow side
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.expected_dpids:
                self.elog.emit("unexpected_switch", level="warn", dpid=f"{dp.id:016x}", note="ignored")
                return
            sw_name = self.expected_dpids[dp.id]
            with self._state_lock:
                self.datapaths[dp.id] = dp
                self.connected_at[dp.id] = time.time()
            self.elog.emit("switch_connected", switch=sw_name, dpid=f"{dp.id:016x}", address=str(dp.address))
            self._reset_switch(dp, sw_name)
        elif ev.state == DEAD_DISPATCHER and self.datapaths.get(dp.id) is dp:
            sw_name = self.expected_dpids.get(dp.id, f"{dp.id:016x}")
            with self._state_lock:
                self.datapaths.pop(dp.id, None)
                self.connected_at.pop(dp.id, None)
                self.flow_cache_by_dpid.pop(f"{dp.id:016x}", None)
                self._stats_buf.pop(dp.id, None)
            self.elog.emit("switch_disconnected", level="warn", switch=sw_name, dpid=f"{dp.id:016x}",
                             note="installed flows stay in the switch until their hard timeout")

    def _reset_switch(self, dp, sw_name):
        """Clean slate for ``dp``: delete every flow, install base rules, and re-apply active blocks."""
        with self._op_lock:
            with self._state_lock:
                affected = [g for g in self.grants.values() if dp.id in g.get("dpids", ())]
                for g in affected:
                    self._drop_grant_locked(g, f"switch {sw_name} (re)connected; flow table wiped")
                blocks = list(self.blocked_hosts.values())
            if affected:
                self.elog.emit("grants_cleared", level="warn", switch=sw_name, count=len(affected),
                                 reason="switch (re)connected; flow table was wiped")
            dp.send_msg(ofp_convert.flow_delete_all(dp))
            rules = flow_rules.base_rules_for_switch(self.cfg, sw_name)
            for rule in rules:
                dp.send_msg(ofp_convert.flow_add(dp, rule))
            for b in blocks:
                for br in flow_rules.block_host_rules(self.cfg, b["host"], b["cookie"]):
                    dp.send_msg(ofp_convert.flow_add(dp, br))
            counts = {}
            for r in rules:
                counts[r.kind] = counts.get(r.kind, 0) + 1
            self.elog.emit("base_rules_installed", switch=sw_name, count=len(rules), kinds=counts,
                             summary=f"default-deny on {sw_name}; L2 forwarding below it")

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def _on_error(self, ev):
        msg = ev.msg
        self._errors[msg.xid] = (msg.type, msg.code)
        if len(self._errors) > 256:
            self._errors.pop(next(iter(self._errors)))
        self.elog.emit("openflow_error", level="error", dpid=f"{msg.datapath.id:016x}",
                       xid=msg.xid, type=msg.type, code=msg.code)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _on_barrier_reply(self, ev):
        evt = self._barriers.pop(ev.msg.xid, None)
        if evt:
            evt.set()

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _on_flow_removed(self, ev):
        msg, ofp = ev.msg, ev.msg.datapath.ofproto
        with self._state_lock:
            grant = self.by_cookie.get(msg.cookie)
        if grant and msg.reason == ofp.OFPRR_HARD_TIMEOUT:
            self.elog.emit("flow_expired", host=grant["host"], service=grant["service"],
                             session=grant["session_ref"], note="hard timeout reached inside the switch")
            with self._state_lock:
                self._drop_grant_locked(grant, "grant expired (switch hard timeout)")
                dps = [self.datapaths[d] for d in grant.get("dpids", ()) if d in self.datapaths]
            for dp in dps:
                dp.send_msg(ofp_convert.flow_delete_cookie(dp, msg.cookie))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _on_packet_in(self, ev):
        """Table-miss: the switch had no rule.  We only observe; nothing is forwarded."""
        msg = ev.msg
        eth = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        if eth is None or eth.src in self._known_macs:
            return
        now = time.time()
        if now - self._unknown_seen.get(eth.src, 0) > 30:
            self._unknown_seen[eth.src] = now
            sw_name = self.expected_dpids.get(msg.datapath.id, f"{msg.datapath.id:016x}")
            self.elog.emit("unknown_host_seen", level="warn", switch=sw_name, mac=eth.src,
                           in_port=msg.match["in_port"], note="not in lab inventory; dropped")

    # ---- flow table polling (real rules for the dashboard)
    def _poll_loop(self):
        interval = self.cfg["controller"].get("flow_poll_seconds", 2.0)
        while True:
            hub.sleep(interval)
            with self._state_lock:
                dps = list(self.datapaths.values())
            for dp in dps:
                parser, ofp = dp.ofproto_parser, dp.ofproto
                dp.send_msg(parser.OFPFlowStatsRequest(dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY, 0, 0,
                                                       parser.OFPMatch()))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _on_flow_stats(self, ev):
        msg = ev.msg
        dp = msg.datapath
        buf = self._stats_buf.setdefault(dp.id, [])
        buf.extend(msg.body)
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return
        raw = self._stats_buf.pop(dp.id, [])
        sw_name = self.expected_dpids.get(dp.id, f"{dp.id:016x}")
        dpid_hex = f"{dp.id:016x}"
        flows = [self._describe_flow(st, dp, sw_name, dpid_hex) for st in raw]
        flows.sort(key=lambda f: (-f["priority"], f["match_text"]))
        with self._state_lock:
            self.flow_cache_by_dpid[dpid_hex] = flows
            merged = [f for fl in self.flow_cache_by_dpid.values() for f in fl]
            merged.sort(key=lambda f: (f["switch"], -f["priority"], f["match_text"]))
            self.flow_cache = {"flows": merged, "updated_at": time.time(), "dpid": dpid_hex}
        self._observe_blocked(flows, sw_name)

    def _describe_flow(self, st, dp, sw_name, dpid_hex):
        parser = dp.ofproto_parser
        match = {item["OXMTlv"]["field"]: item["OXMTlv"]["value"]
                 for item in st.match.to_jsondict()["OFPMatch"]["oxm_fields"]}
        actions = []
        for inst in st.instructions:
            for act in getattr(inst, "actions", []):
                if isinstance(act, parser.OFPActionOutput):
                    actions.append("output:" + str(SPECIAL_PORT_NAMES.get(act.port, act.port)))
        with self._state_lock:
            grant = self.by_cookie.get(st.cookie)
            is_block = any(b["cookie"] == st.cookie for b in self.blocked_hosts.values())
        kind = ("grant" if grant else
                "block" if is_block or st.priority == flow_rules.PRIO_BLOCK else
                {0: "table-miss", flow_rules.PRIO_L2: "l2-forward",
                 flow_rules.PRIO_DENY: "default-deny"}.get(st.priority, "other"))
        return {"switch": sw_name, "dpid": dpid_hex, "priority": st.priority, "kind": kind,
                "match": match, "match_text": flow_rules.match_text(match),
                "actions": actions or ["drop"], "packets": st.packet_count, "bytes": st.byte_count,
                "age_seconds": st.duration_sec, "hard_timeout": st.hard_timeout, "cookie": st.cookie,
                "session": grant["session_ref"] if grant else None}

    def _observe_blocked(self, flows, sw_name):
        """A growing packet counter on a default-deny or block rule == blocked access attempts."""
        for f in flows:
            if f["kind"] not in ("default-deny", "block") or f["match"].get("eth_type") != flow_rules.ETH_IPV4:
                continue
            key = (sw_name, f["match_text"])
            delta = f["packets"] - self._last_deny_counts.get(key, f["packets"] if key not in self._last_deny_counts else 0)
            first = key not in self._last_deny_counts
            self._last_deny_counts[key] = f["packets"]
            if (first and f["packets"] > 0) or (not first and delta > 0):
                self.elog.emit("access_blocked", level="warn", switch=sw_name,
                               packets=f["packets"] if first else delta, rule=f["match_text"],
                               note="drop rule dropped packets (access attempt without a grant)")

    # =============================================================== policy operations
    def _send(self, dp, msg):
        dp.send_msg(msg)
        return msg.xid

    def _confirm(self, dp, xids, timeout=3.0):
        """Barrier: wait until the switch has processed every message sent so far."""
        req = dp.ofproto_parser.OFPBarrierRequest(dp)
        dp.set_xid(req)
        evt = hub.Event()
        self._barriers[req.xid] = evt
        dp.send_msg(req)
        if not evt.wait(timeout=timeout):
            self._barriers.pop(req.xid, None)
            raise PolicyError(503, "switch_timeout", "switch did not confirm the flow change in time")
        failed = [self._errors.pop(x) for x in xids if x in self._errors]
        if failed:
            raise PolicyError(500, "flow_install_failed", f"switch rejected flow change: {failed}")

    def _dps_for_switches(self, sw_names):
        with self._state_lock:
            missing = [s for s in sw_names if self.dpid_by_name[s] not in self.datapaths]
            if missing:
                raise PolicyError(503, "switch_unavailable",
                                  f"OpenFlow switch(es) not connected: {', '.join(missing)}")
            return [(s, self.datapaths[self.dpid_by_name[s]]) for s in sw_names]

    def _all_connected_dps(self):
        with self._state_lock:
            if not self.datapaths:
                raise PolicyError(503, "switch_unavailable", "no OpenFlow switches are connected")
            return list(self.datapaths.items())

    def _set_state(self, host, service, state, reason):
        self.host_state[f"{host}|{service}"] = {"host": host, "service": service, "state": state,
                                                "reason": reason, "changed_at": time.time()}

    def _refresh_user_state_locked(self, username):
        if not username:
            return
        user_grants = [g for g in self.grants.values() if g["username"] == username]
        if not user_grants:
            self.user_state.pop(username, None)
            return
        self.user_state[username] = {
            "username": username,
            "active_grants": len(user_grants),
            "hosts": sorted({g["host"] for g in user_grants}),
            "services": sorted({g["service"] for g in user_grants}),
            "sessions": sorted({g["session_ref"] for g in user_grants}),
            "updated_at": time.time(),
        }

    def grant_access(self, session_ref, username, host, service, ttl):
        with self._op_lock:
            with self._state_lock:
                if host in self.blocked_hosts:
                    raise PolicyError(403, "host_blocked", f"host {host} is blocked by administrator")
                replaced = [g for g in self.grants.values() if g["host"] == host and g["service"] == service]
            sw_names = flow_rules.grant_switches_for(self.cfg, host, service)
            sw_dps = self._dps_for_switches(sw_names)
            if replaced:
                self._revoke_locked(replaced, "replaced by a newer grant")

            cookie = next(self._cookies)
            ttl = max(1, min(int(ttl), int(self.cfg["controller"].get("max_grant_seconds", 3600))))
            installed_rules = []
            installed_dps = []
            try:
                for sw_name, dp in sw_dps:
                    rules = flow_rules.grant_rules_for_switch(self.cfg, sw_name, host, service, ttl, cookie)
                    xids = [self._send(dp, ofp_convert.flow_add(dp, r)) for r in rules]
                    installed_dps.append(dp)
                    self._confirm(dp, xids)
                    installed_rules.extend(rules)
            except PolicyError:
                for dp in installed_dps:
                    self._send(dp, ofp_convert.flow_delete_cookie(dp, cookie))
                raise

            now = time.time()
            grant = {
                "cookie": cookie, "session_ref": session_ref, "username": username, "host": host,
                "service": service, "switches": sw_names, "dpids": [dp.id for _, dp in sw_dps],
                "installed_at": now, "expires_at": now + ttl, "hard_timeout": ttl,
            }
            with self._state_lock:
                self.grants[cookie] = grant
                self.by_cookie[cookie] = grant
                self._set_state(host, service, "granted", f"authenticated session {session_ref} (user {username})")
                self._refresh_user_state_locked(username)
            for r in installed_rules:
                self.elog.emit("flow_rule_installed", kind=r.kind, priority=r.priority,
                               match=flow_rules.match_text(r.match), actions=r.actions or "drop",
                               hard_timeout=r.hard_timeout, cookie=cookie)
            self.elog.emit("grant_installed", host=host, service=service, switches=sw_names,
                           session=session_ref, user=username, hard_timeout=ttl, cookie=cookie)
            return {"ok": True, "cookie": cookie, "hard_timeout": ttl, "switches": sw_names,
                    "flows": [r.description for r in installed_rules]}

    def revoke_access(self, reason, session_ref=None, everything=False):
        with self._op_lock:
            with self._state_lock:
                targets = [g for g in self.grants.values() if everything or g["session_ref"] == session_ref]
            if targets:
                self._revoke_locked(targets, reason)
            return {"ok": True, "revoked": len(targets)}

    def _revoke_locked(self, targets, reason):
        with self._state_lock:
            connected = dict(self.datapaths)
        if not connected:
            raise PolicyError(503, "switch_unavailable", "no OpenFlow switches are connected")
        by_dp = {}
        for g in targets:
            for dpid in g.get("dpids", (self.dpid,)):
                if dpid in connected:
                    by_dp.setdefault(dpid, []).append(g["cookie"])
        for dpid, cookies in by_dp.items():
            dp = connected[dpid]
            xids = [self._send(dp, ofp_convert.flow_delete_cookie(dp, c)) for c in cookies]
            self._confirm(dp, xids)
        with self._state_lock:
            for g in targets:
                self._drop_grant_locked(g, reason)

    def _drop_grant_locked(self, grant, reason):
        if self.grants.pop(grant["cookie"], None) is None:
            return
        self.by_cookie.pop(grant["cookie"], None)
        state = "blocked" if grant["host"] in self.blocked_hosts else "denied"
        self._set_state(grant["host"], grant["service"], state, reason)
        self._refresh_user_state_locked(grant["username"])
        self.elog.emit("grant_revoked", host=grant["host"], service=grant["service"],
                       session=grant["session_ref"], user=grant["username"], reason=reason, cookie=grant["cookie"],
                       note="flow rules deleted from the switch(es)")

    def block_host(self, host, reason="blocked by administrator"):
        with self._op_lock:
            with self._state_lock:
                existing = self.blocked_hosts.get(host)
                if existing:
                    return {"ok": True, "host": host, "already_blocked": True, "cookie": existing["cookie"]}
                targets = [g for g in self.grants.values() if g["host"] == host]
            if targets:
                self._revoke_locked(targets, f"host blocked: {reason}")
            dps = self._all_connected_dps()
            cookie = next(self._cookies)
            rules = flow_rules.block_host_rules(self.cfg, host, cookie)
            installed_dps = []
            try:
                for _, dp in dps:
                    xids = [self._send(dp, ofp_convert.flow_add(dp, r)) for r in rules]
                    installed_dps.append(dp)
                    self._confirm(dp, xids)
            except PolicyError:
                for dp in installed_dps:
                    self._send(dp, ofp_convert.flow_delete_cookie(dp, cookie))
                raise
            entry = {"host": host, "cookie": cookie, "reason": reason, "blocked_at": time.time()}
            with self._state_lock:
                self.blocked_hosts[host] = entry
                for service in self.cfg["services"]:
                    self._set_state(host, service, "blocked", reason)
            self.elog.emit("host_blocked", level="warn", host=host, reason=reason, cookie=cookie,
                           switches=[self.expected_dpids.get(d, f"{d:016x}") for d, _ in dps])
            return {"ok": True, "host": host, "cookie": cookie, "already_blocked": False}

    def unblock_host(self, host, reason="unblocked by administrator"):
        with self._op_lock:
            with self._state_lock:
                entry = self.blocked_hosts.get(host)
            if not entry:
                return {"ok": True, "host": host, "was_blocked": False}
            dps = self._all_connected_dps()
            for _, dp in dps:
                xids = [self._send(dp, ofp_convert.flow_delete_cookie(dp, entry["cookie"]))]
                self._confirm(dp, xids)
            with self._state_lock:
                self.blocked_hosts.pop(host, None)
                for service in self.cfg["services"]:
                    self._set_state(host, service, "denied", f"default-deny ({reason})")
            self.elog.emit("host_unblocked", host=host, reason=reason, cookie=entry["cookie"])
            return {"ok": True, "host": host, "was_blocked": True}

    # =============================================================== HTTP API
    def _serve_api(self):
        c = self.cfg["controller"]
        try:
            sock = eventlet.listen((c["api_host"], c["api_port"]))
        except OSError as exc:
            self.elog.emit("api_start_failed", level="error", detail=str(exc))
            self.log.error("cannot bind policy API: %s", exc)
            return
        eventlet.wsgi.server(sock, self._wsgi_app, log=_NullLog(), log_output=False)

    def _wsgi_app(self, environ, start_response):
        try:
            status, payload = self._route(environ)
        except PolicyError as exc:
            status, payload = exc.status, {"ok": False, "error": exc.code, "message": exc.message}
        except Exception:
            self.log.exception("policy API error")
            status, payload = 500, {"ok": False, "error": "internal_error", "message": "controller error"}
        body = json.dumps(payload, default=str).encode()
        start_response(f"{status} {HTTPStatus(status).phrase}",
                       [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]

    def _route(self, environ):
        method, path = environ["REQUEST_METHOD"], environ["PATH_INFO"]
        if method == "GET" and path == "/policy/health":
            return 200, self.health()
        if method == "GET" and path == "/policy/state":
            return 200, self.state()
        if method == "GET" and path == "/policy/flows":
            return 200, self.flows()
        if method == "POST" and path in ("/policy/grant", "/policy/revoke", "/policy/block", "/policy/unblock"):
            token = environ.get("HTTP_X_POLICY_TOKEN", "")
            if not hmac.compare_digest(token, self.cfg["controller"]["api_token"]):
                self.elog.emit("policy_api_forbidden", level="warn", path=path,
                               note="request without the trusted token rejected")
                raise PolicyError(403, "forbidden", "missing or wrong policy token")
            body = self._read_json(environ)
            if path == "/policy/grant":
                return 200, self._api_grant(body)
            if path == "/policy/revoke":
                return 200, self._api_revoke(body)
            if path == "/policy/block":
                return 200, self._api_block(body, unblock=False)
            return 200, self._api_block(body, unblock=True)
        raise PolicyError(404, "not_found", f"{method} {path}")

    @staticmethod
    def _read_json(environ):
        try:
            length = min(int(environ.get("CONTENT_LENGTH") or 0), 8192)
            data = json.loads(environ["wsgi.input"].read(length).decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            raise PolicyError(400, "bad_json", "request body is not valid JSON")
        if not isinstance(data, dict):
            raise PolicyError(400, "bad_request", "JSON object expected")
        return data

    def _api_grant(self, body):
        ref, host, service, ttl = body.get("session_ref"), body.get("host"), body.get("service"), body.get("ttl_seconds")
        username = str(body.get("username", ""))[:64]
        if not (isinstance(ref, str) and REF_RE.match(ref)):
            raise PolicyError(400, "bad_request", "session_ref missing or malformed")
        if host not in client_hosts(self.cfg):
            raise PolicyError(400, "unknown_host", f"{host!r} is not a registered client host")
        if service not in self.cfg["services"]:
            raise PolicyError(400, "unknown_service", f"{service!r} is not a protected service")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1:
            raise PolicyError(400, "bad_request", "ttl_seconds must be a positive integer")
        return self.grant_access(ref, username, host, service, ttl)

    def _api_revoke(self, body):
        reason = str(body.get("reason", "revoked"))[:200]
        if body.get("all") is True:
            return self.revoke_access(reason, everything=True)
        ref = body.get("session_ref")
        if not (isinstance(ref, str) and REF_RE.match(ref)):
            raise PolicyError(400, "bad_request", "session_ref (or all=true) required")
        return self.revoke_access(reason, session_ref=ref)

    def _api_block(self, body, unblock=False):
        host = body.get("host")
        if host not in client_hosts(self.cfg):
            for n, h in client_hosts(self.cfg).items():
                if h["ip"] == host:
                    host = n
                    break
        reason = str(body.get("reason", "unblocked" if unblock else "blocked by administrator"))[:200]
        if host not in client_hosts(self.cfg):
            raise PolicyError(400, "unknown_host", f"{host!r} is not a registered client host")
        return self.unblock_host(host, reason) if unblock else self.block_host(host, reason)

    # ---- read-only views
    def health(self):
        with self._state_lock:
            switches = [
                {"name": self.expected_dpids[d], "dpid": f"{d:016x}", "connected_at": self.connected_at.get(d)}
                for d in sorted(self.datapaths)
            ]
            all_connected = len(self.datapaths) == len(self.expected_dpids)
            return {
                "ok": True, "service": "controller", "openflow": "1.3",
                "uptime": round(time.time() - self.started_at, 1),
                "switch_connected": all_connected,
                "expected_switches": len(self.expected_dpids),
                "connected_switches": len(self.datapaths),
                "switches": switches,
                "flows_updated_at": self.flow_cache["updated_at"],
                "active_grants": len(self.grants),
                "blocked_hosts": sorted(self.blocked_hosts),
            }

    def state(self):
        hosts = [{"name": n, **h} for n, h in sorted(self.cfg["lab"]["hosts"].items())]
        with self._state_lock:
            grants = sorted(self.grants.values(), key=lambda g: g["installed_at"])
            access = sorted(self.host_state.values(), key=lambda s: (s["host"], s["service"]))
            users = sorted(self.user_state.values(), key=lambda u: u["username"])
            blocked = sorted(self.blocked_hosts.values(), key=lambda b: b["host"])
        return {"generated_at": time.time(), "health": self.health(), "hosts": hosts,
                "grants": grants, "access": access, "users": users, "blocked_hosts": blocked}

    def flows(self):
        with self._state_lock:
            cache = dict(self.flow_cache)
            connected = len(self.datapaths) > 0
        updated = cache["updated_at"]
        return {**cache, "switch_connected": connected,
                "age_seconds": None if updated is None else round(time.time() - updated, 1)}
