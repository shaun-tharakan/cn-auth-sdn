"""Controller logic WITHOUT a switch: a fake datapath serialises real OpenFlow 1.3 messages.

Needs os-ken (skipped otherwise).  This proves the messages are well-formed and that the
multi-switch grant/revoke/block bookkeeping behaves; the real switch behaviour is covered
by the Mininet tests.
"""
import threading
import unittest

try:
    from os_ken.ofproto import ofproto_v1_3, ofproto_v1_3_parser
    HAVE_OSKEN = True
except ImportError:
    HAVE_OSKEN = False

if HAVE_OSKEN:
    from controller import flow_rules, ofp_convert
    import controller.sdn_controller as sdn
from common.config import lab_switches, load_config


class FakeDP:
    ofproto, ofproto_parser = (ofproto_v1_3, ofproto_v1_3_parser) if HAVE_OSKEN else (None, None)

    def __init__(self, app=None, dpid=1):
        self.id = dpid
        self.sent, self.xid, self.app = [], 0, app

    def set_xid(self, msg):
        self.xid += 1
        msg.set_xid(self.xid)
        return self.xid

    def send_msg(self, msg):
        if msg.xid is None:
            self.set_xid(msg)
        msg.serialize()
        self.sent.append(msg)
        if isinstance(msg, ofproto_v1_3_parser.OFPBarrierRequest) and self.app:
            evt = self.app._barriers.pop(msg.xid, None)   # the "switch" confirms immediately
            if evt:
                evt.set()


@unittest.skipUnless(HAVE_OSKEN, "os-ken not installed")
class OfpConvertTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.dp = load_config(), FakeDP()

    def test_all_base_and_grant_rules_serialise_and_parse_back(self):
        specs = (flow_rules.base_rules_for_switch(self.cfg, "s1")
                 + flow_rules.base_rules_for_switch(self.cfg, "s2")
                 + flow_rules.grant_rules_for_switch(self.cfg, "s2", "h1", "protected-echo", 30, 9)
                 + flow_rules.block_host_rules(self.cfg, "h2", 10))
        for spec in specs:
            msg = ofp_convert.flow_add(self.dp, spec)
            msg.serialize()
            parsed = ofproto_v1_3_parser.OFPFlowMod.parser(self.dp, msg.version, msg.msg_type, msg.msg_len, msg.xid, msg.buf)
            self.assertEqual(parsed.priority, spec.priority)
            self.assertEqual(parsed.hard_timeout, spec.hard_timeout)
            self.assertEqual(parsed.cookie, spec.cookie)

    def test_drop_has_no_instructions_and_grant_requests_flow_removed(self):
        deny = next(r for r in flow_rules.base_rules(self.cfg) if r.kind == "default-deny")
        self.assertEqual(ofp_convert.flow_add(self.dp, deny).instructions, [])
        grant = flow_rules.grant_rules(self.cfg, "h1", "protected-echo", 30, 9)[0]
        self.assertTrue(ofp_convert.flow_add(self.dp, grant).flags & ofproto_v1_3.OFPFF_SEND_FLOW_REM)

    def test_delete_by_cookie_uses_full_mask(self):
        msg = ofp_convert.flow_delete_cookie(self.dp, 42)
        self.assertEqual((msg.cookie, msg.cookie_mask, msg.command), (42, 0xFFFFFFFFFFFFFFFF, ofproto_v1_3.OFPFC_DELETE))


@unittest.skipUnless(HAVE_OSKEN, "os-ken not installed")
class ControllerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.app = sdn.PolicyController()
        self.dps = {}
        for sw in lab_switches(self.app.cfg):
            dpid = int(sw["dpid"], 16)
            dp = FakeDP(self.app, dpid=dpid)
            self.dps[sw["name"]] = dp
            self.app.datapaths[dpid] = dp
        self.dp = self.dps["s1"]

    def flowmods(self, sw_name, command):
        return [m for m in self.dps[sw_name].sent
                if isinstance(m, ofproto_v1_3_parser.OFPFlowMod) and m.command == command]

    def test_grant_installs_rules_across_path_switches_and_records_user_state(self):
        out = self.app.grant_access("s-aaaa11", "alice", "h1", "protected-echo", 30)
        self.assertEqual(out["switches"], ["s2", "s1"])
        self.assertEqual(len(self.flowmods("s2", ofproto_v1_3.OFPFC_ADD)), 2)
        self.assertEqual(len(self.flowmods("s1", ofproto_v1_3.OFPFC_ADD)), 2)
        self.assertEqual(len(self.flowmods("s3", ofproto_v1_3.OFPFC_ADD)), 0)
        self.assertEqual(self.app.host_state["h1|protected-echo"]["state"], "granted")
        self.assertIn("alice", self.app.user_state)
        self.assertEqual(self.app.user_state["alice"]["hosts"], ["h1"])

    def test_revoke_deletes_by_cookie_on_all_path_switches(self):
        self.app.grant_access("s-aaaa11", "alice", "h1", "protected-echo", 30)
        self.app.revoke_access("logout", session_ref="s-aaaa11")
        self.assertEqual(len(self.flowmods("s2", ofproto_v1_3.OFPFC_DELETE)), 1)
        self.assertEqual(len(self.flowmods("s1", ofproto_v1_3.OFPFC_DELETE)), 1)
        self.assertEqual(self.app.grants, {})
        self.assertEqual(self.app.user_state, {})
        state = self.app.host_state["h1|protected-echo"]
        self.assertEqual((state["state"], state["reason"]), ("denied", "logout"))

    def test_revoke_other_session_leaves_grant(self):
        self.app.grant_access("s-aaaa11", "alice", "h1", "protected-echo", 30)
        self.app.revoke_access("x", session_ref="s-other99")
        self.assertEqual(len(self.app.grants), 1)

    def test_regrant_replaces_previous_grant(self):
        self.app.grant_access("s-aaaa11", "alice", "h1", "protected-echo", 30)
        self.app.grant_access("s-bbbb22", "carol", "h1", "protected-echo", 30)
        self.assertEqual([g["session_ref"] for g in self.app.grants.values()], ["s-bbbb22"])
        self.assertNotIn("alice", self.app.user_state)
        self.assertIn("carol", self.app.user_state)

    def test_missing_path_switch_means_no_grant(self):
        self.app.datapaths.pop(self.dps["s2"].id)
        with self.assertRaises(sdn.PolicyError) as cm:
            self.app.grant_access("s-aaaa11", "alice", "h1", "protected-echo", 30)
        self.assertEqual(cm.exception.status, 503)
        self.assertEqual(self.app.grants, {})

    def test_switch_error_rolls_back_and_denies(self):
        orig = self.dps["s1"].send_msg

        def failing(msg):
            orig(msg)
            if isinstance(msg, ofproto_v1_3_parser.OFPFlowMod) and msg.command == ofproto_v1_3.OFPFC_ADD:
                self.app._errors[msg.xid] = (5, 1)
        self.dps["s1"].send_msg = failing
        with self.assertRaises(sdn.PolicyError):
            self.app.grant_access("s-aaaa11", "alice", "h1", "protected-echo", 30)
        self.assertEqual(self.app.grants, {})
        self.assertTrue(self.flowmods("s2", ofproto_v1_3.OFPFC_DELETE))
        self.assertTrue(self.flowmods("s1", ofproto_v1_3.OFPFC_DELETE))

    def test_block_and_unblock_host_across_all_switches(self):
        self.app.grant_access("s-aaaa11", "alice", "h1", "protected-echo", 30)
        self.app.block_host("h1", "port scan")
        self.assertEqual(self.app.grants, {})
        self.assertEqual(self.app.host_state["h1|protected-echo"]["state"], "blocked")
        for sw in ("s1", "s2", "s3"):
            adds = [m for m in self.flowmods(sw, ofproto_v1_3.OFPFC_ADD) if m.priority == flow_rules.PRIO_BLOCK]
            self.assertEqual(len(adds), 2, sw)
        self.app.unblock_host("h1")
        self.assertEqual(self.app.host_state["h1|protected-echo"]["state"], "denied")

    def test_concurrent_grants_keep_user_state_consistent(self):
        errs = []

        def worker(i, host, user):
            try:
                self.app.grant_access(f"s-ref{i:04d}", user, host, "protected-echo", 30)
            except Exception as exc:
                errs.append(exc)

        threads = [
            threading.Thread(target=worker, args=(1, "h1", "alice")),
            threading.Thread(target=worker, args=(2, "h3", "carol")),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errs, [])
        self.assertEqual(len(self.app.grants), 2)
        self.assertEqual(set(self.app.user_state), {"alice", "carol"})

    def test_api_validation_rejects_bad_requests(self):
        for body in ({}, {"session_ref": "x"}, {"session_ref": "s-aaaa11", "host": "srv", "service": "protected-echo", "ttl_seconds": 5},
                     {"session_ref": "s-aaaa11", "host": "h1", "service": "nope", "ttl_seconds": 5},
                     {"session_ref": "s-aaaa11", "host": "h1", "service": "protected-echo", "ttl_seconds": "5"},
                     {"session_ref": "s-aaaa11", "host": "h1", "service": "protected-echo", "ttl_seconds": 0}):
            with self.assertRaises(sdn.PolicyError) as cm:
                self.app._api_grant(body)
            self.assertEqual(cm.exception.status, 400)

    def test_wsgi_requires_token(self):
        import io
        env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/policy/revoke", "CONTENT_LENGTH": "2", "wsgi.input": io.BytesIO(b"{}")}
        out = {}
        self.app._wsgi_app(env, lambda status, headers: out.setdefault("status", status))
        self.assertTrue(out["status"].startswith("403"))
        env.update(HTTP_X_POLICY_TOKEN=self.app.cfg["controller"]["api_token"], **{"wsgi.input": io.BytesIO(b'{"all": true}'), "CONTENT_LENGTH": "13"})
        out.clear()
        self.app._wsgi_app(env, lambda status, headers: out.setdefault("status", status))
        self.assertTrue(out["status"].startswith("200"))


if __name__ == "__main__":
    unittest.main()
