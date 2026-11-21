import json
import os
import tempfile
import threading
import unittest

from auth.passwords import hash_password, verify_password
from auth.sessions import SessionManager
from common.config import ConfigError, load_config, validate_config
from common.events import EventLog, read_recent
from controller import flow_rules
from policy.engine import PolicyEngine
from tests.unit.helpers import make_cfg


class PasswordTests(unittest.TestCase):
    def test_hash_verify_and_salt(self):
        h1, h2 = hash_password("secret"), hash_password("secret")
        self.assertNotEqual(h1, h2)
        self.assertNotIn("secret", h1)
        self.assertTrue(verify_password("secret", h1))
        self.assertFalse(verify_password("Secret", h1))

    def test_malformed_record_is_rejected_not_raised(self):
        for bad in ("", "plain", "scrypt$x$y$z$a$b", "md5$1$2$3$a$b"):
            self.assertFalse(verify_password("x", bad))


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.ended = []
        self.mgr = SessionManager(60, clock=lambda: self.now[0], on_end=self.ended.append)

    def test_create_and_lookup(self):
        s = self.mgr.create("alice", "student", "10.0.0.1", "h1")
        self.assertGreaterEqual(len(s.session_id), 40)
        got, err = self.mgr.get_active(s.session_id)
        self.assertIsNone(err)
        self.assertEqual(got.username, "alice")
        self.assertEqual(self.mgr.get_active("nope")[1], "invalid_session")

    def test_expiry_marks_ended_and_notifies(self):
        s = self.mgr.create("alice", "student", "10.0.0.1", "h1")
        self.now[0] += 61
        self.assertEqual(self.mgr.get_active(s.session_id)[1], "session_expired")
        self.assertEqual(self.ended[0].status, "expired")
        self.assertEqual(self.mgr.active_count(), 0)

    def test_expire_due_sweeps(self):
        self.mgr.create("a", "student", "1.1.1.1", None)
        self.mgr.create("b", "student", "1.1.1.2", None)
        self.now[0] += 100
        self.assertEqual(len(self.mgr.expire_due()), 2)
        self.assertEqual(len(self.ended), 2)

    def test_logout_and_revoke(self):
        a = self.mgr.create("alice", "student", "1.1.1.1", None)
        b = self.mgr.create("bob", "guest", "1.1.1.2", None)
        self.assertEqual(self.mgr.logout(a.session_id).status, "logged_out")
        self.assertIsNone(self.mgr.logout(a.session_id))          # second logout: nothing to do
        self.assertEqual(self.mgr.revoke_user("bob")[0].status, "revoked")
        self.assertEqual({s.status for s in self.ended}, {"logged_out", "revoked"})

    def test_snapshot_hides_secrets_and_marks_state(self):
        s = self.mgr.create("alice", "student", "1.1.1.1", "h1")
        self.mgr.logout(s.session_id)
        rows = self.mgr.snapshot()
        self.assertNotIn(s.session_id, json.dumps(rows))
        self.assertEqual(rows[0]["status"], "logged_out")


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = load_config()
        self.engine = PolicyEngine(self.cfg)

    def decide(self, role="student", session_ip="10.10.0.1", request_ip="10.10.0.1", service="protected-echo"):
        return self.engine.decide(username="u", role=role, session_ip=session_ip, request_ip=request_ip, service=service)

    def test_allowed(self):
        d = self.decide()
        self.assertTrue(d.allowed)
        self.assertEqual((d.host, d.service_port), ("h1", 9000))

    def test_denials(self):
        self.assertEqual(self.decide(role="guest").code, "role_not_permitted")
        self.assertEqual(self.decide(role="unknown-role").code, "role_not_permitted")
        self.assertEqual(self.decide(service="nope").code, "unknown_service")
        self.assertEqual(self.decide(request_ip="10.10.0.2").code, "session_ip_mismatch")
        self.assertEqual(self.decide(session_ip="9.9.9.9", request_ip="9.9.9.9").code, "unknown_host")
        self.assertEqual(self.decide(session_ip="10.10.0.254", request_ip="10.10.0.254").code, "unknown_host")


class FlowRuleTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config()

    def test_default_deny_beats_forwarding_and_grant_beats_deny(self):
        base = flow_rules.base_rules(self.cfg)
        deny = [r for r in base if r.kind == "default-deny"]
        fwd = [r for r in base if r.kind in ("l2-forward", "l2-flood")]
        grant = flow_rules.grant_rules(self.cfg, "h1", "protected-echo", 30, 5)
        self.assertTrue(min(r.priority for r in deny) > max(r.priority for r in fwd))
        self.assertTrue(min(r.priority for r in grant) > max(r.priority for r in deny))
        self.assertTrue(all(r.actions == [] for r in deny))   # drop

    def test_every_protected_direction_has_a_deny(self):
        keys = {tuple(sorted(r.match.items())) for r in flow_rules.base_rules(self.cfg) if r.kind == "default-deny"}
        self.assertIn((("eth_type", 0x0800), ("ipv4_dst", "10.10.0.100")), keys)
        self.assertIn((("eth_type", 0x0800), ("ipv4_src", "10.10.0.100")), keys)

    def test_grant_is_narrow_and_bound_to_port_mac_ip(self):
        fwd, rev = flow_rules.grant_rules(self.cfg, "h2", "protected-echo", 99999, 7)
        for key in ("in_port", "eth_src", "eth_dst", "ipv4_src", "ipv4_dst", "ip_proto"):
            self.assertIn(key, fwd.match)
        self.assertEqual((fwd.match["in_port"], fwd.match["ipv4_src"], fwd.match["tcp_dst"]), (2, "10.10.0.2", 9000))
        self.assertEqual((rev.match["in_port"], rev.match["ipv4_dst"], rev.match["tcp_src"]), (3, "10.10.0.2", 9000))
        self.assertEqual(fwd.hard_timeout, flow_rules.MAX_HARD_TIMEOUT)   # clamped to 16 bit
        self.assertEqual(flow_rules.grant_rules(self.cfg, "h1", "protected-echo", 0, 1)[0].hard_timeout, 1)


class ConfigTests(unittest.TestCase):
    def test_validation_catches_inconsistency(self):
        cfg = load_config()
        cfg["lab"]["hosts"]["h2"]["port"] = 1                 # duplicate switch port
        with self.assertRaises(ConfigError):
            validate_config(cfg)
        cfg = load_config()
        cfg["policy"]["roles"]["student"].append("ghost")
        with self.assertRaises(ConfigError):
            validate_config(cfg)


class EventLogTests(unittest.TestCase):
    def test_secrets_stripped_and_concurrent_writes_intact(self):
        path = os.path.join(tempfile.mkdtemp(), "e.jsonl")
        log = EventLog(path, "test")
        log.emit("x", password="hunter2", session_id="abc", username="alice")

        def spam(n):
            for i in range(50):
                log.emit("spam", worker=n, i=i)
        threads = [threading.Thread(target=spam, args=(n,)) for n in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        raw = open(path).read()
        self.assertNotIn("hunter2", raw)
        self.assertNotIn("abc", raw)
        events = read_recent(path, 1000)
        self.assertEqual(len(events), 301)                    # every line parsed -> none interleaved
        self.assertEqual(events[0]["username"], "alice")

    def test_read_missing_file(self):
        self.assertEqual(read_recent("/nonexistent/file.jsonl"), [])


if __name__ == "__main__":
    unittest.main()
