"""Unit tests for the 4 Demo 2 features:
1. TLS authentication channel + cert generation script
2. Multi-switch topology config & OpenFlow rule generation
3. Concurrent clients & scripts/load_test.py
4. Admin role (list active users, revoke, block/unblock hosts, view logs)
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from auth.admin_api import AdminAPI
from auth.client import AuthClient, ConnectionProblem
from auth.passwords import hash_password
from auth.server import AuthServer
from auth.users import UserStore
from common.config import REPO_ROOT, load_config
from controller import flow_rules
from scripts.load_test import run_load_test
from tests.unit.helpers import FakeController, make_cfg

_USERS = {
    "alice": {"password_hash": hash_password("alice-pw"), "role": "student"},
    "bob": {"password_hash": hash_password("bob-pw"), "role": "guest"},
    "carol": {"password_hash": hash_password("carol-pw"), "role": "admin"},
}


def _http(url, method="GET", body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Admin-Token"] = token
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers)
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read().decode())


class MultiSwitchRuleTests(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config()

    def test_switch_paths_across_tree(self):
        self.assertEqual(flow_rules.switch_path(self.cfg, "s2", "s1"), ["s2", "s1"])
        self.assertEqual(flow_rules.switch_path(self.cfg, "s3", "s1"), ["s3", "s1"])
        self.assertEqual(flow_rules.switch_path(self.cfg, "s2", "s3"), ["s2", "s1", "s3"])
        self.assertEqual(flow_rules.grant_switches_for(self.cfg, "h1", "protected-echo"), ["s2", "s1"])
        self.assertEqual(flow_rules.grant_switches_for(self.cfg, "h3", "protected-echo"), ["s3", "s1"])

    def test_base_and_grant_rules_per_switch(self):
        s2_base = flow_rules.base_rules_for_switch(self.cfg, "s2")
        s1_base = flow_rules.base_rules_for_switch(self.cfg, "s1")
        # Both switches must have default-deny rules for the protected service host
        self.assertTrue(any(r.kind == "default-deny" and r.match.get("ipv4_dst") == "10.10.0.100" for r in s2_base))
        self.assertTrue(any(r.kind == "default-deny" and r.match.get("ipv4_dst") == "10.10.0.100" for r in s1_base))

        # Grant for h1 (on s2) -> srv (on s1) installs 2 rules on s2, 2 on s1, 0 on s3
        r_s2 = flow_rules.grant_rules_for_switch(self.cfg, "s2", "h1", "protected-echo", 30, 7)
        r_s1 = flow_rules.grant_rules_for_switch(self.cfg, "s1", "h1", "protected-echo", 30, 7)
        r_s3 = flow_rules.grant_rules_for_switch(self.cfg, "s3", "h1", "protected-echo", 30, 7)
        self.assertEqual(len(r_s2), 2)
        self.assertEqual(len(r_s1), 2)
        self.assertEqual(r_s3, [])
        # s2 forward rule enters port 1 (h1) and exits trunk port 3 (toward s1)
        self.assertEqual(r_s2[0].match["in_port"], 1)
        self.assertEqual(r_s2[0].actions, [("output", 3)])
        # s1 forward rule enters trunk port 3 (from s2) and exits port 1 (srv)
        self.assertEqual(r_s1[0].match["in_port"], 3)
        self.assertEqual(r_s1[0].actions, [("output", 1)])

    def test_block_host_rules_outrank_grants(self):
        rules = flow_rules.block_host_rules(self.cfg, "h2", 99)
        self.assertEqual(len(rules), 2)
        for r in rules:
            self.assertGreater(r.priority, flow_rules.PRIO_GRANT)
            self.assertEqual(r.actions, [])


class TLSTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cert_dir = Path(self.tmp.name) / "certs"
        subprocess.run(["bash", str(REPO_ROOT / "scripts" / "gen_certs.sh"), str(self.cert_dir)],
                       check=True, capture_output=True)
        tls_cfg = {
            "enabled": True,
            "cert": str(self.cert_dir / "server.crt"),
            "key": str(self.cert_dir / "server.key"),
            "ca_cert": str(self.cert_dir / "ca.crt"),
        }
        self.cfg = make_cfg(self.tmp.name, tls=tls_cfg)
        with open(self.cfg["paths"]["users_db"], "w") as fh:
            json.dump({"users": _USERS}, fh)
        self.ctl = FakeController()
        self.server = AuthServer(self.cfg, UserStore(self.cfg["paths"]["users_db"]), controller=self.ctl)
        self.server.start()

    def tearDown(self):
        self.server.stop()
        self.tmp.cleanup()

    def test_tls_client_login_access_logout(self):
        ca = str(self.cert_dir / "ca.crt")
        with AuthClient("127.0.0.1", self.server.port, tls=True, ca_cert=ca) as c:
            pong = c.request({"op": "ping"})
            self.assertTrue(pong["ok"])
            self.assertTrue(pong["tls"])
            login = c.request({"op": "login", "username": "alice", "password": "alice-pw"})
            self.assertTrue(login["ok"])
            acc = c.request({"op": "access", "session_id": login["session_id"], "service": "protected-echo"})
            self.assertTrue(acc["ok"])
            out = c.request({"op": "logout", "session_id": login["session_id"]})
            self.assertTrue(out["ok"])

    def test_plaintext_client_rejected_on_tls_server(self):
        with AuthClient("127.0.0.1", self.server.port, tls=False) as c:
            with self.assertRaises(ConnectionProblem):
                c.request({"op": "ping"})


class ConcurrencyAndLoadTestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cert_dir = Path(self.tmp.name) / "certs"
        subprocess.run(["bash", str(REPO_ROOT / "scripts" / "gen_certs.sh"), str(self.cert_dir)],
                       check=True, capture_output=True)
        tls_cfg = {
            "enabled": True,
            "cert": str(self.cert_dir / "server.crt"),
            "key": str(self.cert_dir / "server.key"),
            "ca_cert": str(self.cert_dir / "ca.crt"),
        }
        self.cfg = make_cfg(self.tmp.name, tls=tls_cfg, max_connections=256)
        with open(self.cfg["paths"]["users_db"], "w") as fh:
            json.dump({"users": _USERS}, fh)
        self.ctl = FakeController()
        self.server = AuthServer(self.cfg, UserStore(self.cfg["paths"]["users_db"]), controller=self.ctl)
        self.server.start()

    def tearDown(self):
        self.server.stop()
        self.tmp.cleanup()

    def test_load_test_script_over_tls(self):
        res = run_load_test(
            host="127.0.0.1", port=self.server.port, tls=True, ca_cert=str(self.cert_dir / "ca.crt"),
            user="alice", password="alice-pw", clients=20, iterations=2, with_access=True,
        )
        self.assertEqual(res["error_count"], 0, res["errors"])
        self.assertEqual(res["ok_ops"], 20 * 2 * 5)


class AdminRoleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(self.tmp.name)
        with open(self.cfg["paths"]["users_db"], "w") as fh:
            json.dump({"users": _USERS}, fh)
        self.ctl = FakeController()
        self.server = AuthServer(self.cfg, UserStore(self.cfg["paths"]["users_db"]), controller=self.ctl)
        self.server.start()
        self.admin_api = AdminAPI(self.server, "127.0.0.1", 0, self.cfg["auth"]["admin_token"])
        self.admin_api.start()
        self.admin_url = f"http://127.0.0.1:{self.admin_api.port}"

    def tearDown(self):
        self.admin_api.stop()
        self.server.stop()
        self.tmp.cleanup()

    def test_non_admin_is_forbidden(self):
        with AuthClient("127.0.0.1", self.server.port) as c:
            sid = c.request({"op": "login", "username": "alice", "password": "alice-pw"})["session_id"]
            for op in ("admin_list_users", "admin_list_blocked", "admin_logs"):
                resp = c.request({"op": op, "session_id": sid})
                self.assertFalse(resp["ok"])
                self.assertEqual(resp["error"], "forbidden")

    def test_admin_role_protocol_full_workflow(self):
        with AuthClient("127.0.0.1", self.server.port) as c:
            alice_sid = c.request({"op": "login", "username": "alice", "password": "alice-pw"})["session_id"]
            carol_sid = c.request({"op": "login", "username": "carol", "password": "carol-pw"})["session_id"]

            # 1. List active users
            users = c.request({"op": "admin_list_users", "session_id": carol_sid})
            self.assertTrue(users["ok"])
            self.assertEqual({u["username"] for u in users["users"]}, {"alice", "carol"})

            # 2. Revoke alice
            rev = c.request({"op": "admin_revoke", "session_id": carol_sid, "username": "alice"})
            self.assertTrue(rev["ok"])
            self.assertEqual(len(rev["revoked"]), 1)
            self.assertEqual(c.request({"op": "status", "session_id": alice_sid})["error"], "invalid_session")

            # 3. Block h2 -> controller block_host called, list_blocked shows h2, unblock restores
            blk = c.request({"op": "admin_block_host", "session_id": carol_sid, "host": "h2", "reason": "port scan"})
            self.assertTrue(blk["ok"])
            self.assertIn("h2", self.ctl.blocked)
            blist = c.request({"op": "admin_list_blocked", "session_id": carol_sid})
            self.assertEqual([b["host"] for b in blist["blocked_hosts"]], ["h2"])
            unblk = c.request({"op": "admin_unblock_host", "session_id": carol_sid, "host": "h2"})
            self.assertTrue(unblk["ok"])
            self.assertNotIn("h2", self.ctl.blocked)

            # 4. View logs while carol session is active
            logs = c.request({"op": "admin_logs", "session_id": carol_sid, "limit": 20})
            self.assertTrue(logs["ok"])
            self.assertTrue(any(e["event"] == "admin_block_host" for e in logs["events"]))

            # 5. Block h1 (our own test IP) -> login denied with host_blocked until unblocked
            c.request({"op": "admin_block_host", "session_id": carol_sid, "host": "h1", "reason": "abuse"})
            denied = c.request({"op": "login", "username": "alice", "password": "alice-pw"})
            self.assertEqual(denied["error"], "host_blocked")
            # Local AdminAPI unblocks h1
            _http(self.admin_url + "/unblock", method="POST", body={"host": "h1"},
                  token=self.cfg["auth"]["admin_token"])
            ok_again = c.request({"op": "login", "username": "alice", "password": "alice-pw"})
            self.assertTrue(ok_again["ok"])

    def test_admin_http_api_endpoints(self):
        tok = self.cfg["auth"]["admin_token"]
        with AuthClient("127.0.0.1", self.server.port) as c:
            c.request({"op": "login", "username": "alice", "password": "alice-pw"})
        users = _http(self.admin_url + "/users")
        self.assertEqual([u["username"] for u in users["users"]], ["alice"])
        _http(self.admin_url + "/block", method="POST", body={"host": "h2", "reason": "test"}, token=tok)
        self.assertEqual([b["host"] for b in _http(self.admin_url + "/blocked")["blocked_hosts"]], ["h2"])
        _http(self.admin_url + "/unblock", method="POST", body={"host": "h2"}, token=tok)
        logs = _http(self.admin_url + "/logs?limit=10")
        self.assertTrue(len(logs["events"]) > 0)


if __name__ == "__main__":
    unittest.main()
