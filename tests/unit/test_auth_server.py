"""Auth server over real TCP sockets (loopback); the controller is a recording fake."""
import json
import socket
import tempfile
import threading
import time
import unittest
import urllib.request

from auth.admin_api import AdminAPI
from auth.init_users import DEMO_USERS
from auth.passwords import hash_password
from auth.server import AuthServer
from auth.users import UserStore
from tests.unit.helpers import FakeController, make_cfg


_USERS = {n: {"password_hash": hash_password(pw), "role": role} for n, (pw, role) in DEMO_USERS.items()}  # hash once


def rpc(port, payload, raw=None, timeout=5):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(raw if raw is not None else json.dumps(payload).encode() + b"\n")
        with s.makefile("rb") as f:
            return json.loads(f.readline().decode())


class ServerCase(unittest.TestCase):
    ttl = 60

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = make_cfg(self.tmp, max_failed_logins=3, lockout_seconds=30, max_message_bytes=512)
        self.cfg["auth"]["session_ttl_seconds"] = self.ttl
        path = self.tmp + "/users.json"
        json.dump({"users": _USERS}, open(path, "w"))
        self.ctl = FakeController()
        self.server = AuthServer(self.cfg, users=UserStore(path), controller=self.ctl)
        self.server.start()
        self.port = self.server.port
        self.addCleanup(self.server.stop)

    def login(self, user="alice", pw="alice-demo-pw"):
        return rpc(self.port, {"op": "login", "username": user, "password": pw})


class ProtocolTests(ServerCase):
    def test_ping(self):
        self.assertTrue(rpc(self.port, {"op": "ping"})["ok"])

    def test_login_ok_and_bad_credentials(self):
        r = self.login()
        self.assertTrue(r["ok"])
        self.assertEqual((r["role"], r["host"]), ("student", "h1"))
        bad = self.login(pw="nope")
        self.assertEqual(bad["error"], "invalid_credentials")
        self.assertEqual(self.login("ghost", "x")["message"], bad["message"])   # no username enumeration

    def test_malformed_messages(self):
        self.assertEqual(rpc(self.port, None, raw=b"not json\n")["error"], "bad_json")
        self.assertEqual(rpc(self.port, None, raw=b"\xff\xfe\n")["error"], "bad_json")
        self.assertEqual(rpc(self.port, None, raw=b"[1,2]\n")["error"], "bad_request")
        self.assertEqual(rpc(self.port, {"op": "explode"})["error"], "unknown_op")
        self.assertEqual(rpc(self.port, {"op": "login", "username": 5, "password": []})["error"], "bad_request")
        self.assertEqual(rpc(self.port, {"op": "login", "username": "../etc", "password": "x"})["error"], "bad_request")
        self.assertEqual(rpc(self.port, {"op": "access", "session_id": "x"})["error"], "bad_request")

    def test_oversized_message(self):
        self.assertEqual(rpc(self.port, None, raw=b"A" * 2000)["error"], "message_too_large")

    def test_multiple_requests_on_one_connection(self):
        with socket.create_connection(("127.0.0.1", self.port)) as s:
            f = s.makefile("rwb")
            for _ in range(3):
                f.write(b'{"op":"ping"}\n')
                f.flush()
                self.assertTrue(json.loads(f.readline())["ok"])

    def test_abrupt_disconnect_does_not_break_server(self):
        s = socket.create_connection(("127.0.0.1", self.port))
        s.sendall(b'{"op":"login"')           # incomplete, then vanish
        s.close()
        time.sleep(0.2)
        self.assertTrue(rpc(self.port, {"op": "ping"})["ok"])

    def test_lockout_after_repeated_failures(self):
        for _ in range(3):
            self.login(pw="bad")
        r = self.login()                      # even the right password is refused while locked
        self.assertEqual(r["error"], "locked_out")

    def test_concurrent_clients(self):
        results, errors = [], []

        def work(i):
            try:
                r = self.login()
                results.append(r["session_id"])
                self.assertTrue(rpc(self.port, {"op": "status", "session_id": r["session_id"]})["ok"])
            except Exception as exc:   # noqa: BLE001
                errors.append(exc)
        threads = [threading.Thread(target=work, args=(i,)) for i in range(25)]
        [t.start() for t in threads]
        [t.join(timeout=30) for t in threads]
        self.assertEqual(errors, [])
        self.assertEqual(len(set(results)), 25)             # unique session ids
        self.assertEqual(self.server.sessions.active_count(), 25)


class AuthorizationTests(ServerCase):
    def access(self, sid, service="protected-echo"):
        return rpc(self.port, {"op": "access", "session_id": sid, "service": service})

    def test_authentication_is_not_authorization(self):
        sid = self.login("bob", "bob-demo-pw")["session_id"]
        r = self.access(sid)
        self.assertEqual((r["ok"], r["code"]), (False, "role_not_permitted"))
        self.assertEqual([c for c in self.ctl.calls if c[0] == "grant"], [])

    def test_grant_calls_controller_with_ref_not_secret(self):
        sid = self.login()["session_id"]
        r = self.access(sid)
        self.assertTrue(r["granted"])
        kind, ref, host, service, ttl = self.ctl.calls[-1]
        self.assertEqual((kind, host, service), ("grant", "h1", "protected-echo"))
        self.assertNotIn(sid, ref)
        self.assertTrue(0 < ttl <= 60)

    def test_unknown_session_and_service(self):
        self.assertEqual(self.access("bogus")["error"], "invalid_session")
        sid = self.login()["session_id"]
        self.assertEqual(self.access(sid, "nothing")["code"], "unknown_service")

    def test_logout_revokes_network_access(self):
        sid = self.login()["session_id"]
        self.access(sid)
        r = rpc(self.port, {"op": "logout", "session_id": sid})
        self.assertTrue(r["ok"] and r["network_access_revoked"])
        self.assertEqual(self.ctl.calls[-1][0], "revoke")
        self.assertEqual(rpc(self.port, {"op": "status", "session_id": sid})["error"], "invalid_session")
        self.assertEqual(self.access(sid)["error"], "invalid_session")

    def test_fail_closed_when_controller_down(self):
        sid = self.login()["session_id"]
        self.ctl.up = False
        r = self.access(sid)
        self.assertEqual((r["ok"], r["error"]), (False, "controller_unavailable"))

    def test_revocation_retried_until_controller_returns(self):
        sid = self.login()["session_id"]
        self.access(sid)
        self.ctl.up = False
        r = rpc(self.port, {"op": "logout", "session_id": sid})
        self.assertFalse(r["network_access_revoked"])
        self.assertEqual(self.server.health()["pending_revocations"], 1)
        self.ctl.up = True
        deadline = time.time() + 5
        while time.time() < deadline and self.server.health()["pending_revocations"]:
            time.sleep(0.1)
        self.assertEqual(self.server.health()["pending_revocations"], 0)
        self.assertEqual(self.ctl.calls[-1][0], "revoke")

    def test_admin_revoke_via_http_api(self):
        sid = self.login()["session_id"]
        self.access(sid)
        admin = AdminAPI(self.server, "127.0.0.1", 0, "tok")
        admin.start()
        self.addCleanup(admin.stop)
        base = f"http://127.0.0.1:{admin.port}"
        bad = urllib.request.Request(base + "/revoke", data=b'{"username":"alice"}', method="POST",
                                     headers={"X-Admin-Token": "wrong"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(bad)
        self.assertEqual(cm.exception.code, 403)
        ok = urllib.request.Request(base + "/revoke", data=b'{"username":"alice"}', method="POST",
                                    headers={"X-Admin-Token": "tok"})
        self.assertEqual(len(json.loads(urllib.request.urlopen(ok).read())["revoked"]), 1)
        self.assertEqual(self.server.sessions.snapshot()[0]["status"], "revoked")
        listing = urllib.request.urlopen(base + "/sessions").read().decode()
        self.assertNotIn(sid, listing)

    def test_startup_clears_stale_grants(self):
        self.assertEqual(self.ctl.calls[0][0], "revoke_all")


class ExpiryTests(ServerCase):
    ttl = 1

    def test_expiry_revokes_network_access_via_reaper(self):
        sid = self.login()["session_id"]
        rpc(self.port, {"op": "access", "session_id": sid, "service": "protected-echo"})
        deadline = time.time() + 6
        while time.time() < deadline and self.ctl.calls[-1][0] != "revoke":
            time.sleep(0.1)
        self.assertEqual(self.ctl.calls[-1][0], "revoke")
        self.assertIn("expired", self.ctl.calls[-1][2])
        self.assertEqual(rpc(self.port, {"op": "status", "session_id": sid})["error"], "invalid_session")
        self.assertEqual(self.server.sessions.snapshot()[0]["status"], "expired")


if __name__ == "__main__":
    unittest.main()
