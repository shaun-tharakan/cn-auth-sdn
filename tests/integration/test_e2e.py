"""End-to-end tests on a real Mininet + Open vSwitch + OS-Ken controller stack.

Needs: root, `mn`, `ovs-vsctl`/`ovs-ofctl`, `osken-manager`, `openssl` (venv on PATH).  Run with
    scripts/run_integration_tests.sh
The test starts its own controller, TLS auth server and multi-switch Mininet lab on *different ports*
and with a short session lifetime, so it does not clash with a running demo.
Tests are numbered because they build on each other's state (one lab per class).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))


def _skip_reason():
    if os.geteuid() != 0:
        return "integration tests need root (sudo)"
    for tool in ("mn", "ovs-vsctl", "ovs-ofctl", "osken-manager", "openssl"):
        if not shutil.which(tool):
            return f"required tool not found on PATH: {tool}"
    try:
        import mininet  # noqa: F401
    except ImportError:
        return "python mininet module not importable (use a venv with --system-site-packages)"
    return None


def _http_json(url, timeout=2):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _wait(fn, seconds, what):
    end = time.time() + seconds
    while time.time() < end:
        try:
            if fn():
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for {what}")


@unittest.skipIf(_skip_reason(), _skip_reason() or "")
class EndToEnd(unittest.TestCase):
    TTL = 12

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cnauth-it-")
        cls.cert_dir = f"{cls.tmp}/certs"
        subprocess.run(["bash", str(REPO / "scripts" / "gen_certs.sh"), cls.cert_dir], check=True, capture_output=True)
        cfg = json.loads((REPO / "config" / "config.json").read_text())
        cfg["controller"].update(openflow_port=16653, api_port=18080, flow_poll_seconds=1.0)
        cfg["auth"].update(
            port=15000, admin_port=15001, session_ttl_seconds=cls.TTL, reaper_interval_seconds=0.5,
            tls={"enabled": True, "cert": f"{cls.cert_dir}/server.crt",
                 "key": f"{cls.cert_dir}/server.key", "ca_cert": f"{cls.cert_dir}/ca.crt"},
        )
        cfg["paths"] = {"events_log": f"{cls.tmp}/events.jsonl", "users_db": f"{cls.tmp}/users.json",
                        "run_dir": f"{cls.tmp}/run", "log_dir": cls.tmp}
        if os.environ.get("CNAUTH_OVS_DATAPATH"):
            dp = os.environ["CNAUTH_OVS_DATAPATH"]
            cfg["lab"]["switch"]["datapath"] = dp
            for sw in cfg["lab"]["switches"]:
                sw["datapath"] = dp
        os.makedirs(cfg["paths"]["run_dir"], exist_ok=True)
        cls.cfg_path = f"{cls.tmp}/config.json"
        Path(cls.cfg_path).write_text(json.dumps(cfg))
        cls.env = dict(os.environ, PYTHONPATH=str(REPO), CNAUTH_CONFIG=cls.cfg_path)
        os.environ.update(PYTHONPATH=str(REPO), CNAUTH_CONFIG=cls.cfg_path)
        cls.api = f"http://127.0.0.1:{cfg['controller']['api_port']}"
        cls.admin = f"http://127.0.0.1:{cfg['auth']['admin_port']}"
        cls.procs = {}
        subprocess.run([sys.executable, "-m", "auth.init_users", "--force"], env=cls.env, cwd=REPO,
                       check=True, capture_output=True)
        try:
            cls._spawn("controller", ["osken-manager", "--ofp-listen-host", "127.0.0.1", "--ofp-tcp-listen-port",
                                      "16653", "controller.sdn_controller"])
            _wait(lambda: _http_json(cls.api + "/policy/health")["ok"], 25, "controller API")
            cls._spawn("auth", [sys.executable, "-m", "auth.server"])
            _wait(lambda: _http_json(cls.admin + "/health")["ok"], 15, "auth server")
            from common.config import load_config
            from network.topology import Lab
            cls.cfg = load_config(cls.cfg_path)
            cls.lab = Lab(cls.cfg)
            if not cls.lab.start(wait_seconds=40):
                raise RuntimeError("switches did not connect to the controller")
            _wait(lambda: _http_json(cls.api + "/policy/health")["switch_connected"], 15, "all switches registration")
        except Exception:
            cls.tearDownClass()
            raise

    @classmethod
    def _spawn(cls, name, argv):
        log = open(f"{cls.tmp}/{name}.out", "wb")
        cls.procs[name] = subprocess.Popen(argv, env=cls.env, cwd=REPO, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "lab", None) and cls.lab.net:
            cls.lab.stop()
        for proc in cls.procs.values():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if os.environ.get("CNAUTH_KEEP_LOGS"):
            print(f"\nlogs kept in {cls.tmp}")
        else:
            shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---------------------------------------------------------------- helpers
    def on(self, host, command, timeout=25):
        """Run a shell command inside a Mininet host; returns (exit_code, output)."""
        out = self.lab.host(host).cmd(
            f"cd {REPO} && PYTHONPATH={REPO} CNAUTH_CONFIG={self.cfg_path} timeout {timeout} {command}; echo __RC=$?")
        body, _, rc = out.rpartition("__RC=")
        return int(rc.strip() or 1), body

    def reach(self, host):
        return self.on(host, "python3 network/service_client.py --timeout 2")

    def login(self, host, user, password):
        return self.on(host, f"python3 -m auth.client login --user {user} --password {password}")

    def access(self, host):
        return self.on(host, "python3 -m auth.client access --service protected-echo")

    def logout(self, host):
        return self.on(host, "python3 -m auth.client logout")

    def flows(self, switch="s1"):
        return subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch], capture_output=True,
                              text=True, check=True).stdout

    def grant_flows(self, switch="s1"):
        return [l for l in self.flows(switch).splitlines() if "priority=200" in l]

    def block_flows(self, switch="s1"):
        return [l for l in self.flows(switch).splitlines() if "priority=300" in l]

    def assert_blocked(self, host):
        rc, out = self.reach(host)
        self.assertEqual(rc, 1, out)
        self.assertIn("BLOCKED", out)

    def assert_reached(self, host):
        rc, out = self.reach(host)
        self.assertEqual(rc, 0, out)
        self.assertIn("echo: hello from a client", out)

    # ---------------------------------------------------------------- scenarios
    def test_01_default_deny_before_authentication_on_all_switches(self):
        for host in ("h1", "h2", "h3"):
            self.assert_blocked(host)
        for sw in ("s1", "s2", "s3"):
            flows = self.flows(sw)
            self.assertIn("priority=100,ip,nw_dst=10.10.0.100 actions=drop", flows, sw)
            self.assertEqual(self.grant_flows(sw), [], sw)

    def test_02_tls_login_and_multiswitch_grant_h1_and_h3(self):
        # h1 is on s2 -> path [s2, s1]
        rc, out = self.login("h1", "alice", "alice-demo-pw")
        self.assertEqual(rc, 0, out)
        self.assert_blocked("h1")
        rc, out = self.access("h1")
        self.assertEqual(rc, 0, out)
        self.assertIn("ACCESS GRANTED", out)
        self.assert_reached("h1")
        self.assertEqual(len(self.grant_flows("s2")), 2)
        self.assertEqual(len(self.grant_flows("s1")), 2)
        self.assertEqual(len(self.grant_flows("s3")), 0)

        # h3 is on s3 -> path [s3, s1]
        rc, out = self.login("h3", "carol", "carol-demo-pw")
        self.assertEqual(rc, 0, out)
        rc, out = self.access("h3")
        self.assertEqual(rc, 0, out)
        self.assert_reached("h3")
        self.assertEqual(len(self.grant_flows("s3")), 2)
        self.logout("h3")

        _wait(lambda: any(f["kind"] == "grant" for f in _http_json(self.api + "/policy/flows")["flows"]), 6,
              "grant rules to appear in the controller's flow view")

    def test_03_other_hosts_stay_blocked_and_session_cannot_be_borrowed(self):
        self.assert_blocked("h2")
        self.assert_blocked("h3")
        state = json.loads(Path(self.cfg["paths"]["run_dir"], "client_session_10.10.0.1.json").read_text())
        Path(self.cfg["paths"]["run_dir"], "client_session_10.10.0.2.json").write_text(json.dumps(state))
        rc, out = self.access("h2")
        self.assertEqual(rc, 1, out)
        self.assertIn("session_ip_mismatch", out)
        self.assert_blocked("h2")
        os.remove(Path(self.cfg["paths"]["run_dir"], "client_session_10.10.0.2.json"))

    def test_04_authenticated_user_without_permission_is_denied(self):
        rc, out = self.login("h2", "bob", "bob-demo-pw")
        self.assertEqual(rc, 0, out)
        rc, out = self.access("h2")
        self.assertEqual(rc, 1, out)
        self.assertIn("role_not_permitted", out)
        self.assert_blocked("h2")
        self.logout("h2")

    def test_05_wrong_password_is_rejected(self):
        rc, out = self.login("h3", "alice", "wrong-password")
        self.assertEqual(rc, 1, out)
        self.assertIn("LOGIN FAILED", out)
        self.assert_blocked("h3")

    def test_06_logout_revokes_network_access_across_switches(self):
        self.assertEqual(self.login("h1", "alice", "alice-demo-pw")[0], 0)
        self.assertEqual(self.access("h1")[0], 0)
        self.assert_reached("h1")
        rc, out = self.logout("h1")
        self.assertEqual(rc, 0, out)
        self.assertIn("network access revoked", out)
        self.assert_blocked("h1")
        self.assertEqual(self.grant_flows("s1"), [])
        self.assertEqual(self.grant_flows("s2"), [])

    def test_07_session_expiry_revokes_network_access(self):
        self.assertEqual(self.login("h1", "alice", "alice-demo-pw")[0], 0)
        self.assertEqual(self.access("h1")[0], 0)
        self.assert_reached("h1")
        time.sleep(self.TTL + 3)
        self.assert_blocked("h1")
        self.assertEqual(self.grant_flows("s1"), [])
        self.assertEqual(self.grant_flows("s2"), [])
        statuses = [s["status"] for s in _http_json(self.admin + "/sessions")["sessions"] if s["username"] == "alice"]
        self.assertIn("expired", statuses)

    def test_08_admin_role_users_revoke_block_and_logs(self):
        self.assertEqual(self.login("h1", "alice", "alice-demo-pw")[0], 0)
        self.assertEqual(self.access("h1")[0], 0)
        self.assert_reached("h1")

        # carol logs in as admin on h3 and exercises admin subcommands over TLS
        self.assertEqual(self.login("h3", "carol", "carol-demo-pw")[0], 0)
        rc, out = self.on("h3", "python3 -m auth.client admin users")
        self.assertEqual(rc, 0, out)
        self.assertIn("alice", out)

        rc, out = self.on("h3", "python3 -m auth.client admin block --host h1 --reason demo_block")
        self.assertEqual(rc, 0, out)
        self.assert_blocked("h1")
        for sw in ("s1", "s2", "s3"):
            self.assertEqual(len(self.block_flows(sw)), 2, sw)

        rc, out = self.on("h3", "python3 -m auth.client admin logs --limit 10")
        self.assertEqual(rc, 0, out)
        self.assertIn("admin_block_host", out)

        rc, out = self.on("h3", "python3 -m auth.client admin unblock --host h1")
        self.assertEqual(rc, 0, out)
        for sw in ("s1", "s2", "s3"):
            self.assertEqual(self.block_flows(sw), [], sw)
        self.logout("h3")

    def test_09_concurrent_load_test_over_tls(self):
        proc = subprocess.run(
            [sys.executable, "scripts/load_test.py", "--port", "15000", "--clients", "15", "--iterations", "2"],
            env=self.env, cwd=REPO, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("errors: 0", proc.stdout)

    def test_10_event_log_records_the_story(self):
        from common.events import read_recent
        names = {e["event"] for e in read_recent(self.cfg["paths"]["events_log"], 800)}
        for expected in ("switch_connected", "base_rules_installed", "login_success", "login_failure",
                         "authorization_decision", "access_granted", "grant_installed", "flow_rule_installed",
                         "grant_revoked", "session_expired", "session_logout", "host_blocked", "host_unblocked",
                         "service_access", "access_blocked"):
            self.assertIn(expected, names)

    def test_11_controller_outage_fails_closed(self):
        self.assertEqual(self.login("h1", "alice", "alice-demo-pw")[0], 0)
        proc = self.procs["controller"]
        proc.terminate()
        proc.wait(timeout=10)
        rc, out = self.access("h1")
        self.assertEqual(rc, 1, out)
        self.assertIn("controller_unavailable", out)
        self.assert_blocked("h1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
