import tempfile
import unittest

try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False

from common.events import EventLog
from tests.unit.helpers import make_cfg


@unittest.skipUnless(HAVE_FLASK, "Flask not installed")
class DashboardTests(unittest.TestCase):
    def setUp(self):
        from dashboard.app import create_app
        self.tmp = tempfile.mkdtemp()
        self.cfg = make_cfg(self.tmp)
        # nothing listens on these ports -> every backend is genuinely down
        self.cfg["auth"].update(port=1, admin_port=1)
        self.cfg["controller"].update(api_port=1)
        self.client = create_app(self.cfg).test_client()

    def test_nothing_running_is_never_reported_healthy(self):
        states = {c["key"]: c["state"] for c in self.client.get("/api/overview").get_json()["components"]}
        self.assertEqual(set(states), {"auth", "controller", "switch", "topology", "service"})
        self.assertNotIn("running", states.values())
        self.assertEqual(states["switch"], "unknown")        # cannot know without the controller

    def test_data_endpoints_report_unavailable_instead_of_inventing_data(self):
        for path in ("/api/sessions", "/api/access", "/api/flows"):
            body = self.client.get(path).get_json()
            self.assertFalse(body["available"], path)
            self.assertTrue(body["error"])

    def test_events_and_auth_activity_come_from_the_log_without_secrets(self):
        log = EventLog(self.cfg["paths"]["events_log"], "auth")
        log.emit("login_success", username="alice", client_ip="10.10.0.1", host="h1", password="hunter2")
        log.emit("login_failure", level="warn", username="mallory", client_ip="10.10.0.3", host="h3", reason="invalid_credentials")
        log.emit("grant_installed", host="h1", service="protected-echo", hard_timeout=30)
        auth = self.client.get("/api/auth").get_json()["events"]
        self.assertEqual([e["event"] for e in auth], ["login_failure", "login_success"])   # newest first
        allev = self.client.get("/api/events").get_json()["events"]
        self.assertEqual(len(allev), 3)
        self.assertNotIn("hunter2", self.client.get("/api/events").get_data(as_text=True))
        policy = self.client.get("/api/events?category=policy").get_json()["events"]
        self.assertEqual([e["event"] for e in policy], ["grant_installed"])

    def test_page_renders_and_is_read_only(self):
        self.assertIn("Authentication and network access control", self.client.get("/").get_data(as_text=True))
        self.assertEqual(self.client.post("/api/sessions").status_code, 405)


if __name__ == "__main__":
    unittest.main()
