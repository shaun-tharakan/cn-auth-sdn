import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from policy.controller_client import ControllerClient, ControllerRejected, ControllerUnavailable


class Stub(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def _go(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        Stub.seen.append((self.command, self.path, self.headers.get("X-Policy-Token"), body))
        status = {"/policy/grant": 200, "/policy/revoke": 400}.get(self.path, 503)
        payload = json.dumps({"ok": status == 200, "error": "bad", "message": "nope", "flows": []}).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    do_GET = do_POST = _go


class ControllerClientTests(unittest.TestCase):
    def setUp(self):
        self.httpd = HTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.shutdown)
        self.client = ControllerClient(f"http://127.0.0.1:{self.httpd.server_address[1]}", "secret", timeout=2)

    def test_grant_sends_token_and_body(self):
        self.client.grant("s-abc123", "alice", "h1", "protected-echo", 30)
        method, path, token, body = Stub.seen[-1]
        self.assertEqual((method, path, token), ("POST", "/policy/grant", "secret"))
        self.assertEqual(json.loads(body)["host"], "h1")

    def test_4xx_is_rejection_5xx_is_unavailable(self):
        with self.assertRaises(ControllerRejected):
            self.client.revoke("s-abc123", "x")
        with self.assertRaises(ControllerUnavailable):
            self.client.health()

    def test_unreachable_controller(self):
        with self.assertRaises(ControllerUnavailable):
            ControllerClient("http://127.0.0.1:1", "t", timeout=1).health()


if __name__ == "__main__":
    unittest.main()
