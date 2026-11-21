"""Read-only monitoring dashboard (Flask).

    python3 -m dashboard.app          # http://127.0.0.1:5050

The Python side only exposes JSON endpoints that read LIVE state from the auth
server, the controller and the shared event log; templates/static/app.js renders them.
The dashboard cannot grant, revoke or change anything.
"""
from flask import Flask, jsonify, render_template, request

from common.config import load_config
from dashboard import backends


def create_app(cfg=None):
    cfg = cfg or load_config()
    app = Flask(__name__)
    app.config["CNAUTH"] = cfg

    @app.get("/")
    def index():
        return render_template("index.html", refresh_ms=cfg["dashboard"]["refresh_ms"],
                               service_name="protected-echo", lab=cfg["lab"]["subnet"])

    @app.get("/api/overview")
    def api_overview():
        return jsonify(backends.overview(cfg))

    @app.get("/api/sessions")
    def api_sessions():
        return jsonify(backends.sessions(cfg))

    @app.get("/api/access")
    def api_access():
        return jsonify(backends.access(cfg))

    @app.get("/api/flows")
    def api_flows():
        return jsonify(backends.flows(cfg))

    @app.get("/api/auth")
    def api_auth():
        return jsonify(backends.events(cfg, limit=request.args.get("limit", 30), only={"auth_activity"}))

    @app.get("/api/events")
    def api_events():
        cat = request.args.get("category")
        return jsonify(backends.events(cfg, limit=request.args.get("limit", 80), only={cat} if cat else None))

    @app.after_request
    def no_cache(resp):
        resp.headers["Cache-Control"] = "no-store"
        return resp

    return app


def main():
    cfg = load_config()
    d = cfg["dashboard"]
    print(f"dashboard on http://{d['host']}:{d['port']}  (read-only)")
    create_app(cfg).run(host=d["host"], port=d["port"], threaded=True)


if __name__ == "__main__":
    main()
