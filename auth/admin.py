"""Command-line admin tool (talks to the auth server's local admin API).

    python3 -m auth.admin list
    python3 -m auth.admin users
    python3 -m auth.admin revoke --user alice
    python3 -m auth.admin revoke --ref s-0123456789ab
    python3 -m auth.admin block --host h2 [--reason "..."]
    python3 -m auth.admin unblock --host h2
    python3 -m auth.admin blocked
    python3 -m auth.admin logs [--limit 30] [--level warn]
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

from common.config import load_config


def _call(cfg, method, path, body=None):
    a = cfg["auth"]
    req = urllib.request.Request(f"http://{a['admin_host']}:{a['admin_port']}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Admin-Token": a["admin_token"], "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=4) as resp:
        return json.loads(resp.read().decode())


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("users")
    rv = sub.add_parser("revoke")
    rv.add_argument("--user")
    rv.add_argument("--ref")
    bk = sub.add_parser("block")
    bk.add_argument("--host", required=True)
    bk.add_argument("--reason", default="blocked by administrator")
    ub = sub.add_parser("unblock")
    ub.add_argument("--host", required=True)
    sub.add_parser("blocked")
    lg = sub.add_parser("logs")
    lg.add_argument("--limit", type=int, default=30)
    lg.add_argument("--level")

    args = parser.parse_args()
    cfg = load_config(args.config)
    try:
        if args.cmd in ("list", "users"):
            path = "/sessions" if args.cmd == "list" else "/users"
            key = "sessions" if args.cmd == "list" else "users"
            rows = _call(cfg, "GET", path)[key]
            print(f"{'REF':16s} {'USER':8s} {'HOST':5s} {'STATUS':10s} {'LEFT':>6s}  SERVICES")
            for r in rows:
                print(f"{r['ref']:16s} {r['username']:8s} {str(r['host']):5s} {r['status']:10s} "
                      f"{r['seconds_remaining']:>5d}s  {','.join(r['services']) or '-'}")
            if not rows:
                print(f"(no {key})")
        elif args.cmd == "revoke":
            if not (args.user or args.ref):
                parser.error("revoke needs --user or --ref")
            out = _call(cfg, "POST", "/revoke", {"username": args.user, "session_ref": args.ref})
            print(f"revoked sessions: {out['revoked'] or 'none matched'}")
        elif args.cmd == "block":
            out = _call(cfg, "POST", "/block", {"host": args.host, "reason": args.reason})
            print(f"blocked host {out['host']}: {out['reason']}")
        elif args.cmd == "unblock":
            out = _call(cfg, "POST", "/unblock", {"host": args.host})
            print(f"unblocked host {out['host']}")
        elif args.cmd == "blocked":
            rows = _call(cfg, "GET", "/blocked")["blocked_hosts"]
            for b in rows:
                print(f"{b['host']:6s} by={b['blocked_by']} reason={b['reason']}")
            if not rows:
                print("(no blocked hosts)")
        elif args.cmd == "logs":
            q = {"limit": str(args.limit)}
            if args.level:
                q["level"] = args.level
            rows = _call(cfg, "GET", "/logs?" + urllib.parse.urlencode(q))["events"]
            for e in rows:
                print(f"{e.get('time','')} [{e.get('level','info')}] {e.get('component')}.{e.get('event')}")
            if not rows:
                print("(no log entries)")
    except urllib.error.HTTPError as exc:
        print(f"admin API error {exc.code}: {exc.read().decode()}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"cannot reach auth admin API: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
