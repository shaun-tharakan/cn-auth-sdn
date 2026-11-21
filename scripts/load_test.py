#!/usr/bin/env python3
"""Concurrent load test for the TLS/TCP authentication server.

Spawns ``--clients`` worker threads that each perform ``--iterations`` cycles of
ping -> login -> status -> (optional access) -> logout and reports throughput
and latency percentiles.

Examples:
    python3 scripts/load_test.py --clients 30 --iterations 3
    python3 scripts/load_test.py --clients 50 --iterations 2 --with-access
"""
import argparse
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from auth.client import AuthClient, ConnectionProblem  # noqa: E402
from common.config import load_config  # noqa: E402


def run_worker(worker_id, host, port, tls, ca_cert, user, password, iterations, with_access, service, timeout):
    latencies_ms = []
    ok_ops = 0
    errors = []
    for _ in range(iterations):
        try:
            with AuthClient(host, port, timeout=timeout, tls=tls, ca_cert=ca_cert) as client:
                t0 = time.perf_counter()
                pong = client.request({"op": "ping"})
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                if not pong.get("ok"):
                    errors.append(f"w{worker_id} ping: {pong}")
                    continue
                ok_ops += 1

                t0 = time.perf_counter()
                login = client.request({"op": "login", "username": user, "password": password})
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                if not login.get("ok"):
                    errors.append(f"w{worker_id} login: {login.get('error')}")
                    continue
                ok_ops += 1
                sid = login["session_id"]

                t0 = time.perf_counter()
                st = client.request({"op": "status", "session_id": sid})
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                if st.get("ok"):
                    ok_ops += 1
                else:
                    errors.append(f"w{worker_id} status: {st.get('error')}")

                if with_access:
                    t0 = time.perf_counter()
                    acc = client.request({"op": "access", "session_id": sid, "service": service})
                    latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                    if acc.get("ok"):
                        ok_ops += 1
                    else:
                        errors.append(f"w{worker_id} access: {acc.get('error')}/{acc.get('code')}")

                t0 = time.perf_counter()
                out = client.request({"op": "logout", "session_id": sid})
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                if out.get("ok"):
                    ok_ops += 1
                else:
                    errors.append(f"w{worker_id} logout: {out.get('error')}")
        except ConnectionProblem as exc:
            errors.append(f"w{worker_id} conn: {exc}")
    return ok_ops, latencies_ms, errors


def run_load_test(host, port, tls=False, ca_cert=None, user="alice", password="alice-demo-pw",
                  clients=20, iterations=2, with_access=False, service="protected-echo", timeout=10.0):
    started = time.perf_counter()
    all_latencies = []
    all_errors = []
    total_ok = 0

    with ThreadPoolExecutor(max_workers=clients) as pool:
        futs = [
            pool.submit(run_worker, i, host, port, tls, ca_cert, user, password,
                        iterations, with_access, service, timeout)
            for i in range(clients)
        ]
        for fut in as_completed(futs):
            ok_ops, lats, errs = fut.result()
            total_ok += ok_ops
            all_latencies.extend(lats)
            all_errors.extend(errs)

    elapsed = max(1e-6, time.perf_counter() - started)
    all_latencies.sort()
    p95 = all_latencies[int(0.95 * (len(all_latencies) - 1))] if all_latencies else 0.0
    return {
        "clients": clients,
        "iterations": iterations,
        "elapsed_s": round(elapsed, 3),
        "ok_ops": total_ok,
        "error_count": len(all_errors),
        "errors": all_errors[:10],
        "rps": round(total_ok / elapsed, 1),
        "p50_ms": round(statistics.median(all_latencies), 2) if all_latencies else 0.0,
        "p95_ms": round(p95, 2),
        "max_ms": round(max(all_latencies), 2) if all_latencies else 0.0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    parser.add_argument("--no-tls", action="store_true")
    parser.add_argument("--ca-cert")
    parser.add_argument("--user", default="alice")
    parser.add_argument("--password", default="alice-demo-pw")
    parser.add_argument("--clients", type=int, default=25)
    parser.add_argument("--iterations", type=int, default=2)
    parser.add_argument("--with-access", action="store_true")
    parser.add_argument("--service", default="protected-echo")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    cfg = load_config(args.config)
    port = args.port or cfg["auth"]["port"]
    tls_cfg = cfg["auth"].get("tls") or {}
    tls = False if args.no_tls else bool(tls_cfg.get("enabled"))
    ca_cert = args.ca_cert or tls_cfg.get("ca_cert")

    res = run_load_test(
        host=args.host, port=port, tls=tls, ca_cert=ca_cert, user=args.user, password=args.password,
        clients=args.clients, iterations=args.iterations, with_access=args.with_access,
        service=args.service, timeout=args.timeout,
    )
    print(f"Load test ({'TLS' if tls else 'TCP'} -> {args.host}:{port}): "
          f"{res['clients']} clients x {res['iterations']} iter")
    print(f"  completed ops : {res['ok_ops']}  errors: {res['error_count']}  elapsed: {res['elapsed_s']}s")
    print(f"  throughput    : {res['rps']} ops/s")
    print(f"  latency (ms)  : p50={res['p50_ms']}  p95={res['p95_ms']}  max={res['max_ms']}")
    if res["errors"]:
        for e in res["errors"]:
            print(f"  ERR: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
