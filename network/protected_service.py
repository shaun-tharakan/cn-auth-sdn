"""The protected network service: a small threaded TCP echo server.

It runs on the Mininet host ``srv``.  It cannot enforce anything itself -- the
*network* decides who may reach it (OpenFlow rules).  Every connection that does
get through is logged, which proves that authorised traffic really arrived.

    python3 network/protected_service.py --host 10.10.0.100 --port 9000
"""
import argparse
import os
import signal
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.config import load_config  # noqa: E402
from common.events import EventLog  # noqa: E402


def handle(conn, addr, events, name):
    conn.settimeout(10)
    try:
        conn.sendall(f"PROTECTED-SERVICE {name}: welcome {addr[0]}\n".encode())
        data = conn.recv(1024)
        text = data.decode("utf-8", "replace").strip()
        conn.sendall(f"PROTECTED-SERVICE {name}: echo: {text}\n".encode())
        events.emit("service_access", client_ip=addr[0], service=name, bytes=len(data),
                    note="connection reached the protected service")
    except OSError:
        pass
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int)
    parser.add_argument("--name", default="protected-echo")
    args = parser.parse_args()
    cfg = load_config(args.config)
    port = args.port or cfg["services"][args.name]["port"]
    events = EventLog(cfg["paths"]["events_log"], "service")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, port))
    srv.listen(64)
    srv.settimeout(1.0)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    events.emit("service_started", host=args.host, port=port, service=args.name)
    print(f"protected service {args.name} listening on {args.host}:{port}", flush=True)
    while not stop.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle, args=(conn, addr, events, args.name), daemon=True).start()
    srv.close()
    events.emit("service_stopped", service=args.name)


if __name__ == "__main__":
    main()
