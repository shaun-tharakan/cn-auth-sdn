"""Try to use the protected service (run on a Mininet host: ``h1 python3 network/service_client.py``).

Prints the service's reply, or BLOCKED if the network never lets the connection through.
Exit code 0 = reached the service, 1 = blocked / timed out / refused.
"""
import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.config import load_config  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--message", default="hello from a client")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    cfg = load_config(args.config)
    svc = cfg["services"]["protected-echo"]
    host = args.host or cfg["lab"]["hosts"][svc["host"]]["ip"]
    port = args.port or svc["port"]
    try:
        with socket.create_connection((host, port), timeout=args.timeout) as sock:
            sock.settimeout(args.timeout)
            stream = sock.makefile("rwb")
            banner = stream.readline().decode().strip()
            stream.write(args.message.encode() + b"\n")
            stream.flush()
            reply = stream.readline().decode().strip()
            print(f"REACHED {host}:{port}\n  {banner}\n  {reply}")
            return 0
    except socket.timeout:
        print(f"BLOCKED: no response from {host}:{port} within {args.timeout}s (packets dropped by the network)")
    except OSError as exc:
        print(f"BLOCKED: cannot connect to {host}:{port}: {exc}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
