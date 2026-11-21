"""Create data/users.json with hashed DEMONSTRATION credentials.

    python3 -m auth.init_users [--force]

These accounts exist only for the lab demo.  Roles decide what the policy layer
allows (see "policy" in config/config.json):
    alice  student  -> may use protected-echo
    carol  admin    -> may use protected-echo
    bob    guest    -> can log in, but is NOT authorised for any service
"""
import argparse
import json
import os
import sys

from auth.passwords import hash_password
from common.config import load_config

DEMO_USERS = {
    "alice": ("alice-demo-pw", "student"),
    "bob": ("bob-demo-pw", "guest"),
    "carol": ("carol-demo-pw", "admin"),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="overwrite an existing users.json")
    parser.add_argument("--config")
    args = parser.parse_args()
    cfg = load_config(args.config)
    path = cfg["paths"]["users_db"]
    if os.path.exists(path) and not args.force:
        print(f"{path} already exists (use --force to recreate)")
        return 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    users = {name: {"password_hash": hash_password(pw), "role": role} for name, (pw, role) in DEMO_USERS.items()}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"users": users}, fh, indent=2)
    os.chmod(path, 0o600)
    print(f"wrote {path}")
    for name, (pw, role) in DEMO_USERS.items():
        print(f"  {name:6s} role={role:8s} demo password: {pw}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
