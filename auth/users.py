"""Local demonstration user database (JSON file with scrypt password hashes)."""
import json
from dataclasses import dataclass

from auth.passwords import DUMMY_HASH, verify_password


@dataclass(frozen=True)
class User:
    username: str
    role: str


class UserStore:
    def __init__(self, path):
        self.path = path
        with open(path, "r", encoding="utf-8") as fh:
            self._users = json.load(fh)["users"]

    def authenticate(self, username, password):
        """Return a :class:`User` on success, otherwise ``None``."""
        record = self._users.get(username)
        if record is None:
            verify_password(password, DUMMY_HASH)  # equalise timing
            return None
        if verify_password(password, record["password_hash"]):
            return User(username, record["role"])
        return None

    def usernames(self):
        return sorted(self._users)
