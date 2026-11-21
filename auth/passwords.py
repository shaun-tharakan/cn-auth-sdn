"""Password hashing with scrypt (standard library, memory-hard).

Stored format:  scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>
Passwords are never stored or logged in plaintext.
"""
import base64
import hashlib
import hmac
import os

N, R, P, DKLEN = 2 ** 14, 8, 1, 32


def _derive(password, salt, n, r, p):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=DKLEN, maxmem=64 * 1024 * 1024)


def hash_password(password):
    salt = os.urandom(16)
    digest = _derive(password, salt, N, R, P)
    return "scrypt${}${}${}${}${}".format(N, R, P, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())


def verify_password(password, stored):
    """Constant-time check. Returns False (never raises) for malformed records."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(hash_b64)
        actual = _derive(password, base64.b64decode(salt_b64), int(n), int(r), int(p))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# Used to burn the same CPU time when a username does not exist, so response
# timing does not reveal which usernames are valid.
DUMMY_HASH = hash_password("dummy-password-for-timing")
