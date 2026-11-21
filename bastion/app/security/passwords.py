"""
Password hashing and password policy.

Why bcrypt instead of MD5?
  * MD5 is a fast, general-purpose hash. A normal GPU computes billions of MD5
    hashes per second, and unsalted MD5 of common passwords is already in public
    lookup tables (e.g. 5f4dcc3b5aa765d61d8327deb882cf99 is "password").
  * bcrypt is designed for passwords: it adds a random 128-bit salt per user (so
    equal passwords get different hashes and lookup tables are useless) and has
    an adjustable cost factor. Cost 12 = 2^12 rounds, roughly a quarter second
    per guess on a laptop, which makes large-scale guessing impractical.
  * bcrypt.checkpw compares in constant time and the salt + cost are stored
    inside the hash string ($2b$12$<salt><hash>), so there is nothing extra to
    store or manage.
"""
import hashlib
import re

import bcrypt

BCRYPT_ROUNDS = 12
BCRYPT_MAX_BYTES = 72  # bcrypt only uses the first 72 bytes; bcrypt>=5 rejects longer input

# One list drives both the server-side check and the live checklist on the
# registration page, so the two can never disagree.
POLICY = [
    ("length", r".{8,}", "At least 8 characters"),
    ("upper", r"[A-Z]", "One uppercase letter (A-Z)"),
    ("lower", r"[a-z]", "One lowercase letter (a-z)"),
    ("digit", r"[0-9]", "One number (0-9)"),
    ("special", r"[^A-Za-z0-9]", "One special character (e.g. ! @ # $ %)"),
]


def policy_errors(password):
    """Return the list of unmet requirements (empty list = password is fine)."""
    errors = [f"Password needs: {label.lower()}." for _key, pattern, label in POLICY
              if not re.search(pattern, password or "")]
    if len((password or "").encode("utf-8")) > BCRYPT_MAX_BYTES:
        errors.append(f"Password must be at most {BCRYPT_MAX_BYTES} bytes long.")
    return errors


# VULNERABLE: unsalted MD5 - kept only for the "before" build.
def hash_md5(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


# SECURE: salted, slow, adaptive bcrypt.
def hash_bcrypt(password):
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("ascii")


def verify_bcrypt(password, stored_hash):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("ascii"))
    except ValueError:
        # Malformed hash or password longer than 72 bytes -> treat as a mismatch.
        return False


_DUMMY_HASH = None


def burn_time():
    """Spend the same time as a real check when the username does not exist."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_bcrypt("timing-equaliser-not-a-real-password")
    verify_bcrypt("wrong-password", _DUMMY_HASH)


def describe_hash(stored_hash):
    """Human description used on the admin page (never shows a bcrypt hash)."""
    if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
        cost = stored_hash.split("$")[2]
        return f"bcrypt, cost {int(cost)}"
    if re.fullmatch(r"[0-9a-f]{32}", stored_hash):
        return "MD5 (unsalted)"
    return "unknown"
