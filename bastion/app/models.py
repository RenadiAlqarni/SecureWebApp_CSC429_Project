"""
Data access for users and comments.

Each security-relevant operation has two implementations next to each other:
`_..._vulnerable()` (string-built SQL, MD5) and `_..._secure()` (parameterized
SQL, bcrypt, encryption at rest). The public functions pick one based on the
running mode, so routes never contain SQL themselves.
"""
import re

from flask import current_app

from . import db
from .security import passwords

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,24}$")


def is_secure():
    return current_app.config["MODE"] == "secure"


def cipher():
    """FieldCipher (Fernet) in secure mode, a no-op PlaintextCipher in vulnerable mode."""
    return current_app.extensions["field_cipher"]


class ValidationError(ValueError):
    """Raised with a list of messages the form can show to the user."""

    def __init__(self, messages):
        super().__init__("; ".join(messages))
        self.messages = messages


# ==========================================================================
# Registration
# ==========================================================================
def register_user(username, password, full_name="", email=""):
    username = username.strip()
    full_name = full_name.strip()
    email = email.strip()
    if is_secure():
        return _register_secure(username, password, full_name, email)
    return _register_vulnerable(username, password, full_name, email)


def _register_vulnerable(username, password, full_name, email):
    # VULNERABLE: no password policy and no input validation.
    if not username or not password:
        raise ValidationError(["Username and password are required."])

    # VULNERABLE (SQL injection): input is pasted straight into the SQL text.
    exists = db.query_unsafe(
        f"SELECT id FROM users WHERE username = '{username}'", one=True, inspect=True
    )
    if exists:
        raise ValidationError(["That username is taken."])

    # VULNERABLE (weak password storage): unsalted MD5. Identical passwords get
    # identical hashes and common ones are found instantly in lookup tables.
    pw_hash = passwords.hash_md5(password)

    # VULNERABLE (SQL injection): putting   Mallory', 'admin')--   in the
    # "Full name" field closes the string, supplies role='admin' and comments
    # out the rest, so the attacker registers themselves as an administrator.
    db.execute_unsafe(
        "INSERT INTO users (username, password_hash, email, full_name, role) "
        f"VALUES ('{username}', '{pw_hash}', '{email}', '{full_name}', 'user')",
        inspect=True,
    )


def _register_secure(username, password, full_name, email):
    # SECURE: validate everything on the server (the browser checks are only UX).
    errors = []
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-32 characters: letters, numbers, dot, dash or underscore.")
    errors += passwords.policy_errors(password)
    if len(full_name) > 80:
        errors.append("Full name must be 80 characters or fewer.")
    if email and not EMAIL_RE.match(email):
        errors.append("Enter a valid email address, or leave it empty.")
    if errors:
        raise ValidationError(errors)

    # SECURE (parameterized query): the "?" placeholders are filled by the
    # SQLite driver, so input is always treated as data, never as SQL.
    if db.query("SELECT id FROM users WHERE username = ?", (username,), one=True, inspect=True):
        raise ValidationError(["That username is taken."])

    db.execute(
        "INSERT INTO users (username, password_hash, email, full_name) VALUES (?, ?, ?, ?)",
        (
            username,
            passwords.hash_bcrypt(password),   # SECURE: salted, slow bcrypt hash
            cipher().encrypt(email),           # SECURE: email encrypted at rest
            full_name,
        ),
        inspect=True,
    )


# ==========================================================================
# Login
# ==========================================================================
def authenticate(username, password):
    """Return the user row if the credentials are valid, otherwise None."""
    if is_secure():
        return _authenticate_secure(username.strip(), password)
    return _authenticate_vulnerable(username, password)


def _authenticate_vulnerable(username, password):
    # VULNERABLE (SQL injection): typing   admin' --   as the username turns the
    # query into  ... WHERE username = 'admin' --' AND password_hash = '...'
    # Everything after -- is a comment, so the password is never checked.
    pw_hash = passwords.hash_md5(password)
    sql = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password_hash = '{pw_hash}'"
    )
    return db.query_unsafe(sql, one=True, inspect=True)


def _authenticate_secure(username, password):
    # SECURE (parameterized query): look the user up by name only...
    row = db.query(
        "SELECT id, username, role, password_hash FROM users WHERE username = ?",
        (username,), one=True, inspect=True,
    )
    if row is None:
        # Run a bcrypt check anyway so "no such user" takes as long as
        # "wrong password" (stops username discovery by timing).
        passwords.burn_time()
        return None
    # ...then compare the password in Python with bcrypt's constant-time check.
    if not passwords.verify_bcrypt(password, row["password_hash"]):
        return None
    return row


# ==========================================================================
# Users
# ==========================================================================
def get_user(user_id):
    # Parameterized in both modes: the assignment's SQL injection target is the
    # login and registration pages.
    return db.query(
        "SELECT id, username, full_name, email, role, created_at, last_login "
        "FROM users WHERE id = ?",
        (user_id,), one=True,
    )


def profile(user_row):
    """User row as a dict with the email decrypted for display."""
    data = dict(user_row)
    data["email"] = cipher().decrypt(data.get("email"))
    return data


def touch_last_login(user_id):
    db.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (user_id,))


def list_users():
    rows = db.query(
        "SELECT id, username, full_name, role, created_at, last_login, password_hash "
        "FROM users ORDER BY id"
    )
    return [dict(r) for r in rows]


def set_role(user_id, role):
    if role not in ("user", "admin"):
        raise ValidationError(["Unknown role."])
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))


def count_admins():
    return db.query("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'", one=True)["n"]


def seed_user(username, password, full_name, email, role):
    """Create a demo account at start-up, hashed the way the current mode hashes."""
    if db.query("SELECT 1 FROM users WHERE username = ?", (username,), one=True):
        return
    pw_hash = passwords.hash_bcrypt(password) if is_secure() else passwords.hash_md5(password)
    db.execute(
        "INSERT INTO users (username, password_hash, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
        (username, pw_hash, full_name, cipher().encrypt(email), role),
    )


# ==========================================================================
# Comments (guestbook on the dashboard)
# ==========================================================================
def add_comment(user_id, body):
    # Parameterized in both modes. The comment feature demonstrates XSS, which
    # is about how the text is *displayed*, not how it is stored.
    db.execute("INSERT INTO comments (user_id, body) VALUES (?, ?)", (user_id, body))


def list_comments(limit=50):
    rows = db.query(
        "SELECT c.id, c.body, c.created_at, u.username, u.role "
        "FROM comments c JOIN users u ON u.id = c.user_id "
        "ORDER BY c.id DESC LIMIT ?",
        (limit,),
    )
    return [dict(r) for r in rows]


def delete_comment(comment_id):
    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
