"""
Sessions: encrypted cookie + server-side registry (secure mode).

Flask's default session cookie is *signed* but not *encrypted*: anyone can
base64-decode it and read what is inside (try scripts/inspect_cookie.py on a
cookie from the vulnerable build). In secure mode the whole session is
encrypted with Fernet, so the cookie is an opaque token that cannot be read or
modified without the server's key.

Encryption alone cannot make a cookie "forgettable": a copied cookie would stay
valid until it expires. So in secure mode the cookie also carries a random
session id, and the server keeps a table of live ids (stored as SHA-256 hashes).
Logout deletes the row, which kills the session everywhere at once, even if
someone kept a copy of the old cookie.
"""
import hashlib
import json
import secrets

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app, g, session
from flask.sessions import SecureCookieSession, SessionInterface

from .. import db, models

SERVER_SESSION_MAX_HOURS = 12  # absolute limit, on top of the 30-minute idle timeout


class EncryptedCookieSessionInterface(SessionInterface):
    """SECURE: session dict -> JSON -> Fernet token stored in the cookie."""

    session_class = SecureCookieSession

    def __init__(self, fernet: Fernet, max_age_seconds: int):
        self.fernet = fernet
        self.max_age = max_age_seconds

    def open_session(self, app, request):
        token = request.cookies.get(self.get_cookie_name(app))
        if not token:
            return self.session_class()
        try:
            # ttl: Fernet rejects tokens older than the idle timeout, even if the
            # browser ignores the cookie's expiry date.
            payload = self.fernet.decrypt(token.encode("ascii"), ttl=self.max_age)
            return self.session_class(json.loads(payload))
        except (InvalidToken, ValueError, UnicodeError):
            # Tampered, expired or foreign cookie: start over with an empty session.
            return self.session_class()

    def save_session(self, app, session, response):
        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        httponly = self.get_cookie_httponly(app)

        if session.accessed:
            response.vary.add("Cookie")

        if not session:
            if session.modified:  # session was cleared (logout) -> delete cookie
                response.delete_cookie(name, domain=domain, path=path, secure=secure,
                                       samesite=samesite, httponly=httponly)
            return

        if not self.should_set_cookie(app, session):
            return

        token = self.fernet.encrypt(json.dumps(dict(session)).encode("utf-8")).decode("ascii")
        response.set_cookie(
            name, token,
            expires=self.get_expiration_time(app, session),
            httponly=httponly, domain=domain, path=path, secure=secure, samesite=samesite,
        )


def _hash_sid(sid):
    return hashlib.sha256(sid.encode("ascii")).hexdigest()


def _secure():
    return current_app.config["MODE"] == "secure"


def start_session(user):
    """Log `user` in on the current request."""
    # Both modes: throw away the pre-login session so an attacker cannot plant
    # a session id before login and reuse it after (session fixation).
    # Pending flash messages are carried over so they still show after redirect.
    pending_flashes = session.get("_flashes", [])
    session.clear()
    if pending_flashes:
        session["_flashes"] = pending_flashes
    session.permanent = True
    session["user_id"] = user["id"]

    if _secure():
        # SECURE: random 256-bit id, registered server-side so it can be revoked.
        sid = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO sessions (sid_hash, user_id, expires_at) "
            f"VALUES (?, ?, datetime('now', '+{SERVER_SESSION_MAX_HOURS} hours'))",
            (_hash_sid(sid), user["id"]),
        )
        session["sid"] = sid
    else:
        # VULNERABLE: identity details sit readable in the cookie and there is
        # no server-side record, so the cookie cannot be revoked.
        session["username"] = user["username"]
        session["role"] = user["role"]

    models.touch_last_login(user["id"])


def end_session(everywhere=False):
    """Log out. With everywhere=True, revoke every session of this user."""
    if _secure():
        if everywhere and g.get("user"):
            db.execute("DELETE FROM sessions WHERE user_id = ?", (g.user["id"],))
        elif session.get("sid"):
            db.execute("DELETE FROM sessions WHERE sid_hash = ?", (_hash_sid(session["sid"]),))
    session.clear()
    g.user = None


def active_session_count(user_id):
    if not _secure():
        return None
    row = db.query(
        "SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND expires_at > datetime('now')",
        (user_id,), one=True,
    )
    return row["n"]


def load_logged_in_user():
    """before_request hook: set g.user (or None) for this request."""
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return

    if _secure():
        # SECURE: the cookie alone is not enough; its id must still be live
        # in the server-side table (deleted on logout, expires after 12 h).
        sid = session.get("sid")
        alive = sid and db.query(
            "SELECT 1 FROM sessions WHERE sid_hash = ? AND user_id = ? "
            "AND expires_at > datetime('now')",
            (_hash_sid(sid), user_id), one=True,
        )
        if not alive:
            session.clear()
            return

    # Role and profile always come from the database, not from the cookie.
    user = models.get_user(user_id)
    if user is None:
        session.clear()
        return
    g.user = user
