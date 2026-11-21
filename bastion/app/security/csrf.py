"""
CSRF protection (extra hardening, secure mode).

Every form includes a hidden random token that is also stored in the encrypted
session. A malicious site can make the browser *send* a POST to Bastion, but it
cannot *read* the token, so its forged request is rejected with 400.
SameSite=Strict on the session cookie is a second, independent layer.
"""
import hmac
import secrets

from flask import abort, current_app, request, session


def get_token():
    if current_app.config["MODE"] != "secure":
        return ""  # VULNERABLE: no CSRF protection
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def protect():
    """before_request hook: reject state-changing requests without a valid token."""
    if current_app.config["MODE"] != "secure":
        return
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    sent = request.form.get("csrf_token", "")
    expected = session.get("_csrf", "")
    # compare_digest: constant-time comparison, no timing side channel.
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400)
