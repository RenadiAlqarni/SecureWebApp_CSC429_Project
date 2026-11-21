"""
Bastion - application factory.

The same code base runs in two modes so every vulnerability can be shown
next to its fix:

    vulnerable  -> the "before" build. Five classic weaknesses are switched on
                   (SQL injection, MD5 passwords, stored XSS, broken access
                   control, readable session cookie over plain HTTP).
    secure      -> the "after" build. Each weakness is mitigated, plus extra
                   hardening (CSRF tokens, security headers, login throttling,
                   server-side session revocation).

Every place where the two modes differ is marked in the code with
`# VULNERABLE:` and `# SECURE:` comments so a reviewer can compare them
side by side.
"""
import os
from datetime import timedelta

from cryptography.fernet import Fernet
from flask import Flask, g, render_template

from . import db
from .security import csrf, headers
from .security.crypto import FieldCipher, PlaintextCipher
from .security.keys import load_or_create_key
from .security.ratelimit import LoginThrottle
from .security.session import EncryptedCookieSessionInterface, load_logged_in_user

MODES = ("secure", "vulnerable")


def create_app(mode="secure", database=None, reset_db=False, testing=False):
    """Build a Flask app configured for `mode` ("secure" or "vulnerable")."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")

    app = Flask(__name__)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.update(
        MODE=mode,
        TESTING=testing,
        # Each mode gets its own database so MD5 rows and bcrypt rows never mix.
        DATABASE=database or os.path.join(app.instance_path, f"{mode}.db"),
        # The SQL inspector shows the query that ran after a login/registration.
        # It is a teaching aid for the demo; set BASTION_SQL_INSPECTOR=0 to hide it.
        SQL_INSPECTOR=os.environ.get("BASTION_SQL_INSPECTOR", "1") != "0",
        MAX_CONTENT_LENGTH=64 * 1024,  # reject oversized request bodies
    )

    if mode == "secure":
        _configure_secure(app)
    else:
        _configure_vulnerable(app)

    # --- database -----------------------------------------------------------
    db.init_app(app)
    with app.app_context():
        db.init_db(reset=reset_db)

    # --- request lifecycle hooks ---------------------------------------------
    app.before_request(load_logged_in_user)   # who is logged in? (session check)
    app.before_request(csrf.protect)          # CSRF check on POST (secure mode)
    app.after_request(headers.apply)          # cache + security headers

    # --- blueprints -----------------------------------------------------------
    from .routes import admin, auth, main

    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(admin.bp)

    # --- template helpers -----------------------------------------------------
    @app.context_processor
    def inject_globals():
        return {
            "mode": app.config["MODE"],
            "secure_mode": app.config["MODE"] == "secure",
            "csrf_token": csrf.get_token,
            "current_user": g.get("user"),
        }

    _register_error_pages(app)
    return app


def _configure_secure(app):
    """SECURE: random keys, encrypted + hardened session cookie."""
    instance = app.instance_path
    app.config.update(
        # Random 256-bit key generated on first run and kept out of git.
        SECRET_KEY=load_or_create_key(
            os.path.join(instance, "secret.key"), lambda: os.urandom(32).hex().encode(),
            env="BASTION_SECRET_KEY",
        ),
        # "__Host-" prefix: browser only accepts it over HTTPS, with Path=/
        # and no Domain attribute, so a sub-domain cannot overwrite it.
        SESSION_COOKIE_NAME="__Host-bastion_session",
        SESSION_COOKIE_SECURE=True,      # only sent over HTTPS
        SESSION_COOKIE_HTTPONLY=True,    # JavaScript (and XSS) cannot read it
        SESSION_COOKIE_SAMESITE="Strict",  # not sent on cross-site requests (CSRF)
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # idle timeout
    )

    # Two separate keys (key separation): one for session cookies, one for
    # data at rest. Leaking one does not expose the other.
    session_key = load_or_create_key(
        os.path.join(instance, "session.key"), Fernet.generate_key, env="BASTION_SESSION_KEY"
    )
    data_key = load_or_create_key(
        os.path.join(instance, "data.key"), Fernet.generate_key, env="BASTION_DATA_KEY"
    )

    lifetime = int(app.config["PERMANENT_SESSION_LIFETIME"].total_seconds())
    app.session_interface = EncryptedCookieSessionInterface(Fernet(session_key), lifetime)
    app.extensions["field_cipher"] = FieldCipher(Fernet(data_key))
    app.extensions["login_throttle"] = LoginThrottle(max_attempts=5, window_seconds=300)


def _configure_vulnerable(app):
    """VULNERABLE: weak, hard-coded key and a readable, script-accessible cookie."""
    app.config.update(
        # VULNERABLE: guessable secret committed to source control. Anyone who
        # knows it can forge a session cookie (e.g. with flask-unsign).
        SECRET_KEY="dev",
        SESSION_COOKIE_NAME="session",
        SESSION_COOKIE_SECURE=False,     # VULNERABLE: cookie travels over plain HTTP
        SESSION_COOKIE_HTTPONLY=False,   # VULNERABLE: document.cookie can steal it via XSS
        SESSION_COOKIE_SAMESITE=None,
        PERMANENT_SESSION_LIFETIME=timedelta(days=31),
    )
    # VULNERABLE: Flask's default cookie is only *signed*, not encrypted, so the
    # payload (user id, username, role) is readable by anyone holding it.
    app.extensions["field_cipher"] = PlaintextCipher()   # email stored as plain text
    app.extensions["login_throttle"] = None              # unlimited password guessing


def _register_error_pages(app):
    messages = {
        400: ("Request rejected", "The form was missing its security token or contained invalid data. Go back, reload the page and try again."),
        403: ("You don't have access to this page", "This page is for administrators. Your account has the standard user role."),
        404: ("Page not found", "Check the address, or go back to your dashboard."),
        413: ("Request too large", "Shorten what you entered and try again."),
        429: ("Too many attempts", "Wait a few minutes before trying again."),
    }

    def make_handler(code):
        title, body = messages[code]

        def handler(_error):
            return render_template("errors/error.html", code=code, title=title, body=body), code

        return handler

    for code in messages:
        app.register_error_handler(code, make_handler(code))
