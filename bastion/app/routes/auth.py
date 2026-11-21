"""Registration, login and logout."""
import sqlite3
from urllib.parse import urlsplit

from flask import (Blueprint, current_app, flash, g, redirect, render_template,
                   request, url_for)

from .. import models
from ..security import passwords
from ..security.access import login_required
from ..security.session import end_session, start_session

bp = Blueprint("auth", __name__)


def _secure():
    return current_app.config["MODE"] == "secure"


def _safe_next(target):
    """Only allow redirects to paths on this site (prevents open redirects)."""
    if not target:
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or not target.startswith("/") or target.startswith("//"):
        return None
    return target


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("main.dashboard"))

    form = {"username": "", "full_name": "", "email": ""}
    if request.method == "POST":
        form = {k: request.form.get(k, "") for k in form}
        if request.form.get("password", "") != request.form.get("confirm", ""):
            flash("The two passwords don't match.", "error")
            return render_template("auth/register.html", form=form, policy=passwords.POLICY), 400
        try:
            models.register_user(
                form["username"], request.form.get("password", ""),
                form["full_name"], form["email"],
            )
        except models.ValidationError as exc:
            for message in exc.messages:
                flash(message, "error")
            return render_template("auth/register.html", form=form, policy=passwords.POLICY), 400
        except sqlite3.Error as exc:
            # VULNERABLE only (secure queries cannot be broken by input): the raw
            # database error is shown, which helps an attacker shape the payload.
            flash(f"Database error: {exc}", "error")
            return render_template("auth/register.html", form=form, policy=passwords.POLICY), 500

        flash("Account created. Sign in with your new username and password.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form, policy=passwords.POLICY)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("main.dashboard"))

    username = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        throttle = current_app.extensions.get("login_throttle")
        throttle_key = f"{request.remote_addr}|{username.strip().lower()}"
        if throttle:  # SECURE: refuse when too many recent failures
            wait = throttle.retry_after(throttle_key)
            if wait:
                flash(f"Too many failed attempts for this account. Try again in {wait} seconds.", "error")
                return render_template("auth/login.html", username=username), 429

        try:
            user = models.authenticate(username, password)
        except sqlite3.Error as exc:
            flash(f"Database error: {exc}", "error")  # VULNERABLE only, see register()
            return render_template("auth/login.html", username=username), 500

        if user is None:
            if throttle:
                throttle.record_failure(throttle_key)
            # Same message for "no such user" and "wrong password", so the form
            # does not reveal which usernames exist.
            flash("Incorrect username or password.", "error")
            return render_template("auth/login.html", username=username), 401

        if throttle:
            throttle.reset(throttle_key)
        start_session(user)
        flash(f"Signed in as {user['username']}.", "success")
        return redirect(_safe_next(request.args.get("next")) or url_for("main.dashboard"))

    return render_template("auth/login.html", username=username)


@bp.post("/logout")
def logout():
    # POST only (with a CSRF token in secure mode): a link or image on another
    # site cannot log the user out.
    end_session()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))


@bp.post("/logout/everywhere")
@login_required
def logout_everywhere():
    end_session(everywhere=True)
    flash("Signed out on every device.", "success")
    return redirect(url_for("auth.login"))
