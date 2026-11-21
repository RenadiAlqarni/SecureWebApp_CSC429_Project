"""Landing page, dashboard, comments and the security lab guide."""
from flask import (Blueprint, current_app, flash, g, redirect, render_template,
                   request, url_for)

from .. import models
from ..security.access import login_required
from ..security.sanitize import MAX_COMMENT_LENGTH, sanitize_comment
from ..security.session import active_session_count

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        profile=models.profile(g.user),
        comments=models.list_comments(),
        sessions=active_session_count(g.user["id"]),
        max_comment=MAX_COMMENT_LENGTH,
    )


@bp.post("/comments")
@login_required
def post_comment():
    raw = request.form.get("body", "")

    if current_app.config["MODE"] == "secure":
        # SECURE: strip all markup on input; templates escape on output as well.
        body = sanitize_comment(raw)
    else:
        # VULNERABLE (stored XSS): saved exactly as typed and later printed
        # with |safe, so <script> tags run in every visitor's browser.
        body = raw.strip()

    if not body:
        flash("Write something before posting. HTML tags are removed, so a comment made only of tags is empty.", "error")
    else:
        models.add_comment(g.user["id"], body)
        flash("Comment posted.", "success")
    return redirect(url_for("main.dashboard") + "#guestbook")


@bp.route("/lab")
def lab():
    return render_template("lab.html")
