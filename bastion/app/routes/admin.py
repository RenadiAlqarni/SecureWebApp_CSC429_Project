"""Admin area: user roles and comment moderation. Protected by RBAC."""
from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, request, url_for)

from .. import models
from ..security.access import role_required
from ..security.passwords import describe_hash

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@role_required("admin")
def panel():
    users = models.list_users()
    for u in users:
        u["hash_kind"] = describe_hash(u["password_hash"])
        if current_app.config["MODE"] == "secure":
            u.pop("password_hash")  # SECURE: hashes never leave the database
    return render_template("admin/panel.html", users=users, comments=models.list_comments())


@bp.post("/users/<int:user_id>/role")
@role_required("admin")
def change_role(user_id):
    role = request.form.get("role", "")
    target = models.get_user(user_id)
    if target is None:
        abort(404)

    if current_app.config["MODE"] == "secure":
        # SECURE: keep at least one administrator so the site cannot be locked out.
        if target["role"] == "admin" and role != "admin" and models.count_admins() <= 1:
            flash("Keep at least one administrator. Promote someone else first.", "error")
            return redirect(url_for("admin.panel"))

    try:
        models.set_role(user_id, role)
    except models.ValidationError as exc:
        flash(exc.messages[0], "error")
        return redirect(url_for("admin.panel"))

    current_app.logger.info("%s set role of %s to %s", g.user["username"], target["username"], role)
    flash(f"{target['username']} is now {'an admin' if role == 'admin' else 'a standard user'}.", "success")
    return redirect(url_for("admin.panel"))


@bp.post("/comments/<int:comment_id>/delete")
@role_required("admin")
def delete_comment(comment_id):
    models.delete_comment(comment_id)
    flash("Comment deleted.", "success")
    return redirect(url_for("admin.panel") + "#moderation")
