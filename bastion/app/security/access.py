"""
Authentication and role-based access control (RBAC) decorators.

Roles: "user" (standard account) and "admin". The full permission matrix is in
SECURITY_REPORT.md. Two rules make the secure version work:

  1. Checks run on the server for every request. Hiding the "Admin" link in
     the menu is not access control: anyone can type /admin into the address bar.
  2. The role is read from the database on every request (see
     session.load_logged_in_user), never from the cookie or the form, so a
     tampered cookie or a role demoted a minute ago takes effect immediately.
"""
from functools import wraps

from flask import abort, current_app, g, redirect, request, url_for


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles):
    """Allow the view only for logged-in users whose role is in `roles`."""

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if current_app.config["MODE"] == "vulnerable":
                # VULNERABLE (broken access control): only "is logged in" is
                # checked. The admin link is hidden for normal users, but any
                # logged-in user who visits /admin gets full admin powers.
                return view(*args, **kwargs)

            # SECURE: deny by default unless the role from the database matches.
            if g.user["role"] not in roles:
                current_app.logger.warning(
                    "Access denied: user %s (role %s) tried %s",
                    g.user["username"], g.user["role"], request.path,
                )
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
