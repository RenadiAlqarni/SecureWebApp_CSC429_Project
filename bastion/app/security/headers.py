"""
HTTP response headers.

Both modes: dynamic pages are sent with Cache-Control: no-store, so after
logout the browser cannot show a cached copy of the dashboard via the Back
button; it has to ask the server again, which redirects to the login page.

Secure mode adds browser-side defences:
  Content-Security-Policy  only scripts/styles from this site may run, so an
                           injected <script> or onerror= handler is blocked even
                           if escaping were ever missed (second XSS layer).
  Strict-Transport-Security  browser must use HTTPS for this host for a year.
  X-Frame-Options / frame-ancestors  page cannot be framed (clickjacking).
  X-Content-Type-Options   no MIME sniffing.
  Referrer-Policy          URLs are not leaked to other sites.
"""
from flask import current_app, request

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


def apply(response):
    if not request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    if current_app.config["MODE"] == "secure":
        response.headers["Content-Security-Policy"] = CSP
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return response
