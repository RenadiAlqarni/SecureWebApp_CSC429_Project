"""
Automated attack suite: every attack is run against BOTH builds.

    python -m unittest -v

For each vulnerability the vulnerable build must FALL to the attack and the
secure build must RESIST it. If a test in VulnerableBuildTests fails, the demo
weakness is gone; if a test in SecureBuildTests fails, a fix is broken.
The results of this suite fill the testing table in SECURITY_REPORT.md.
"""
import base64
import json
import os
import re
import sqlite3
import tempfile
import unittest
import zlib

from app import create_app

ADMIN_PW = "Admin@2026!"
ALICE_PW = "Alice@2026!"
STRONG_PW = "Str0ng!Pass"
XSS = "<script>alert(document.cookie)</script>"


class SharedBuildTests:
    """Tests both builds must pass. Mixed into the two TestCase classes below."""

    mode = None
    base_url = None

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.environ["BASTION_SQL_INSPECTOR"] = "1"
        self.app = create_app(self.mode, database=self.db_path, reset_db=True, testing=True)
        self.client = self.app.test_client()

    def tearDown(self):
        os.remove(self.db_path)

    # -- helpers -------------------------------------------------------------
    def get(self, path, **kw):
        return self.client.get(path, base_url=self.base_url, **kw)

    def post(self, path, data=None, with_csrf=True, **kw):
        data = dict(data or {})
        if with_csrf and self.mode == "secure":
            data.setdefault("csrf_token", self.csrf())
        return self.client.post(path, data=data, base_url=self.base_url, **kw)

    def csrf(self):
        """Read the CSRF token from a rendered form, like a real browser would."""
        for page in ("/dashboard", "/login"):
            html = self.get(page).get_data(as_text=True)
            match = re.search(r'name="csrf_token" value="([^"]+)"', html)
            if match:
                return match.group(1)
        return ""

    def login(self, username, password):
        return self.post("/login", {"username": username, "password": password})

    def register(self, username, password, full_name="", email=""):
        return self.post("/register", {"username": username, "password": password,
                                       "confirm": password, "full_name": full_name, "email": email})

    def logout(self):
        return self.post("/logout")

    def db_row(self, sql, params=()):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(sql, params).fetchone()
        finally:
            conn.close()

    def session_cookie(self):
        return self.client.get_cookie(self.app.config["SESSION_COOKIE_NAME"])

    # -- functional tests shared by both builds ------------------------------
    def test_register_login_dashboard_logout(self):
        self.assertEqual(self.register("bob", STRONG_PW, "Bob Builder", "bob@example.com").status_code, 302)
        r = self.login("bob", STRONG_PW)
        self.assertEqual(r.status_code, 302)
        page = self.get("/dashboard").get_data(as_text=True)
        self.assertIn("bob", page)
        self.assertIn("bob@example.com", page)
        self.logout()
        r = self.get("/dashboard")
        self.assertEqual(r.status_code, 302, "dashboard must not be reachable after logout")
        self.assertIn("/login", r.headers["Location"])

    def test_dashboard_is_not_cacheable(self):
        self.login("alice", ALICE_PW)
        r = self.get("/dashboard")
        self.assertIn("no-store", r.headers["Cache-Control"])


class VulnerableBuildTests(SharedBuildTests, unittest.TestCase):
    mode = "vulnerable"
    base_url = "http://localhost"

    def test_sqli_login_bypass_works(self):
        r = self.login("admin' --", "wrong password")
        self.assertEqual(r.status_code, 302)
        self.assertIn("admin", self.get("/dashboard").get_data(as_text=True))

    def test_sqli_always_true_condition_works(self):
        self.assertEqual(self.login("' OR '1'='1' --", "x").status_code, 302)
        self.assertIn("admin", self.get("/dashboard").get_data(as_text=True))

    def test_sql_error_details_leak(self):
        r = self.login("'", "x")
        self.assertEqual(r.status_code, 500)
        self.assertIn("Database error", r.get_data(as_text=True))

    def test_old_cookie_still_works_after_logout(self):
        self.login("alice", ALICE_PW)
        stolen = self.session_cookie().value
        self.logout()
        self.client.set_cookie("session", stolen)
        self.assertEqual(self.get("/dashboard").status_code, 200)  # cannot be revoked

    def test_sqli_register_privilege_escalation_works(self):
        self.register("mallory", "x", full_name="Mallory', 'admin')--")
        self.assertEqual(self.db_row("SELECT role FROM users WHERE username='mallory'")["role"], "admin")

    def test_passwords_stored_as_md5_and_no_policy(self):
        self.assertEqual(self.register("weak", "123").status_code, 302)
        h = self.db_row("SELECT password_hash FROM users WHERE username='weak'")["password_hash"]
        self.assertEqual(h, "202cb962ac59075b964b07152d234b70")  # md5("123")

    def test_stored_xss_executes(self):
        self.login("alice", ALICE_PW)
        self.post("/comments", {"body": XSS})
        self.assertIn(XSS, self.get("/dashboard").get_data(as_text=True))
        self.assertNotIn("Content-Security-Policy", self.get("/dashboard").headers)

    def test_standard_user_reaches_admin_and_self_promotes(self):
        self.login("alice", ALICE_PW)
        self.assertEqual(self.get("/admin/").status_code, 200)
        alice_id = self.db_row("SELECT id FROM users WHERE username='alice'")["id"]
        self.post(f"/admin/users/{alice_id}/role", {"role": "admin"})
        self.assertEqual(self.db_row("SELECT role FROM users WHERE id=?", (alice_id,))["role"], "admin")

    def test_session_cookie_is_readable_and_unprotected(self):
        self.login("alice", ALICE_PW)
        cookie = self.session_cookie()
        payload = cookie.value.lstrip(".").split(".")[0]
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        if cookie.value.startswith("."):
            raw = zlib.decompress(raw)
        data = json.loads(raw)
        self.assertEqual(data["username"], "alice")
        self.assertFalse(cookie.http_only)
        self.assertFalse(cookie.secure)
        email = self.db_row("SELECT email FROM users WHERE username='alice'")["email"]
        self.assertEqual(email, "alice@bastion.local")  # plain text at rest


class SecureBuildTests(SharedBuildTests, unittest.TestCase):
    mode = "secure"
    base_url = "https://localhost"

    def test_sqli_login_bypass_blocked(self):
        r = self.login("admin' --", "wrong password")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.get("/dashboard").status_code, 302)

    def test_sqli_always_true_condition_blocked(self):
        self.assertEqual(self.login("' OR '1'='1' --", "x").status_code, 401)

    def test_sql_error_details_not_leaked(self):
        r = self.login("'", "x")
        self.assertEqual(r.status_code, 401)
        self.assertNotIn("Database error", r.get_data(as_text=True))

    def test_sqli_register_payload_stored_as_text(self):
        self.register("mallory", STRONG_PW, full_name="Mallory', 'admin')--")
        row = self.db_row("SELECT role, full_name FROM users WHERE username='mallory'")
        self.assertEqual(row["role"], "user")
        self.assertEqual(row["full_name"], "Mallory', 'admin')--")

    def test_password_policy_enforced(self):
        for weak in ["123", "password", "Password1", "password1!", "PASSWORD1!", "Pass!word"]:
            with self.subTest(password=weak):
                self.assertEqual(self.register("weak", weak).status_code, 400)
        self.assertIsNone(self.db_row("SELECT 1 FROM users WHERE username='weak'"))

    def test_passwords_stored_with_bcrypt(self):
        self.register("strong", STRONG_PW)
        h = self.db_row("SELECT password_hash FROM users WHERE username='strong'")["password_hash"]
        self.assertTrue(h.startswith("$2b$12$"), h)
        self.register("strong2", STRONG_PW)
        h2 = self.db_row("SELECT password_hash FROM users WHERE username='strong2'")["password_hash"]
        self.assertNotEqual(h, h2, "same password must give different hashes (salt)")

    def test_stored_xss_neutralised(self):
        self.login("alice", ALICE_PW)
        self.post("/comments", {"body": "hi " + XSS + " <img src=x onerror=alert(1)> a < b"})
        stored = self.db_row("SELECT body FROM comments")["body"]
        self.assertNotIn("<script", stored)
        self.assertNotIn("onerror", stored)
        r = self.get("/dashboard")
        html = r.get_data(as_text=True)
        self.assertNotIn("<script>alert", html)
        self.assertIn("a &lt; b", html)  # ordinary text survives, escaped
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])

    def test_standard_user_gets_403_on_admin(self):
        self.login("alice", ALICE_PW)
        self.assertEqual(self.get("/admin/").status_code, 403)
        alice_id = self.db_row("SELECT id FROM users WHERE username='alice'")["id"]
        self.assertEqual(self.post(f"/admin/users/{alice_id}/role", {"role": "admin"}).status_code, 403)
        self.assertEqual(self.db_row("SELECT role FROM users WHERE id=?", (alice_id,))["role"], "user")

    def test_admin_can_use_admin_page(self):
        self.login("admin", ADMIN_PW)
        self.assertEqual(self.get("/admin/").status_code, 200)

    def test_anonymous_redirected_from_admin(self):
        self.assertEqual(self.get("/admin/").status_code, 302)

    def test_session_cookie_encrypted_and_flagged(self):
        self.login("alice", ALICE_PW)
        cookie = self.session_cookie()
        self.assertTrue(cookie.value.startswith("gAAAAA"), "expected a Fernet token")
        self.assertNotIn(b"alice", base64.urlsafe_b64decode(cookie.value + "=" * (-len(cookie.value) % 4)))
        self.assertTrue(cookie.secure)
        self.assertTrue(cookie.http_only)
        self.assertEqual(cookie.same_site, "Strict")

    def test_tampered_cookie_rejected(self):
        self.login("alice", ALICE_PW)
        name = self.app.config["SESSION_COOKIE_NAME"]
        value = self.session_cookie().value
        flipped = value[:-6] + ("A" if value[-6] != "A" else "B") + value[-5:]
        self.client.set_cookie(name, flipped, secure=True)
        self.assertEqual(self.get("/dashboard").status_code, 302)

    def test_email_encrypted_at_rest(self):
        email = self.db_row("SELECT email FROM users WHERE username='alice'")["email"]
        self.assertTrue(email.startswith("gAAAAA"))
        self.assertNotIn("alice", email)

    def test_hsts_and_security_headers(self):
        h = self.get("/").headers
        self.assertIn("max-age=31536000", h["Strict-Transport-Security"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")

    def test_old_cookie_useless_after_logout(self):
        self.login("alice", ALICE_PW)
        name = self.app.config["SESSION_COOKIE_NAME"]
        stolen = self.session_cookie().value
        self.logout()
        self.client.set_cookie(name, stolen, secure=True)  # replay the pre-logout cookie
        self.assertEqual(self.get("/dashboard").status_code, 302)

    def test_csrf_token_required(self):
        self.login("alice", ALICE_PW)
        r = self.post("/comments", {"body": "forged"}, with_csrf=False)
        self.assertEqual(r.status_code, 400)
        self.assertIsNone(self.db_row("SELECT 1 FROM comments WHERE body='forged'"))

    def test_login_throttled_after_five_failures(self):
        for _ in range(5):
            self.assertEqual(self.login("alice", "wrong").status_code, 401)
        self.assertEqual(self.login("alice", ALICE_PW).status_code, 429)

    def test_session_regenerated_on_login(self):
        self.get("/login")
        before = self.session_cookie().value
        self.login("alice", ALICE_PW)
        self.assertNotEqual(before, self.session_cookie().value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
