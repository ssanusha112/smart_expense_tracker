import io
import hmac
import json
import sqlite3
import tempfile
import unittest
import uuid
import hashlib
from contextlib import closing
from http.cookies import SimpleCookie
from pathlib import Path
from unittest.mock import patch

import server


class ExpenseTrackerSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test-expenses.db"
        self.database_patch = patch.object(server, "DATABASE", self.database_path)
        self.database_patch.start()
        self.key_patch = patch.object(server, "TOTP_KEY_PATH", Path(self.temp_dir.name) / "test-totp.key")
        self.key_patch.start()
        server.initialize_db()
        self.remote_addr = "test-client-" + uuid.uuid4().hex
        status, headers, payload = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "DemoPass!2026",
        })
        self.assertEqual(status, 200, "demo login should work in the isolated test database")
        self.cookie = self.cookie_value(headers)
        self.csrf = payload.get("csrf_token", "")

    def tearDown(self):
        self.key_patch.stop()
        self.database_patch.stop()
        self.temp_dir.cleanup()

    def api(self, method, path, payload=None, *, raw_body=None, cookie=None,
            csrf=None, origin="http://127.0.0.1:8000", host="127.0.0.1:8000",
            scheme="http", remote_addr=None):
        if raw_body is None and payload is not None:
            body = json.dumps(payload).encode("utf-8")
        else:
            body = raw_body or b""
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "SERVER_NAME": "127.0.0.1",
            "SERVER_PORT": "8000",
            "wsgi.url_scheme": scheme,
            "wsgi.input": io.BytesIO(body),
            "wsgi.errors": io.StringIO(),
            "wsgi.version": (1, 0),
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "REMOTE_ADDR": remote_addr or self.remote_addr,
            "HTTP_HOST": host,
        }
        if method in ("POST", "PATCH", "DELETE"):
            environ["CONTENT_TYPE"] = "application/json"
            environ["CONTENT_LENGTH"] = str(len(body))
        if origin is not None:
            environ["HTTP_ORIGIN"] = origin
        if cookie:
            environ["HTTP_COOKIE"] = cookie
        if csrf is not None:
            environ["HTTP_X_CSRF_TOKEN"] = csrf
        response = {}

        def start_response(status_line, headers):
            response["status"] = int(status_line.split(" ", 1)[0])
            response["headers"] = dict(headers)
            response["headers_list"] = headers

        body_bytes = b"".join(server.application(environ, start_response))
        try:
            response_payload = json.loads(body_bytes) if body_bytes else None
        except (ValueError, UnicodeDecodeError):
            response_payload = None
        response["headers"]["_all"] = response["headers_list"]
        return response["status"], response["headers"], response_payload

    def cookie_value(self, headers, name="session"):
        cookie_header = next(
            (value for key, value in headers.get("_all", [])
             if key.lower() == "set-cookie" and value.startswith(name + "=")),
            headers.get("Set-Cookie", ""),
        )
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get(name)
        self.assertIsNotNone(morsel, "authentication should issue a session cookie")
        return name + "=" + morsel.value

    def mutate(self, method, path, payload=None, **kwargs):
        return self.api(method, path, payload, cookie=self.cookie, csrf=self.csrf, **kwargs)

    def enable_totp(self):
        status, _, setup = self.mutate("POST", "/api/security/totp/setup", {"password": "DemoPass!2026"})
        self.assertEqual(status, 200)
        secret = setup["secret"]
        status, _, confirmation = self.mutate("POST", "/api/security/totp/confirm", {
            "code": server.totp_code(secret),
        })
        self.assertEqual(status, 200)
        return secret, confirmation["recovery_codes"]

    def test_demo_login_sets_protected_cookie_and_security_headers(self):
        status, headers, payload = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "DemoPass!2026",
        })
        cookie = SimpleCookie()
        cookie.load(headers.get("Set-Cookie", ""))
        self.assertEqual(status, 200)
        self.assertTrue(bool(payload.get("csrf_token")), "login should return a CSRF token")
        self.assertTrue(cookie["session"]["httponly"], "session cookie must be HttpOnly")
        self.assertEqual(cookie["session"]["samesite"], "Lax")
        self.assertIn("object-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "same-origin")

    def test_static_files_receive_security_headers(self):
        status, headers, _ = self.api("GET", "/", origin=None)
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_static_404_responses_receive_security_headers(self):
        status, headers, _ = self.api("GET", "/missing-static-resource", origin=None)
        self.assertEqual(status, 404)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_server_errors_do_not_expose_exception_details(self):
        with patch.object(server, "connect_db", side_effect=sqlite3.OperationalError("private database path")):
            status, headers, payload = self.api("GET", "/api/security/summary", cookie=self.cookie)
        self.assertEqual(status, 500)
        self.assertEqual(payload["error"], "The database could not complete this request.")
        self.assertNotIn("private", payload["error"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_session_rotates_and_previous_cookie_is_revoked(self):
        old_cookie = self.cookie
        status, headers, _ = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "DemoPass!2026",
        }, cookie=old_cookie)
        new_cookie = self.cookie_value(headers)
        self.assertEqual(status, 200)
        self.assertNotEqual(old_cookie, new_cookie, "successful re-authentication should rotate the session")
        old_status, _, _ = self.api("GET", "/api/bootstrap", cookie=old_cookie)
        new_status, _, _ = self.api("GET", "/api/bootstrap", cookie=new_cookie)
        self.assertEqual(old_status, 401, "the previous session must no longer be usable")
        self.assertEqual(new_status, 200)
        with closing(sqlite3.connect(self.database_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 1)

    def test_expired_session_is_rejected(self):
        cookie = SimpleCookie()
        cookie.load(self.cookie)
        token_hash = hashlib.sha256(cookie["session"].value.encode("ascii")).hexdigest()
        with closing(sqlite3.connect(self.database_path)) as db:
            db.execute("UPDATE sessions SET expires_at = 0 WHERE token_hash = ?", (token_hash,))
            db.commit()
        status, _, payload = self.api("GET", "/api/bootstrap", cookie=self.cookie)
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "Sign in to continue.")

    def test_login_and_registration_require_matching_local_origin(self):
        payload = {"email": "demo@example.com", "password": "DemoPass!2026"}
        status, _, _ = self.api("POST", "/api/login", payload, origin=None)
        self.assertEqual(status, 403)
        status, _, _ = self.api("POST", "/api/login", payload, origin="https://attacker.example")
        self.assertEqual(status, 403)
        registration = {"name": "Casey Example", "email": "casey@example.test", "password": "LongEnough!2026"}
        status, _, _ = self.api("POST", "/api/register", registration, host="attacker.example:8000",
                                origin="http://attacker.example:8000")
        self.assertEqual(status, 403, "non-local Host values should be rejected")

    def test_registration_creates_separate_account_and_session(self):
        registration = {"name": "Casey Example", "email": "casey@example.test", "password": "LongEnough!2026"}
        status, headers, payload = self.api("POST", "/api/register", registration)
        self.assertEqual(status, 200)
        self.assertTrue(bool(payload.get("csrf_token")))
        cookie = self.cookie_value(headers)
        status, _, account = self.api("GET", "/api/bootstrap", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(account["user"]["email"], "casey@example.test")
        self.assertEqual(account["transactions"], [])

    def test_mutating_routes_reject_missing_and_invalid_csrf(self):
        _, _, account = self.api("GET", "/api/bootstrap", cookie=self.cookie)
        transaction_id = account["transactions"][0]["id"]
        payload = {"title": "Test expense", "amount": "12.34", "kind": "expense", "category": "Food", "date": "2026-10-09", "note": ""}
        mutations = [
            ("POST", "/api/transactions", payload),
            ("PATCH", f"/api/transactions/{transaction_id}", {"title": "Changed"}),
            ("DELETE", f"/api/transactions/{transaction_id}", {}),
            ("PATCH", "/api/budget", {"amount": "2000"}),
            ("POST", "/api/logout", {}),
        ]
        for method, path, body in mutations:
            with self.subTest(method=method, path=path):
                status, _, _ = self.api(method, path, body, cookie=self.cookie)
                self.assertEqual(status, 403)
                status, _, _ = self.api(method, path, body, cookie=self.cookie, csrf="invalid-token")
                self.assertEqual(status, 403)

    def test_transaction_and_budget_inputs_are_validated(self):
        valid = {"title": "Validation test", "amount": "12.34", "kind": "expense", "category": "Food", "date": "2026-10-09", "note": ""}
        invalid_values = [
            {**valid, "amount": "0"},
            {**valid, "amount": "1.239"},
            {**valid, "date": "not-a-date"},
            {**valid, "title": " "},
            {**valid, "title": 42},
            {**valid, "category": "Food' OR 1=1 --"},
            {**valid, "category": []},
            {**valid, "kind": "transfer"},
            {**valid, "note": 17},
            {**valid, "user_id": 1},
        ]
        for payload in invalid_values:
            with self.subTest(field=next(key for key in payload if payload[key] != valid.get(key))):
                status, _, _ = self.mutate("POST", "/api/transactions", payload)
                self.assertEqual(status, 400)
        for amount in ("0", "not-a-number", "1000001"):
            status, _, _ = self.mutate("PATCH", "/api/budget", {"amount": amount})
            self.assertEqual(status, 400)
        status, _, _ = self.mutate("PATCH", "/api/budget", {"amount": "2000", "user_id": 1})
        self.assertEqual(status, 400)

    def test_transaction_crud_and_budget_changes_persist(self):
        payload = {"title": "Persistence check", "amount": "23.45", "kind": "expense", "category": "Food", "date": "2026-10-09", "note": "initial"}
        status, _, created = self.mutate("POST", "/api/transactions", payload)
        self.assertEqual(status, 201)
        transaction_id = created["transaction"]["id"]
        status, _, changed = self.mutate("PATCH", f"/api/transactions/{transaction_id}", {
            "title": "Persisted update", "amount": "24.50", "note": "edited",
        })
        self.assertEqual(status, 200)
        self.assertEqual(changed["transaction"]["amount_cents"], 2450)
        status, _, budget = self.mutate("PATCH", "/api/budget", {"amount": "2100.00"})
        self.assertEqual(status, 200)
        status, _, loaded = self.api("GET", "/api/bootstrap", cookie=self.cookie)
        self.assertEqual(status, 200)
        self.assertEqual(loaded["budget_cents"], 210000)
        self.assertIn("Persisted update", [item["title"] for item in loaded["transactions"]])
        status, _, _ = self.mutate("DELETE", f"/api/transactions/{transaction_id}", {})
        self.assertEqual(status, 200)
        status, _, after_delete = self.api("GET", "/api/bootstrap", cookie=self.cookie)
        self.assertEqual(status, 200)
        self.assertNotIn(transaction_id, [item["id"] for item in after_delete["transactions"]])
        self.assertEqual(after_delete["budget_cents"], budget["budget_cents"])

    def test_malformed_duplicate_and_oversized_json_are_rejected(self):
        status, _, _ = self.api("POST", "/api/login", raw_body=b"{", remote_addr=uuid.uuid4().hex)
        self.assertEqual(status, 400)
        duplicate = b'{"email":"first@example.test","email":"second@example.test","password":"LongEnough!2026"}'
        status, _, _ = self.api("POST", "/api/login", raw_body=duplicate, remote_addr=uuid.uuid4().hex)
        self.assertEqual(status, 400)
        oversized = b" " * (server.MAX_BODY_BYTES + 1)
        status, _, _ = self.api("POST", "/api/login", raw_body=oversized, remote_addr=uuid.uuid4().hex)
        self.assertEqual(status, 413)

    def test_user_cannot_read_or_change_another_users_records_or_budget(self):
        _, _, owner_data = self.api("GET", "/api/bootstrap", cookie=self.cookie)
        owner_id = owner_data["transactions"][0]["id"]
        registration = {"name": "Taylor Example", "email": "taylor@example.test", "password": "Another!Long2026"}
        _, owner_headers, owner_session = self.api("POST", "/api/register", registration)
        other_cookie = self.cookie_value(owner_headers)
        other_csrf = owner_session["csrf_token"]
        status, _, other_data = self.api("GET", "/api/bootstrap", cookie=other_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(other_data["transactions"], [])
        for method, payload in (("PATCH", {"title": "stolen"}), ("DELETE", {})):
            status, _, _ = self.api(method, f"/api/transactions/{owner_id}", payload,
                                    cookie=other_cookie, csrf=other_csrf)
            self.assertEqual(status, 404)
        status, _, _ = self.api("PATCH", "/api/budget", {"amount": "123.45"},
                                cookie=other_cookie, csrf=other_csrf)
        self.assertEqual(status, 200)
        _, _, owner_after = self.api("GET", "/api/bootstrap", cookie=self.cookie)
        _, _, other_after = self.api("GET", "/api/bootstrap", cookie=other_cookie)
        self.assertEqual(owner_after["budget_cents"], 180000)
        self.assertEqual(other_after["budget_cents"], 12345)
        self.assertEqual(len(owner_after["transactions"]), 10)

    def test_sql_injection_is_treated_as_data(self):
        injection = "demo@example.com' OR 1=1 --"
        status, _, _ = self.api("POST", "/api/login", {
            "email": injection, "password": "DemoPass!2026",
        })
        self.assertEqual(status, 401)
        title = "Lunch'); DROP TABLE transactions; --"
        payload = {"title": title, "amount": "1.00", "kind": "expense", "category": "Food", "date": "2026-10-09", "note": ""}
        status, _, created = self.mutate("POST", "/api/transactions", payload)
        self.assertEqual(status, 201)
        _, _, account = self.api("GET", "/api/bootstrap", cookie=self.cookie)
        self.assertIn(title, [item["title"] for item in account["transactions"]])
        self.assertEqual(len(account["transactions"]), 11)

    def test_frontend_escapes_untrusted_values_and_keeps_csv_export(self):
        source = (server.PUBLIC / "app.js").read_text(encoding="utf-8")
        self.assertIn("const escapeText = value =>", source)
        self.assertIn("escapeText(item.title)", source)
        self.assertIn("escapeText(item.note)", source)
        self.assertIn("escapeText(item.category)", source)
        self.assertIn("escapeText(state.user.name.split(' ')[0])", source)
        self.assertIn("function exportCsv()", source)
        self.assertIn("function renderOverview()", source)

    def test_rate_limits_are_separate_by_ip_and_registration_action(self):
        client = uuid.uuid4().hex
        for _ in range(server._rate_limits["register"][1]):
            status, _, _ = self.api("POST", "/api/register", raw_body=b"{}", remote_addr=client)
            self.assertEqual(status, 400)
        status, _, _ = self.api("POST", "/api/register", raw_body=b"{}", remote_addr=client)
        self.assertEqual(status, 429)
        status, _, _ = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "DemoPass!2026",
        }, remote_addr=client)
        self.assertEqual(status, 200, "registration throttling must not lock out login")

        login_client = uuid.uuid4().hex
        for _ in range(server._rate_limits["login"][1]):
            status, _, _ = self.api("POST", "/api/login", {
                "email": "demo@example.com", "password": "incorrect-password",
            }, remote_addr=login_client)
            self.assertEqual(status, 401)
        status, _, _ = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "incorrect-password",
        }, remote_addr=login_client)
        self.assertEqual(status, 429)
        status, _, _ = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "DemoPass!2026",
        }, remote_addr=uuid.uuid4().hex)
        self.assertEqual(status, 200, "a failed-login threshold must not lock the account itself")

    def test_https_cookie_gets_secure_attribute(self):
        status, headers, _ = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "DemoPass!2026",
        }, host="localhost:8000", origin="https://localhost:8000", scheme="https")
        self.assertEqual(status, 200)
        cookie = SimpleCookie()
        cookie.load(headers.get("Set-Cookie", ""))
        self.assertTrue(cookie["session"]["secure"], "HTTPS sessions should set Secure")

    def test_audit_events_omit_financial_details_and_are_account_scoped(self):
        payload = {"title": "Private title", "amount": "456.78", "kind": "expense", "category": "Food", "date": "2026-10-09", "note": "Private note"}
        status, _, created = self.mutate("POST", "/api/transactions", payload)
        self.assertEqual(status, 201)
        transaction_id = created["transaction"]["id"]
        status, _, _ = self.mutate("PATCH", f"/api/transactions/{transaction_id}", {"title": "Changed title"})
        self.assertEqual(status, 200)
        status, _, _ = self.mutate("DELETE", f"/api/transactions/{transaction_id}", {})
        self.assertEqual(status, 200)
        status, _, _ = self.mutate("PATCH", "/api/budget", {"amount": "1900"})
        self.assertEqual(status, 200)
        status, _, summary = self.api("GET", "/api/security/summary", cookie=self.cookie)
        self.assertEqual(status, 200)
        types = [event["event_type"] for event in summary["events"]]
        self.assertTrue({"login.success", "transaction.created", "transaction.updated", "transaction.deleted", "budget.updated"}.issubset(types))
        status, _, _ = self.mutate("POST", "/api/logout", {})
        self.assertEqual(status, 200)
        with closing(sqlite3.connect(self.database_path)) as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(security_events)")}
            self.assertEqual(columns, {"id", "user_id", "event_type", "severity", "occurred_at"})
            owner_id = db.execute("SELECT id FROM users WHERE email = ?", ("demo@example.com",)).fetchone()[0]
            events = {row[0] for row in db.execute("SELECT event_type FROM security_events WHERE user_id = ?", (owner_id,))}
            count = len(events)
            self.assertGreaterEqual(count, 5)
            self.assertIn("logout", events)

    def test_repeated_failed_signins_create_account_scoped_alert(self):
        client = uuid.uuid4().hex
        for _ in range(5):
            status, _, _ = self.api("POST", "/api/login", {
                "email": "demo@example.com", "password": "wrong-password-value",
            }, remote_addr=client)
            self.assertEqual(status, 401)
        status, _, summary = self.api("GET", "/api/security/summary", cookie=self.cookie)
        self.assertEqual(status, 200)
        self.assertEqual(summary["failed_login_24h"], 5)
        alert = next((item for item in summary["alerts"] if item["alert_type"] == "repeated_login_failures"), None)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "warning")
        self.assertIn("15 minutes", alert["summary"])
        status, _, _ = self.mutate("POST", f"/api/security/alerts/{alert['id']}/acknowledge", {})
        self.assertEqual(status, 200)
        status, _, reviewed = self.api("GET", "/api/security/summary", cookie=self.cookie)
        self.assertEqual(status, 200)
        self.assertEqual(reviewed["open_alerts"], 0)
        self.assertIsNotNone(reviewed["alerts"][0]["acknowledged_at"])

    def test_repeated_rejected_csrf_requests_create_security_alert(self):
        for _ in range(5):
            status, _, _ = self.api("PATCH", "/api/budget", {"amount": "1800"},
                                    cookie=self.cookie, csrf="invalid-token")
            self.assertEqual(status, 403)
        status, _, summary = self.api("GET", "/api/security/summary", cookie=self.cookie)
        self.assertEqual(status, 200)
        self.assertIn("request.csrf_rejected", [event["event_type"] for event in summary["events"]])
        self.assertIn("repeated_rejected_requests", [alert["alert_type"] for alert in summary["alerts"]])

    def test_security_events_and_alerts_are_private_to_each_account(self):
        for _ in range(5):
            self.api("POST", "/api/login", {
                "email": "demo@example.com", "password": "incorrect-password",
            }, remote_addr=uuid.uuid4().hex)
        _, _, owner_summary = self.api("GET", "/api/security/summary", cookie=self.cookie)
        owner_alert = next(item for item in owner_summary["alerts"] if item["alert_type"] == "repeated_login_failures")
        registration = {"name": "Morgan Tester", "email": "morgan@example.test", "password": "ASeparate!Pass2026"}
        status, headers, new_account = self.api("POST", "/api/register", registration)
        self.assertEqual(status, 200)
        other_cookie = self.cookie_value(headers)
        status, _, _ = self.api("POST", f"/api/security/alerts/{owner_alert['id']}/acknowledge", {},
                                cookie=other_cookie, csrf=new_account["csrf_token"])
        self.assertEqual(status, 404)
        status, _, other_summary = self.api("GET", "/api/security/summary", cookie=other_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(other_summary["failed_login_24h"], 0)
        self.assertEqual(other_summary["alerts"], [])
        self.assertNotIn("login.failure", [event["event_type"] for event in other_summary["events"]])

    def test_totp_rfc6238_code_and_window_validation(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertEqual(server.totp_code(secret, 59), "287082")
        self.assertTrue(server.verify_totp(secret, "287082", 59))
        self.assertFalse(server.verify_totp(secret, "287083", 59))
        self.assertFalse(server.verify_totp(secret, "12x456", 59))

    def test_totp_secret_is_encrypted_and_enrollment_returns_one_time_recovery_codes(self):
        status, _, setup = self.mutate("POST", "/api/security/totp/setup", {"password": "DemoPass!2026"})
        self.assertEqual(status, 200)
        secret = setup["secret"]
        self.assertTrue(setup["otpauth_uri"].startswith("otpauth://totp/"))
        with closing(sqlite3.connect(self.database_path)) as db:
            pending = db.execute("SELECT totp_pending_encrypted FROM users WHERE email = ?", ("demo@example.com",)).fetchone()[0]
            self.assertIsNotNone(pending)
            self.assertNotIn(secret.encode("ascii"), bytes(pending), "TOTP secret must not be stored in plaintext")
            decrypted = server.get_totp_cipher().decrypt(bytes(pending)).decode("ascii")
            self.assertTrue(hmac.compare_digest(decrypted, secret), "encrypted TOTP secret should round-trip")
        status, _, confirmed = self.mutate("POST", "/api/security/totp/confirm", {"code": server.totp_code(secret)})
        self.assertEqual(status, 200)
        self.assertEqual(len(confirmed["recovery_codes"]), 10)
        with closing(sqlite3.connect(self.database_path)) as db:
            enabled, stored_secret, pending_secret, hashes_json = db.execute(
                "SELECT totp_enabled, totp_secret_encrypted, totp_pending_encrypted, totp_recovery_hashes FROM users WHERE email = ?",
                ("demo@example.com",),
            ).fetchone()
            self.assertEqual(enabled, 1)
            self.assertIsNotNone(stored_secret)
            self.assertIsNone(pending_secret)
            self.assertNotIn(confirmed["recovery_codes"][0], hashes_json)
            self.assertEqual(len(json.loads(hashes_json)), 10)

    def test_totp_login_uses_recovery_codes_once_and_can_be_disabled(self):
        secret, recovery_codes = self.enable_totp()
        status, headers, challenge = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "DemoPass!2026",
        }, remote_addr=uuid.uuid4().hex)
        self.assertEqual(status, 200)
        self.assertTrue(challenge["requires_totp"])
        challenge_cookie = self.cookie_value(headers, "login_challenge")
        status, headers, completed = self.api("POST", "/api/login/totp", {"code": recovery_codes[0]},
                                              cookie=challenge_cookie, csrf=challenge["csrf_token"],
                                              remote_addr=uuid.uuid4().hex)
        self.assertEqual(status, 200)
        new_cookie = self.cookie_value(headers)
        status, _, _ = self.api("GET", "/api/bootstrap", cookie=new_cookie)
        self.assertEqual(status, 200)

        status, headers, second_challenge = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "DemoPass!2026",
        }, remote_addr=uuid.uuid4().hex)
        self.assertEqual(status, 200)
        status, _, _ = self.api("POST", "/api/login/totp", {"code": recovery_codes[0]},
                                cookie=self.cookie_value(headers, "login_challenge"),
                                csrf=second_challenge["csrf_token"], remote_addr=uuid.uuid4().hex)
        self.assertEqual(status, 401, "a consumed recovery code must not work again")

        status, _, disabled = self.mutate("POST", "/api/security/totp/disable", {
            "password": "DemoPass!2026", "code": server.totp_code(secret),
        })
        self.assertEqual(status, 200)
        status, _, summary = self.api("GET", "/api/security/summary", cookie=self.cookie)
        self.assertEqual(status, 200)
        self.assertFalse(summary["totp_enabled"])
        with closing(sqlite3.connect(self.database_path)) as db:
            events = {row[0] for row in db.execute("SELECT event_type FROM security_events")}
        self.assertIn("totp.enabled", events)
        self.assertIn("totp.disabled", events)

    def test_totp_login_challenge_expires_after_five_failed_codes(self):
        secret, _ = self.enable_totp()
        status, headers, challenge = self.api("POST", "/api/login", {
            "email": "demo@example.com", "password": "DemoPass!2026",
        }, remote_addr=uuid.uuid4().hex)
        self.assertEqual(status, 200)
        self.assertTrue(challenge["requires_totp"])
        challenge_cookie = self.cookie_value(headers, "login_challenge")
        current_code = server.totp_code(secret)
        wrong_code = "000000" if current_code != "000000" else "000001"
        for attempt in range(5):
            status, _, result = self.api("POST", "/api/login/totp", {"code": wrong_code},
                                         cookie=challenge_cookie, csrf=challenge["csrf_token"],
                                         remote_addr=uuid.uuid4().hex)
            self.assertEqual(status, 401)
            if attempt == 4:
                self.assertIn("challenge expired", result["error"].lower())


if __name__ == "__main__":
    unittest.main()