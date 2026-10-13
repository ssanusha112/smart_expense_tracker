import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import struct
import threading
import time
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from http import HTTPStatus
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit
from wsgiref.simple_server import make_server

from cryptography.fernet import Fernet, InvalidToken


ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
DATABASE = ROOT / "expense_tracker.db"
TOTP_KEY_PATH = ROOT / ".totp.key"
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
SESSION_DAYS = 7
PBKDF2_ROUNDS = 310_000
MAX_BODY_BYTES = 65_536
EXPENSE_CATEGORIES = {
    "Food", "Transport", "Housing", "Utilities", "Health", "Shopping",
    "Education", "Entertainment", "Other",
}
INCOME_CATEGORIES = {"Salary", "Freelance", "Gift", "Other"}

_attempts_lock = threading.Lock()
_rate_limits = {"login": (60, 8), "register": (3600, 10), "totp": (60, 10), "totp_settings": (60, 10)}
_rate_events = {}
SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'"),
]


class ApiError(Exception):
    def __init__(self, status, message, audit_user_id=None, audit_event_type=None):
        self.status = status
        self.message = message
        self.audit_user_id = audit_user_id
        self.audit_event_type = audit_event_type


@contextmanager
def connect_db():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return salt.hex() + ":" + derived.hex()


def password_matches(password, stored):
    salt_hex, expected = stored.split(":", 1)
    actual = password_hash(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
    return hmac.compare_digest(actual, expected)


DUMMY_PASSWORD_HASH = password_hash("not-a-real-account-password", b"\0" * 16)


def initialize_db():
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                category TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('expense', 'income')),
                transaction_date TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS transactions_user_date
                ON transactions(user_id, transaction_date DESC);
            CREATE TABLE IF NOT EXISTS budgets (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                monthly_limit_cents INTEGER NOT NULL CHECK (monthly_limit_cents > 0)
            );
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
                occurred_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS security_events_user_time
                ON security_events(user_id, occurred_at DESC);
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acknowledged_at TEXT
            );
            CREATE INDEX IF NOT EXISTS security_alerts_user_time
                ON security_alerts(user_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS login_challenges (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        additions = {
            "totp_secret_encrypted": "BLOB",
            "totp_pending_encrypted": "BLOB",
            "totp_pending_expires": "INTEGER",
            "totp_enabled": "INTEGER NOT NULL DEFAULT 0",
            "totp_recovery_hashes": "TEXT NOT NULL DEFAULT '[]'",
        }
        for column, definition in additions.items():
            if column not in user_columns:
                db.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
        db.execute("DELETE FROM login_challenges WHERE expires_at <= ?", (int(time.time()),))
        demo = db.execute("SELECT id FROM users WHERE email = ?", ("demo@example.com",)).fetchone()
        if demo is None:
            cursor = db.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                ("Alex Morgan", "demo@example.com", password_hash("DemoPass!2026"), datetime.now(timezone.utc).isoformat()),
            )
            user_id = cursor.lastrowid
            db.execute("INSERT INTO budgets (user_id, monthly_limit_cents) VALUES (?, ?)", (user_id, 180000))
            samples = [
                ("Weekly groceries", 8462, "Food", "expense", date.today().isoformat(), "Market and produce"),
                ("Metro pass", 3250, "Transport", "expense", (date.today() - timedelta(days=1)).isoformat(), "Monthly commute"),
                ("Internet bill", 5999, "Utilities", "expense", (date.today() - timedelta(days=3)).isoformat(), ""),
                ("Design project", 48000, "Freelance", "income", (date.today() - timedelta(days=5)).isoformat(), "Website milestone"),
                ("Dinner with friends", 4320, "Food", "expense", (date.today() - timedelta(days=7)).isoformat(), ""),
                ("Course materials", 2799, "Education", "expense", (date.today() - timedelta(days=10)).isoformat(), "Cloud security book"),
                ("Part-time pay", 72000, "Salary", "income", (date.today() - timedelta(days=15)).isoformat(), ""),
                ("Pharmacy", 1640, "Health", "expense", (date.today() - timedelta(days=18)).isoformat(), ""),
                ("Apartment rent", 75000, "Housing", "expense", (date.today() - timedelta(days=23)).isoformat(), ""),
                ("Coffee and lunch", 2180, "Food", "expense", (date.today() - timedelta(days=27)).isoformat(), ""),
            ]
            db.executemany(
                """INSERT INTO transactions
                   (user_id, title, amount_cents, category, kind, transaction_date, note, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [(user_id, *row, datetime.now(timezone.utc).isoformat()) for row in samples],
            )


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def get_totp_cipher():
    configured_key = os.environ.get("TOTP_ENCRYPTION_KEY")
    if configured_key:
        try:
            return Fernet(configured_key.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise RuntimeError("TOTP encryption key configuration is invalid.")
    try:
        key = TOTP_KEY_PATH.read_bytes().strip()
    except FileNotFoundError:
        key = Fernet.generate_key()
        try:
            descriptor = os.open(TOTP_KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            key = TOTP_KEY_PATH.read_bytes().strip()
        else:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(key)
    try:
        return Fernet(key)
    except (ValueError, TypeError):
        raise RuntimeError("TOTP encryption key file is invalid.")


def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret, timestamp=None):
    timestamp = time.time() if timestamp is None else timestamp
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    counter = int(timestamp // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{number:06d}"


def verify_totp(secret, code, timestamp=None):
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return False
    timestamp = time.time() if timestamp is None else timestamp
    return any(
        hmac.compare_digest(totp_code(secret, timestamp + (window * 30)), code)
        for window in (-1, 0, 1)
    )


def totp_uri(secret, email):
    label = quote(f"Smart Expense Tracker:{email}", safe="")
    issuer = quote("Smart Expense Tracker", safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


def json_response(start_response, status, payload, headers=None):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    response_headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
    ]
    response_headers.extend(SECURITY_HEADERS)
    if headers:
        response_headers.extend(headers)
    start_response(f"{status} {HTTPStatus(status).phrase}", response_headers)
    return [body]


def cookie_headers(token, max_age=SESSION_DAYS * 24 * 60 * 60, secure=False, name="session", path="/"):
    secure_attribute = "; Secure" if secure else ""
    value = f"{name}={token}; Path={path}; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure_attribute}"
    return [("Set-Cookie", value)]


def read_json(environ):
    content_type = environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Send data as JSON.")
    raw_size = environ.get("CONTENT_LENGTH", "")
    if not raw_size or not raw_size.isascii() or not raw_size.isdecimal():
        raise ApiError(HTTPStatus.BAD_REQUEST, "Invalid request size.")
    if len(raw_size) > len(str(MAX_BODY_BYTES)):
        raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request is too large.")
    size = int(raw_size)
    if size < 0 or size > MAX_BODY_BYTES:
        raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request is too large.")
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key.")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("Invalid JSON constant.")

    try:
        body = environ["wsgi.input"].read(size)
        if len(body) != size:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Incomplete JSON request body.")
        payload = json.loads(body, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except ApiError:
        raise
    except (ValueError, UnicodeDecodeError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "Invalid JSON.")
    if not isinstance(payload, dict):
        raise ApiError(HTTPStatus.BAD_REQUEST, "Expected a JSON object.")
    return payload


def current_session(environ, db):
    cookie = SimpleCookie()
    cookie.load(environ.get("HTTP_COOKIE", ""))
    morsel = cookie.get("session")
    if not morsel:
        return None
    token_hash = hashlib.sha256(morsel.value.encode("ascii", "ignore")).hexdigest()
    session = db.execute(
        """SELECT sessions.user_id, sessions.csrf_token, users.name, users.email
           FROM sessions JOIN users ON users.id = sessions.user_id
           WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
        (token_hash, int(time.time())),
    ).fetchone()
    return session


def check_origin(environ, required=True):
    origin = environ.get("HTTP_ORIGIN")
    host = environ.get("HTTP_HOST")
    if not host or not origin:
        if required:
            raise ApiError(HTTPStatus.FORBIDDEN, "A same-origin request is required.")
        return
    try:
        parsed_origin = urlsplit(origin)
        parsed_host = urlsplit("//" + host)
        valid_origin = (
            parsed_origin.scheme in ("http", "https")
            and bool(parsed_origin.netloc)
            and parsed_origin.path == ""
            and not parsed_origin.query
            and not parsed_origin.fragment
            and parsed_origin.username is None
            and parsed_origin.password is None
        )
        valid_host = (
            bool(parsed_host.netloc)
            and parsed_host.path == ""
            and parsed_host.username is None
            and parsed_host.password is None
            and parsed_host.hostname in ("localhost", "127.0.0.1", "::1")
        )
        parsed_origin.port
        parsed_host.port
    except ValueError:
        valid_origin = valid_host = False
    if not valid_origin or not valid_host or parsed_origin.netloc.lower() != host.lower():
        raise ApiError(HTTPStatus.FORBIDDEN, "Cross-origin requests are not allowed.")


def require_csrf(environ, session):
    try:
        check_origin(environ, required=True)
    except ApiError as error:
        raise ApiError(error.status, error.message, session["user_id"], "request.origin_rejected")
    supplied = environ.get("HTTP_X_CSRF_TOKEN", "")
    if not hmac.compare_digest(supplied, session["csrf_token"]):
        raise ApiError(
            HTTPStatus.FORBIDDEN, "Your session token has expired. Refresh and try again.",
            session["user_id"], "request.csrf_rejected",
        )


def cents_from(value):
    try:
        amount = Decimal(str(value))
        quantized = amount.quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "Enter a valid amount.")
    if not amount.is_finite() or amount != quantized or amount <= 0 or amount > Decimal("1000000"):
        raise ApiError(HTTPStatus.BAD_REQUEST, "Amount must be greater than zero and at most 1,000,000.")
    return int(quantized * 100)


def transaction_payload(payload):
    title_value = payload.get("title", "")
    note_value = payload.get("note", "")
    kind = payload.get("kind")
    category = payload.get("category")
    date_value = payload.get("date", "")
    if not isinstance(title_value, str) or not isinstance(note_value, str) or not isinstance(date_value, str):
        raise ApiError(HTTPStatus.BAD_REQUEST, "Transaction fields have invalid types.")
    title = title_value.strip()
    note = note_value.strip()
    if not isinstance(kind, str) or not isinstance(category, str):
        raise ApiError(HTTPStatus.BAD_REQUEST, "Choose a valid transaction type and category.")
    try:
        transaction_date = date.fromisoformat(date_value)
    except (ValueError, TypeError):
        raise ApiError(HTTPStatus.BAD_REQUEST, "Choose a valid date.")
    if not title or len(title) > 80:
        raise ApiError(HTTPStatus.BAD_REQUEST, "Description must be between 1 and 80 characters.")
    if len(note) > 240:
        raise ApiError(HTTPStatus.BAD_REQUEST, "Note must be 240 characters or fewer.")
    allowed = INCOME_CATEGORIES if kind == "income" else EXPENSE_CATEGORIES if kind == "expense" else set()
    if category not in allowed:
        raise ApiError(HTTPStatus.BAD_REQUEST, "Choose a valid category for this transaction type.")
    return {
        "title": title,
        "amount_cents": cents_from(payload.get("amount")),
        "category": category,
        "kind": kind,
        "date": transaction_date.isoformat(),
        "note": note,
    }


def transaction_dict(row):
    return {
        "id": row["id"], "title": row["title"], "amount_cents": row["amount_cents"],
        "category": row["category"], "kind": row["kind"], "date": row["transaction_date"], "note": row["note"],
    }


def rate_is_limited(action, remote_addr):
    now = time.time()
    with _attempts_lock:
        max_window = max(window for window, _ in _rate_limits.values())
        for key, stamps in list(_rate_events.items()):
            recent = [stamp for stamp in stamps if now - stamp < max_window]
            if recent:
                _rate_events[key] = recent
            else:
                del _rate_events[key]
        window, limit = _rate_limits[action]
        key = (action, remote_addr)
        recent = [stamp for stamp in _rate_events.get(key, []) if now - stamp < window]
        _rate_events[key] = recent
        return len(recent) >= limit


def record_rate_event(action, remote_addr):
    with _attempts_lock:
        _rate_events.setdefault((action, remote_addr), []).append(time.time())


def clear_rate_events(action, remote_addr):
    with _attempts_lock:
        _rate_events.pop((action, remote_addr), None)


def record_security_event(db, user_id, event_type, severity="info"):
    occurred_at = utc_now().isoformat()
    db.execute(
        "INSERT INTO security_events (user_id, event_type, severity, occurred_at) VALUES (?, ?, ?, ?)",
        (user_id, event_type, severity, occurred_at),
    )


def create_alert_once(db, user_id, alert_type, severity, summary, within_minutes=30):
    cutoff = (utc_now() - timedelta(minutes=within_minutes)).isoformat()
    existing = db.execute(
        "SELECT id FROM security_alerts WHERE user_id = ? AND alert_type = ? AND created_at >= ? LIMIT 1",
        (user_id, alert_type, cutoff),
    ).fetchone()
    if existing is None:
        db.execute(
            "INSERT INTO security_alerts (user_id, alert_type, severity, summary, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, alert_type, severity, summary, utc_now().isoformat()),
        )


def detect_repeated_login_failures(db, user_id):
    if user_id is None:
        return
    cutoff = (utc_now() - timedelta(minutes=15)).isoformat()
    failures = db.execute(
        "SELECT COUNT(*) FROM security_events WHERE user_id = ? AND event_type = 'login.failure' AND occurred_at >= ?",
        (user_id, cutoff),
    ).fetchone()[0]
    if failures >= 5:
        create_alert_once(
            db, user_id, "repeated_login_failures", "warning",
            "Five or more unsuccessful sign-in attempts were recorded for this account in 15 minutes.",
        )


def detect_repeated_request_failures(db, user_id, event_type):
    if user_id is None:
        return
    cutoff = (utc_now() - timedelta(minutes=10)).isoformat()
    failures = db.execute(
        "SELECT COUNT(*) FROM security_events WHERE user_id = ? AND event_type = ? AND occurred_at >= ?",
        (user_id, event_type, cutoff),
    ).fetchone()[0]
    if failures >= 5:
        create_alert_once(
            db, user_id, "repeated_rejected_requests", "warning",
            "Repeated requests with invalid origin or security tokens were rejected.",
        )


def log_failed_login(db, user_id):
    record_security_event(db, user_id, "login.failure", "warning")
    detect_repeated_login_failures(db, user_id)


def create_session(db, user_id):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    expires_at = int(time.time()) + SESSION_DAYS * 24 * 60 * 60
    db.execute("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
               (token_hash, user_id, csrf, expires_at))
    return token, csrf


def revoke_presented_session(db, environ):
    cookie = SimpleCookie()
    cookie.load(environ.get("HTTP_COOKIE", ""))
    token = cookie.get("session")
    if token:
        token_hash = hashlib.sha256(token.value.encode("ascii", "ignore")).hexdigest()
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def create_login_challenge(db, user_id):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    db.execute("DELETE FROM login_challenges WHERE user_id = ?", (user_id,))
    db.execute(
        "INSERT INTO login_challenges (token_hash, user_id, csrf_hash, expires_at) VALUES (?, ?, ?, ?)",
        (hashlib.sha256(token.encode("ascii")).hexdigest(), user_id,
         hashlib.sha256(csrf.encode("ascii")).hexdigest(), int(time.time()) + 300),
    )
    return token, csrf


def current_login_challenge(environ, db):
    cookie = SimpleCookie()
    cookie.load(environ.get("HTTP_COOKIE", ""))
    token = cookie.get("login_challenge")
    if token is None:
        return None
    token_hash = hashlib.sha256(token.value.encode("ascii", "ignore")).hexdigest()
    return db.execute(
        """SELECT login_challenges.token_hash, login_challenges.user_id, login_challenges.csrf_hash,
                  login_challenges.expires_at, login_challenges.attempts, users.email, users.name,
                  users.totp_secret_encrypted, users.totp_recovery_hashes
           FROM login_challenges JOIN users ON users.id = login_challenges.user_id
           WHERE login_challenges.token_hash = ? AND login_challenges.expires_at > ?""",
        (token_hash, int(time.time())),
    ).fetchone()


def consume_recovery_code(db, user_id, code):
    if not isinstance(code, str) or not 8 <= len(code) <= 64:
        return False
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    user = db.execute("SELECT totp_recovery_hashes FROM users WHERE id = ?", (user_id,)).fetchone()
    hashes = json.loads(user["totp_recovery_hashes"] or "[]")
    for index, expected in enumerate(hashes):
        if hmac.compare_digest(code_hash, expected):
            del hashes[index]
            db.execute("UPDATE users SET totp_recovery_hashes = ? WHERE id = ?", (json.dumps(hashes), user_id))
            return True
    return False


def clear_login_challenge_cookie(secure=False):
    return cookie_headers("", 0, secure=secure, name="login_challenge", path="/api/login")


def api_app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = unquote(environ.get("PATH_INFO", "/"))
    try:
        with connect_db() as db:
            if method == "GET" and path == "/api/session":
                session = current_session(environ, db)
                if session is None:
                    return json_response(start_response, HTTPStatus.OK, {"user": None})
                return json_response(start_response, HTTPStatus.OK, {
                    "user": {"name": session["name"], "email": session["email"]}, "csrf_token": session["csrf_token"],
                })

            if method == "POST" and path in ("/api/register", "/api/login"):
                check_origin(environ, required=True)
                action = "register" if path == "/api/register" else "login"
                remote_addr = environ.get("REMOTE_ADDR", "unknown")
                if rate_is_limited(action, remote_addr):
                    raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "Too many authentication requests. Wait and try again.")
                if action == "register":
                    record_rate_event(action, remote_addr)
                payload = read_json(environ)
                email_value = payload.get("email", "")
                password = payload.get("password", "")
                required_fields = {"name", "email", "password"} if action == "register" else {"email", "password"}
                if set(payload) != required_fields:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Authentication request fields are invalid.")
                if not isinstance(email_value, str) or len(email_value) > 254:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Enter a valid email address.")
                email = email_value.strip().lower()
                if not isinstance(password, str) or not 1 <= len(password) <= 128:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Password must be between 1 and 128 characters.")
                if path == "/api/register":
                    name_value = payload.get("name", "")
                    if not isinstance(name_value, str):
                        raise ApiError(HTTPStatus.BAD_REQUEST, "Name must be between 2 and 60 characters.")
                    name = name_value.strip()
                    if len(name) < 2 or len(name) > 60:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "Name must be between 2 and 60 characters.")
                    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "Enter a valid email address.")
                    if len(password) < 12:
                        raise ApiError(HTTPStatus.BAD_REQUEST, "Use a password with at least 12 characters.")
                    try:
                        cursor = db.execute(
                            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                            (name, email, password_hash(password), datetime.now(timezone.utc).isoformat()),
                        )
                    except sqlite3.IntegrityError:
                        raise ApiError(HTTPStatus.CONFLICT, "An account with this email already exists.")
                    user_id = cursor.lastrowid
                    db.execute("INSERT INTO budgets (user_id, monthly_limit_cents) VALUES (?, ?)", (user_id, 180000))
                    record_security_event(db, user_id, "account.created")
                else:
                    if rate_is_limited(action, remote_addr):
                        raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "Too many sign-in attempts. Wait a minute and try again.")
                    user = db.execute("SELECT id, password_hash, totp_enabled FROM users WHERE email = ?", (email,)).fetchone()
                    encoded_hash = user["password_hash"] if user is not None else DUMMY_PASSWORD_HASH
                    password_is_valid = password_matches(password, encoded_hash)
                    if user is None or not password_is_valid:
                        record_rate_event(action, remote_addr)
                        log_failed_login(db, user["id"] if user is not None else None)
                        return json_response(start_response, HTTPStatus.UNAUTHORIZED, {"error": "Email or password is incorrect."})
                    user_id = user["id"]
                    clear_rate_events(action, remote_addr)
                    if user["totp_enabled"]:
                        record_security_event(db, user_id, "login.challenge_started")
                        challenge, challenge_csrf = create_login_challenge(db, user_id)
                        return json_response(
                            start_response, HTTPStatus.OK,
                            {"requires_totp": True, "csrf_token": challenge_csrf},
                            cookie_headers(challenge, 300, secure=environ.get("wsgi.url_scheme") == "https",
                                           name="login_challenge", path="/api/login"),
                        )
                revoke_presented_session(db, environ)
                token, csrf = create_session(db, user_id)
                record_security_event(db, user_id, "login.success")
                user = db.execute("SELECT name, email FROM users WHERE id = ?", (user_id,)).fetchone()
                return json_response(start_response, HTTPStatus.OK, {
                    "user": {"name": user["name"], "email": user["email"]}, "csrf_token": csrf,
                }, cookie_headers(token, secure=environ.get("wsgi.url_scheme") == "https"))

            if method == "POST" and path == "/api/login/totp":
                check_origin(environ, required=True)
                challenge = current_login_challenge(environ, db)
                secure = environ.get("wsgi.url_scheme") == "https"
                if challenge is None:
                    return json_response(
                        start_response, HTTPStatus.UNAUTHORIZED, {"error": "The sign-in challenge expired. Sign in again."},
                        clear_login_challenge_cookie(secure),
                    )
                payload = read_json(environ)
                if set(payload) != {"code"} or not isinstance(payload["code"], str):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Enter an authenticator or recovery code.")
                supplied_csrf = environ.get("HTTP_X_CSRF_TOKEN", "")
                csrf_hash = hashlib.sha256(supplied_csrf.encode("utf-8")).hexdigest()
                if not hmac.compare_digest(csrf_hash, challenge["csrf_hash"]):
                    remote_addr = environ.get("REMOTE_ADDR", "unknown")
                    if rate_is_limited("totp", remote_addr):
                        return json_response(start_response, HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many verification attempts. Wait and try again."})
                    record_rate_event("totp", remote_addr)
                    record_security_event(db, challenge["user_id"], "request.csrf_rejected", "warning")
                    detect_repeated_request_failures(db, challenge["user_id"], "request.csrf_rejected")
                    return json_response(start_response, HTTPStatus.FORBIDDEN, {"error": "The sign-in challenge is invalid."})
                remote_addr = environ.get("REMOTE_ADDR", "unknown")
                if rate_is_limited("totp", remote_addr):
                    return json_response(start_response, HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many verification attempts. Wait and try again."})
                try:
                    secret = get_totp_cipher().decrypt(bytes(challenge["totp_secret_encrypted"])).decode("ascii")
                except (InvalidToken, UnicodeDecodeError, TypeError):
                    raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, "Two-factor verification is temporarily unavailable.")
                code = payload["code"].strip()
                verified = verify_totp(secret, code) or consume_recovery_code(db, challenge["user_id"], code)
                if not verified:
                    record_rate_event("totp", remote_addr)
                    attempts = challenge["attempts"] + 1
                    record_security_event(db, challenge["user_id"], "login.failure", "warning")
                    detect_repeated_login_failures(db, challenge["user_id"])
                    if attempts >= 5:
                        db.execute("DELETE FROM login_challenges WHERE token_hash = ?", (challenge["token_hash"],))
                        headers = clear_login_challenge_cookie(secure)
                    else:
                        db.execute("UPDATE login_challenges SET attempts = ? WHERE token_hash = ?",
                                   (attempts, challenge["token_hash"]))
                        headers = None
                    return json_response(start_response, HTTPStatus.UNAUTHORIZED, {
                        "error": "Sign-in challenge expired. Sign in again." if attempts >= 5
                                 else "Authenticator or recovery code is incorrect.",
                    }, headers)
                clear_rate_events("totp", remote_addr)
                revoke_presented_session(db, environ)
                db.execute("DELETE FROM login_challenges WHERE token_hash = ?", (challenge["token_hash"],))
                record_security_event(db, challenge["user_id"], "login.success")
                token, csrf = create_session(db, challenge["user_id"])
                headers = cookie_headers(token, secure=secure)
                headers.extend(clear_login_challenge_cookie(secure))
                return json_response(start_response, HTTPStatus.OK, {
                    "user": {"name": challenge["name"], "email": challenge["email"]}, "csrf_token": csrf,
                }, headers)

            session = current_session(environ, db)
            if session is None:
                raise ApiError(HTTPStatus.UNAUTHORIZED, "Sign in to continue.")

            if method == "GET" and path == "/api/bootstrap":
                rows = db.execute(
                    "SELECT * FROM transactions WHERE user_id = ? ORDER BY transaction_date DESC, id DESC",
                    (session["user_id"],),
                ).fetchall()
                budget = db.execute("SELECT monthly_limit_cents FROM budgets WHERE user_id = ?", (session["user_id"],)).fetchone()
                return json_response(start_response, HTTPStatus.OK, {
                    "user": {"name": session["name"], "email": session["email"]},
                    "csrf_token": session["csrf_token"],
                    "budget_cents": budget["monthly_limit_cents"],
                    "transactions": [transaction_dict(row) for row in rows],
                })

            if method == "GET" and path == "/api/security/summary":
                user_id = session["user_id"]
                since = (utc_now() - timedelta(hours=24)).isoformat()
                counts = db.execute(
                    """SELECT
                         SUM(CASE WHEN event_type = 'login.failure' AND occurred_at >= ? THEN 1 ELSE 0 END) AS failed_24h,
                         SUM(CASE WHEN event_type = 'login.success' AND occurred_at >= ? THEN 1 ELSE 0 END) AS successful_24h
                       FROM security_events WHERE user_id = ?""",
                    (since, since, user_id),
                ).fetchone()
                events = db.execute(
                    "SELECT event_type, severity, occurred_at FROM security_events WHERE user_id = ? ORDER BY id DESC LIMIT 30",
                    (user_id,),
                ).fetchall()
                alerts = db.execute(
                    """SELECT id, alert_type, severity, summary, created_at, acknowledged_at
                       FROM security_alerts WHERE user_id = ? ORDER BY id DESC LIMIT 20""",
                    (user_id,),
                ).fetchall()
                open_alerts = db.execute(
                    "SELECT COUNT(*) FROM security_alerts WHERE user_id = ? AND acknowledged_at IS NULL",
                    (user_id,),
                ).fetchone()[0]
                totp = db.execute("SELECT totp_enabled FROM users WHERE id = ?", (user_id,)).fetchone()
                return json_response(start_response, HTTPStatus.OK, {
                    "failed_login_24h": counts["failed_24h"] or 0,
                    "successful_login_24h": counts["successful_24h"] or 0,
                    "open_alerts": open_alerts,
                    "totp_enabled": bool(totp["totp_enabled"]),
                    "events": [dict(event) for event in events],
                    "alerts": [dict(alert) for alert in alerts],
                })

            alert_match = re.fullmatch(r"/api/security/alerts/(\d+)/acknowledge", path)
            if method == "POST" and alert_match:
                require_csrf(environ, session)
                alert_id = int(alert_match.group(1))
                cursor = db.execute(
                    "UPDATE security_alerts SET acknowledged_at = ? WHERE id = ? AND user_id = ? AND acknowledged_at IS NULL",
                    (utc_now().isoformat(), alert_id, session["user_id"]),
                )
                if cursor.rowcount == 0:
                    owned = db.execute("SELECT id FROM security_alerts WHERE id = ? AND user_id = ?",
                                       (alert_id, session["user_id"])).fetchone()
                    if owned is None:
                        raise ApiError(HTTPStatus.NOT_FOUND, "Security alert not found.")
                    return json_response(start_response, HTTPStatus.OK, {"ok": True})
                record_security_event(db, session["user_id"], "security.alert_acknowledged")
                return json_response(start_response, HTTPStatus.OK, {"ok": True})

            if method == "POST" and path == "/api/security/totp/setup":
                require_csrf(environ, session)
                payload = read_json(environ)
                if set(payload) != {"password"} or not isinstance(payload["password"], str):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Enter your password to continue.")
                remote_addr = environ.get("REMOTE_ADDR", "unknown")
                if rate_is_limited("totp_settings", remote_addr):
                    raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "Too many security-setting attempts. Wait and try again.")
                user = db.execute("SELECT email, password_hash, totp_enabled FROM users WHERE id = ?",
                                  (session["user_id"],)).fetchone()
                if not password_matches(payload["password"], user["password_hash"]):
                    record_rate_event("totp_settings", remote_addr)
                    record_security_event(db, session["user_id"], "totp.setup_rejected", "warning")
                    return json_response(start_response, HTTPStatus.UNAUTHORIZED, {"error": "Password verification failed."})
                if user["totp_enabled"]:
                    raise ApiError(HTTPStatus.CONFLICT, "Two-factor authentication is already enabled.")
                secret = new_totp_secret()
                encrypted = get_totp_cipher().encrypt(secret.encode("ascii"))
                expires_at = int(time.time()) + 600
                db.execute(
                    "UPDATE users SET totp_pending_encrypted = ?, totp_pending_expires = ? WHERE id = ?",
                    (encrypted, expires_at, session["user_id"]),
                )
                clear_rate_events("totp_settings", remote_addr)
                record_security_event(db, session["user_id"], "totp.setup_started")
                return json_response(start_response, HTTPStatus.OK, {
                    "secret": secret, "otpauth_uri": totp_uri(secret, user["email"]),
                    "expires_in_seconds": 600,
                })

            if method == "POST" and path == "/api/security/totp/confirm":
                require_csrf(environ, session)
                payload = read_json(environ)
                if set(payload) != {"code"} or not isinstance(payload["code"], str):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Enter the six-digit authenticator code.")
                if rate_is_limited("totp_settings", environ.get("REMOTE_ADDR", "unknown")):
                    raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "Too many security-setting attempts. Wait and try again.")
                user = db.execute(
                    "SELECT totp_pending_encrypted, totp_pending_expires FROM users WHERE id = ?",
                    (session["user_id"],),
                ).fetchone()
                if not user["totp_pending_encrypted"] or not user["totp_pending_expires"] or user["totp_pending_expires"] <= int(time.time()):
                    return json_response(start_response, HTTPStatus.CONFLICT, {"error": "Enrollment expired. Start setup again."})
                try:
                    secret = get_totp_cipher().decrypt(bytes(user["totp_pending_encrypted"])).decode("ascii")
                except (InvalidToken, UnicodeDecodeError, TypeError):
                    raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, "Two-factor enrollment is temporarily unavailable.")
                if not verify_totp(secret, payload["code"].strip()):
                    record_rate_event("totp_settings", environ.get("REMOTE_ADDR", "unknown"))
                    record_security_event(db, session["user_id"], "totp.enrollment_failed", "warning")
                    return json_response(start_response, HTTPStatus.UNAUTHORIZED, {"error": "Authenticator code is incorrect."})
                recovery_codes = [secrets.token_urlsafe(12) for _ in range(10)]
                recovery_hashes = [hashlib.sha256(code.encode("ascii")).hexdigest() for code in recovery_codes]
                db.execute(
                    """UPDATE users SET totp_secret_encrypted = ?, totp_pending_encrypted = NULL,
                       totp_pending_expires = NULL, totp_enabled = 1, totp_recovery_hashes = ? WHERE id = ?""",
                    (user["totp_pending_encrypted"], json.dumps(recovery_hashes), session["user_id"]),
                )
                clear_rate_events("totp_settings", environ.get("REMOTE_ADDR", "unknown"))
                record_security_event(db, session["user_id"], "totp.enabled")
                return json_response(start_response, HTTPStatus.OK, {"recovery_codes": recovery_codes})

            if method == "POST" and path == "/api/security/totp/disable":
                require_csrf(environ, session)
                payload = read_json(environ)
                if set(payload) != {"password", "code"} or not all(isinstance(payload[key], str) for key in payload):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Enter your password and authenticator or recovery code.")
                remote_addr = environ.get("REMOTE_ADDR", "unknown")
                if rate_is_limited("totp_settings", remote_addr):
                    raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, "Too many security-setting attempts. Wait and try again.")
                user = db.execute(
                    "SELECT password_hash, totp_secret_encrypted, totp_enabled FROM users WHERE id = ?",
                    (session["user_id"],),
                ).fetchone()
                if not password_matches(payload["password"], user["password_hash"]) or not user["totp_enabled"]:
                    record_rate_event("totp_settings", remote_addr)
                    record_security_event(db, session["user_id"], "totp.disable_rejected", "warning")
                    return json_response(start_response, HTTPStatus.UNAUTHORIZED, {"error": "Security verification failed."})
                try:
                    secret = get_totp_cipher().decrypt(bytes(user["totp_secret_encrypted"])).decode("ascii")
                except (InvalidToken, UnicodeDecodeError, TypeError):
                    raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, "Two-factor verification is temporarily unavailable.")
                verified = verify_totp(secret, payload["code"].strip()) or consume_recovery_code(db, session["user_id"], payload["code"].strip())
                if not verified:
                    record_rate_event("totp_settings", remote_addr)
                    record_security_event(db, session["user_id"], "totp.disable_rejected", "warning")
                    return json_response(start_response, HTTPStatus.UNAUTHORIZED, {"error": "Security verification failed."})
                db.execute(
                    """UPDATE users SET totp_secret_encrypted = NULL, totp_pending_encrypted = NULL,
                       totp_pending_expires = NULL, totp_enabled = 0, totp_recovery_hashes = '[]' WHERE id = ?""",
                    (session["user_id"],),
                )
                db.execute("DELETE FROM login_challenges WHERE user_id = ?", (session["user_id"],))
                clear_rate_events("totp_settings", remote_addr)
                record_security_event(db, session["user_id"], "totp.disabled")
                return json_response(start_response, HTTPStatus.OK, {"ok": True})

            if method == "POST" and path == "/api/logout":
                require_csrf(environ, session)
                record_security_event(db, session["user_id"], "logout")
                cookie = SimpleCookie()
                cookie.load(environ.get("HTTP_COOKIE", ""))
                token = cookie.get("session")
                if token:
                    db.execute("DELETE FROM sessions WHERE token_hash = ?",
                               (hashlib.sha256(token.value.encode("ascii", "ignore")).hexdigest(),))
                return json_response(start_response, HTTPStatus.OK, {"ok": True}, cookie_headers("", 0, secure=environ.get("wsgi.url_scheme") == "https"))

            if method == "POST" and path == "/api/transactions":
                require_csrf(environ, session)
                payload = read_json(environ)
                if not set(payload).issubset({"title", "amount", "category", "kind", "date", "note"}):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Unexpected transaction field.")
                item = transaction_payload(payload)
                cursor = db.execute(
                    """INSERT INTO transactions (user_id, title, amount_cents, category, kind, transaction_date, note, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (session["user_id"], item["title"], item["amount_cents"], item["category"], item["kind"],
                     item["date"], item["note"], datetime.now(timezone.utc).isoformat()),
                )
                item["id"] = cursor.lastrowid
                record_security_event(db, session["user_id"], "transaction.created")
                return json_response(start_response, HTTPStatus.CREATED, {"transaction": item})

            match = re.fullmatch(r"/api/transactions/(\d+)", path)
            if match and method in ("PATCH", "DELETE"):
                require_csrf(environ, session)
                transaction_id = int(match.group(1))
                row = db.execute("SELECT * FROM transactions WHERE id = ? AND user_id = ?",
                                 (transaction_id, session["user_id"])).fetchone()
                if row is None:
                    raise ApiError(HTTPStatus.NOT_FOUND, "Transaction not found.")
                if method == "DELETE":
                    db.execute("DELETE FROM transactions WHERE id = ? AND user_id = ?",
                               (transaction_id, session["user_id"]))
                    record_security_event(db, session["user_id"], "transaction.deleted")
                    return json_response(start_response, HTTPStatus.OK, {"ok": True})
                existing = transaction_dict(row)
                payload = read_json(environ)
                merged = {
                    "title": existing["title"], "amount": str(Decimal(existing["amount_cents"]) / 100),
                    "category": existing["category"], "kind": existing["kind"], "date": existing["date"], "note": existing["note"],
                }
                allowed_fields = {"title", "amount", "category", "kind", "date", "note"}
                if not set(payload).issubset(allowed_fields):
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Unexpected transaction field.")
                merged.update(payload)
                item = transaction_payload(merged)
                db.execute(
                    """UPDATE transactions SET title = ?, amount_cents = ?, category = ?, kind = ?, transaction_date = ?, note = ?
                       WHERE id = ? AND user_id = ?""",
                    (item["title"], item["amount_cents"], item["category"], item["kind"], item["date"], item["note"], transaction_id, session["user_id"]),
                )
                item["id"] = transaction_id
                record_security_event(db, session["user_id"], "transaction.updated")
                return json_response(start_response, HTTPStatus.OK, {"transaction": item})

            if method == "PATCH" and path == "/api/budget":
                require_csrf(environ, session)
                payload = read_json(environ)
                if set(payload) != {"amount"}:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "Budget request fields are invalid.")
                amount_cents = cents_from(payload["amount"])
                db.execute("UPDATE budgets SET monthly_limit_cents = ? WHERE user_id = ?",
                           (amount_cents, session["user_id"]))
                record_security_event(db, session["user_id"], "budget.updated")
                return json_response(start_response, HTTPStatus.OK, {"budget_cents": amount_cents})

            raise ApiError(HTTPStatus.NOT_FOUND, "Endpoint not found.")
    except ApiError as error:
        if error.audit_user_id is not None and error.audit_event_type is not None:
            try:
                with connect_db() as audit_db:
                    record_security_event(audit_db, error.audit_user_id, error.audit_event_type, "warning")
                    detect_repeated_request_failures(audit_db, error.audit_user_id, error.audit_event_type)
            except sqlite3.Error:
                pass
        return json_response(start_response, error.status, {"error": error.message})
    except sqlite3.Error:
        return json_response(start_response, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "The database could not complete this request."})
    except Exception:
        return json_response(start_response, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "The request could not be completed."})


def static_app(environ, start_response):
    path = unquote(environ.get("PATH_INFO", "/"))
    if path == "/":
        path = "/index.html"
    candidate = (PUBLIC / path.lstrip("/")).resolve()
    if not candidate.is_relative_to(PUBLIC.resolve()) or not candidate.is_file():
        body = b"Not found"
        start_response("404 Not Found", [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            *SECURITY_HEADERS,
        ])
        return [body]
    mime = "text/html; charset=utf-8" if candidate.suffix == ".html" else "text/css; charset=utf-8" if candidate.suffix == ".css" else "text/javascript; charset=utf-8"
    body = candidate.read_bytes()
    start_response("200 OK", [
        ("Content-Type", mime), ("Content-Length", str(len(body))), ("Cache-Control", "no-store"),
        *SECURITY_HEADERS,
    ])
    return [body]


def application(environ, start_response):
    try:
        if environ.get("PATH_INFO", "").startswith("/api/"):
            return api_app(environ, start_response)
        if environ.get("REQUEST_METHOD") not in ("GET", "HEAD"):
            return json_response(start_response, HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})
        return static_app(environ, start_response)
    except Exception:
        return json_response(start_response, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "The request could not be completed."})


if __name__ == "__main__":
    initialize_db()
    print(f"Smart Expense Tracker is running at http://{HOST}:{PORT}")
    with make_server(HOST, PORT, application) as server:
        server.serve_forever()