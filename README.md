# Smart Expense Tracker

A local full-stack personal finance app built for a second-year cybersecurity project. It records income and expenses, tracks a monthly spending budget, visualizes spending patterns, and exports transaction history as CSV. The frontend is plain HTML, CSS, and JavaScript; the backend is Python's standard-library WSGI server with SQLite persistence. Security regression tests also use only the Python standard library.

## Run locally

Requirements: Python 3.10 or newer. Install the single runtime dependency from PowerShell in the project folder:

```powershell
py -3 -m pip install -r requirements.txt
```

Start the local server:

```powershell
py -3 server.py
```

Then open <http://localhost:8000>. The server binds to `127.0.0.1` by default and is intended for local development.

The first launch creates `expense_tracker.db` and sample records. The demo account is:

- Email: `demo@example.com`
- Password: `DemoPass!2026`

Choose **Create an account** to create a separate account. All data stays in the local SQLite database; no bank integration or cloud service is used.

Set a different port with `$env:PORT=8080` before starting the server.

## Project structure

```text
server.py             WSGI server, JSON API, authentication, and SQLite persistence
public/index.html     Accessible app shell and forms
public/styles.css     Responsive dashboard and login styling
public/app.js         Client-side navigation, charts, filters, and API integration
tests/                Isolated standard-library security regression tests
requirements.txt      Fernet encryption dependency for TOTP secrets
PROJECT_REPORT.md    Final-year project report and technical design
DEMO_GUIDE.md        Safe, local demonstration steps using a temporary copy
VIVA_QUESTIONS.md    Twenty viva questions with concise answers
expense_tracker.db    Created on first run; contains local app data
```

## Back Up The Database

Before changing database-related code or performing maintenance, create a separate backup with SQLite's backup API. This PowerShell command uses a timestamp and adds a suffix if a file with that name already exists; it does not overwrite an earlier backup:

```powershell
@'
import datetime
import pathlib
import sqlite3

stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
backup = pathlib.Path(f"expense_tracker.backup-{stamp}.db")
suffix = 1
while backup.exists():
	backup = pathlib.Path(f"expense_tracker.backup-{stamp}-{suffix}.db")
	suffix += 1
source = sqlite3.connect("expense_tracker.db")
destination = sqlite3.connect(backup)
source.backup(destination)
source.close()
destination.close()
print(f"Backup created: {backup}")
'@ | py -3 -
```

## Security Controls

- PBKDF2-HMAC-SHA256 password hashes with per-user random salts
- Opaque, random server-side sessions with seven-day expiration; successful sign-in issues a fresh session ID and revokes the session cookie presented to that sign-in
- Session cookies are `HttpOnly` and `SameSite=Lax`; the `Secure` attribute is added when the WSGI request uses HTTPS, but stays off for local HTTP development
- Login and registration require a matching localhost `Origin` and `Host`; every authenticated state-changing API request requires both this origin check and the session CSRF token
- Login failures are limited to 8 per minute per source IP; registration is limited to 10 attempts per hour per source IP. Limits are not keyed to an account, so a remote source cannot put a specific account into a lockout state
- JSON requests require a valid content type and content length, are limited to 64 KB, and reject malformed or duplicate-key JSON
- Parameterized SQL, server-side field validation, and per-account ownership checks for transaction and budget reads/writes
- Content Security Policy, `nosniff`, frame protection, same-origin resource policy, referrer policy, and a restrictive permissions policy
- User-provided transaction text is escaped in the frontend; CSV formula-like values are neutralized during export
- Amounts stored as integer cents instead of floating-point values

The login and registration rate limits are kept in process memory. They reset when the server restarts and do not coordinate across multiple worker processes. Since local requests share a loopback address, repeated failed sign-ins from this machine can temporarily throttle sign-in attempts from this machine, but do not lock a particular account. A public service needs a shared rate-limit store and operational monitoring.

Audit events and security alerts currently have no retention or pagination policy. Repeated known-account failures can grow the SQLite database; monitor available disk space. SQLite transaction names, notes, balances, and budgets are not encrypted at rest, so restrict access to the database and its backups. The seeded demo account uses public fixed credentials and is for local demonstration only; disable/remove it before any deployment.

The existing database schema did not need changes for Phase 2. The app continues to use the existing accounts, transactions, budgets, and sessions; it does not reset the database.

## Security Dashboard

After signing in, open **Security** in the workspace navigation. The page shows successful and failed sign-in counts for the last 24 hours, recent account-scoped security events, active alerts, and two-factor status. Select **Mark reviewed** on an alert to acknowledge it; the event stays in the audit trail.

Audit events record account ID, event type, severity, and timestamp. They do not contain passwords, cookies, CSRF values, IP addresses, transaction amounts, titles, notes, or budget values. Failed logins for a known account are associated with that account; attempts for unknown email addresses cannot be attributed to an account and are not shown in a user's dashboard.

Repeated activity creates a warning when five known-account sign-in failures occur within 15 minutes, or when five authenticated origin/CSRF rejections occur within 10 minutes. Similar alerts are deduplicated for 30 minutes. Alerts are indicators for review, not proof of an attack. A user mistyping a password or a browser with stale security state can trigger an alert. This local version does not collect IP/device/location context, send notifications, or detect activity outside the events it records.

## Optional Two-Factor Authentication

On the Security page, choose **Set up two-factor** and confirm your account password. Add the displayed setup secret to a TOTP authenticator, then enter its current six-digit code to finish enrollment. Until that confirmation succeeds, your existing password sign-in remains unchanged. Save the ten recovery codes when they appear; they are displayed once, each code works once, and they are stored in the database as hashes. You can download a local text copy from the one-time screen. Keep that file private and offline. To turn two-factor off later, provide your password and a current authenticator or unused recovery code.

TOTP secrets are encrypted in SQLite with Fernet. The encryption key is created locally as `.totp.key` on first enrollment; it is git-ignored and must be protected separately. Back up this key securely alongside every database backup after enabling TOTP. A database backup without its matching key cannot decrypt enrolled authenticator secrets. On Windows, restrict the key file to your user account with:

```powershell
icacls .totp.key /inheritance:r /grant:r "$($env:USERNAME):(R)"
```

If both an authenticator and all recovery codes are lost, this educational app has no email-based account recovery; an administrator would need to verify the owner and reset TOTP locally. Do not delete the key while any account has TOTP enabled. No SMS, email, or cloud service is involved.

TOTP uses the installed `cryptography` package for authenticated encryption. The implementation follows RFC 6238 with a 30-second period, six-digit SHA-1 codes, and a one-step clock tolerance. Keep the device clock accurate. The local key file is readable by the Windows account that runs the server; protect the Windows account and key file. For a public service, use a managed secret store rather than a project-folder key.

## Run Tests

From the project folder, run:

```powershell
py -3 -m unittest discover -s tests -v
```

The tests create isolated temporary SQLite databases and temporary TOTP keys. They do not open or change `expense_tracker.db` or `.totp.key`. Coverage includes authentication, session rotation/expiration, Origin/CSRF rejection, request limits, authorization, SQL-injection handling, transaction/budget persistence, error responses and headers (including static 404s), audit privacy/scope, alert thresholds/acknowledgement, RFC 6238 codes, encrypted TOTP enrollment, TOTP login, one-time recovery codes, and disable flow. The final local assessment also exercised XSS rendering and CSV formula handling in a disposable browser test app. See [PHASE4_SECURITY_REPORT.md](PHASE4_SECURITY_REPORT.md) for the assessment scope, actual results, confirmed fix, and remaining risks.

For TOTP recovery: use one saved recovery code at sign-in if the authenticator is unavailable; each code works once. If both the authenticator and all recovery codes are lost, this local project has no self-service reset. Verify the account owner and perform an administrator-assisted local reset. Back up and retain the matching `.totp.key`; without it, TOTP secrets in a database backup cannot be decrypted.

## API overview

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/session` | Check the current session |
| `POST` | `/api/register` | Create an account |
| `POST` | `/api/login` | Sign in |
| `POST` | `/api/logout` | Sign out |
| `GET` | `/api/bootstrap` | Load account, budget, and transactions |
| `POST` | `/api/transactions` | Add a transaction |
| `PATCH` | `/api/transactions/{id}` | Edit an owned transaction |
| `DELETE` | `/api/transactions/{id}` | Delete an owned transaction |
| `PATCH` | `/api/budget` | Update the monthly budget |
| `GET` | `/api/security/summary` | Load the signed-in account's security events and alerts |
| `POST` | `/api/security/alerts/{id}/acknowledge` | Acknowledge an owned security alert |
| `POST` | `/api/security/totp/setup` | Start TOTP enrollment |
| `POST` | `/api/security/totp/confirm` | Confirm enrollment and issue recovery codes |
| `POST` | `/api/security/totp/disable` | Disable TOTP after password and code verification |
| `POST` | `/api/login/totp` | Complete a pending TOTP sign-in challenge |

This is an educational local-development project, not a production financial service. Do not expose the development server to the public internet. Any future public deployment requires HTTPS end to end, a production-grade WSGI server, correctly configured TLS-aware proxy settings, `Secure` cookies, shared rate limiting, security review, backups, and managed secret/configuration practices. Do not trust forwarded host or scheme headers unless they are set by a trusted proxy. The seeded demo account is intended only for local demonstration.