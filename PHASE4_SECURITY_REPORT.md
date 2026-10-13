# Phase 4 Security Assessment

Assessment date: 2026-10-09

## Scope

Reviewed `server.py`, the HTML/JavaScript/CSS frontend, README setup/security guidance, and the existing standard-library regression suite. Exercised the web application only on loopback. Automated tests used per-test temporary SQLite databases and temporary TOTP keys. Browser payload tests used a second loopback server with a disposable database and synthetic transactions. No attack payloads were submitted to the production database, and no user financial records were changed by the assessment.

This is a defensive project assessment, not a formal penetration test, source-code certification, or production readiness approval.

## Architecture And Features

- Python standard-library WSGI server serves static frontend files and JSON APIs.
- SQLite stores users, sessions, transactions, budgets, security events, alerts, and TOTP state.
- Plain HTML, CSS, and JavaScript render the responsive expense dashboard, transaction ledger, budgets, CSV export, Security page, and TOTP flows.
- TOTP secret encryption uses the `cryptography` package; the app otherwise uses Python's standard library.

## Controls Reviewed

- Passwords use salted PBKDF2-HMAC-SHA256; failed login checks use a dummy hash for unknown accounts.
- Sessions use random opaque IDs, server-side hashed IDs, expiration, HttpOnly/SameSite cookies, rotation on successful authentication, and revocation of the presented old session.
- State-changing authenticated requests require CSRF and same-origin Origin/Host validation. Login and registration require matching localhost Origin/Host.
- SQLite statements use bound parameters, request bodies are capped at 64 KB and parsed with duplicate-key rejection, and inputs are validated server-side.
- Transactions, budgets, security events, and alerts are scoped to the signed-in account.
- TOTP secrets are encrypted with Fernet; recovery codes are stored as hashes and consumed once. TOTP is opt-in.
- Content Security Policy, X-Content-Type-Options, Referrer-Policy, frame/resource isolation, permissions policy, and no-store headers are applied to app/API responses.
- Frontend transaction/event text is escaped; CSV formula-prefixed strings are neutralized.
- Security audit events contain account ID, event type, severity, and timestamp, not passwords, cookies, CSRF tokens, IPs, or transaction details.

## Confirmed Finding Fixed

Static 404 responses did not receive the normal security headers or `Cache-Control: no-store`. The 404 path now sends the shared security headers and no-store policy. An automated regression test verifies this response.

No confirmed SQL injection, authentication bypass, cross-account access, CSRF bypass, or rendered XSS was found in the paths exercised. This statement is limited to the tests and manual checks listed here; it is not a guarantee that the application has no vulnerabilities.

## Test Results

Command run:

```powershell
py -3 -m unittest discover -s tests -v
```

Result: **25 tests passed, 0 failed**, on temporary databases. Coverage included authentication and registration, session rotation/expiration, CSRF and Origin/Host rejection, account isolation, SQL-injection-shaped inputs, request validation/limits, generic errors, security headers including static 404, transaction CRUD, budget persistence, audit scope/privacy, alert thresholds/acknowledgement, RFC 6238 codes, encrypted TOTP enrollment, login challenges, recovery-code single use, and TOTP disable.

Browser checks on the isolated temporary app created two synthetic transactions through the normal API. Transaction rendering retained `<img>`/`<svg>` payloads as text and created zero corresponding DOM elements. CSV export neutralized an `=HYPERLINK(...)` payload and preserved CSV quote escaping. A separate read-only in-memory UI probe used synthetic alert text; it made no API mutation. No real financial values were used as attack payloads or exported.

Automated tests and end-to-end payload requests used temporary databases. The production database was only read by the already signed-in local page and the later read-only integrity/count comparison; it was not modified by testing. The production backup was opened only read-only for integrity and aggregate-count verification.

## Residual Risks And Limitations

- The built-in WSGI server is for local development and does not provide HTTPS. Do not expose it publicly. A public deployment needs a production server, end-to-end TLS, trusted proxy configuration, `Secure` cookies, and HSTS after HTTPS is correctly deployed.
- Login and registration throttles are in process memory, reset on restart, and do not coordinate across workers. Requests behind one proxy/IP may share a rate limit. A public service needs a shared limiter and monitoring.
- Audit events and alerts have no retention or pagination policy. A sufficiently large volume of known-account failures could grow the SQLite database; production needs bounded retention and disk monitoring.
- Failed attempts for unknown accounts cannot be assigned to an account, and the dashboard stores no IP, device, or location context. Alerts are heuristic and can be triggered by user mistakes; low-rate password spraying may not cross thresholds.
- SQLite financial fields and transaction notes are not encrypted at rest. Protect the database and every backup with operating-system access controls and storage encryption.
- TOTP's `.totp.key` is a local key file. Back it up securely with the database, restrict its Windows ACL, and use a managed secret store for deployment. Losing the key makes encrypted TOTP secrets unusable. Losing both an authenticator and all recovery codes requires local administrator recovery.
- The seeded demo account has public, fixed credentials and must not be enabled in a public deployment.
- The application has no password-reset/email recovery, centralized alert delivery, or account-wide session management UI.

## Future Improvements

Add an external/shared rate-limit store, bounded audit retention and paginated security history, password reset with verified ownership, account-wide session revocation, operational monitoring, backup/restore drills including the TOTP key, and deployment automation that enforces TLS and HSTS. Reassess the demo account and encryption-key storage before any deployment beyond localhost.