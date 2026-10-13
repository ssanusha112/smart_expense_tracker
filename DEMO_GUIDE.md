# Smart Expense Tracker Demo Guide

This guide is for a local classroom demonstration using synthetic data. Do not present real account credentials, real transaction details, or recovery codes. Keep the server bound to `127.0.0.1`; do not expose it to the internet.

## Prerequisites

- Python 3.10 or newer on Windows.
- PowerShell opened in the project folder.
- The `cryptography` package installed from `requirements.txt` for optional TOTP.

## Start An Isolated Demo Copy

Use a fresh temporary folder so the demonstration creates its own database instead of opening the project's existing `expense_tracker.db`:

```powershell
$demo = Join-Path $env:TEMP ("smart-expense-demo-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Path $demo | Out-Null
Copy-Item .\server.py, .\requirements.txt -Destination $demo
Copy-Item .\public -Destination (Join-Path $demo "public") -Recurse
Push-Location $demo
$env:HOST = "127.0.0.1"
$env:PORT = "8010"
py -3 -m pip install -r .\requirements.txt
py -3 server.py
```

Open <http://127.0.0.1:8010>. On first startup this isolated copy creates a new `expense_tracker.db` with synthetic sample records. Create a disposable account through **Create an account**; use a temporary password that is not used for any personal account. Stop the server with `Ctrl+C` when finished, then run `Pop-Location` in that PowerShell window. The original project database and its backups are not copied into this demo folder.

## Demonstration Sequence

1. **Authentication:** register the disposable account, sign in, and sign out. Explain that sessions are server-side and expire.
2. **Overview:** show monthly spending, remaining budget, income, savings rate, category totals, and six-month spending chart.
3. **Transactions:** add synthetic entries such as `Coffee`, `Bus pass`, and `Part-time income`, with plausible sample amounts and today's date. Search and filter the ledger, edit one entry, then delete that same synthetic entry.
4. **Budget:** set a small demonstration budget in Settings, observe the dashboard progress, then restore a reasonable sample value.
5. **CSV export:** export the synthetic ledger. To show formula neutralization, optionally add a synthetic description beginning with `=HYPERLINK("https://example.invalid","click")`, export, and inspect that the CSV cell is prefixed as text. Do not open untrusted CSVs from other sources.
6. **Security dashboard:** review the sign-in counts, account-scoped events, and TOTP status. To demonstrate an alert, sign out and make five incorrect password attempts for the disposable account within 15 minutes, then sign in correctly and show the warning. The local login limit is eight attempts per source IP per minute, so do not exceed that threshold.
7. **Optional TOTP:** only on the disposable account, choose **Set up two-factor**, follow the authenticator prompt, confirm a code, and save the one-time recovery codes in a safe temporary location. Sign out/in to demonstrate second-factor verification, then disable TOTP with a current code or unused recovery code. Do not enable TOTP on an account unless you have saved its recovery codes and backed up the matching `.totp.key`.

## Safe Test Data

Use only synthetic entries, for example:

| Description | Type | Category | Amount |
| --- | --- | --- | ---: |
| Coffee | Expense | Food | 4.50 |
| Bus pass | Expense | Transport | 18.00 |
| Course materials | Expense | Education | 12.75 |
| Part-time income | Income | Salary | 150.00 |

Use a future-proof sample password unique to this temporary demo account. Never include personal bank/card numbers, real pay details, personal addresses, or passwords in transaction notes.

## Presenter Notes

- The app has no bank connection, email delivery, SMS, or cloud service.
- Security alerts are heuristic; user mistakes can trigger them, and low-volume password spraying may not cross the threshold.
- Rate limiting is in memory and resets with the process. Local requests share the loopback address.
- Financial data is not encrypted at rest. The isolated demo avoids putting real data into the project database.
- The automated suite uses temporary databases: `py -3 -m unittest discover -s tests -v`.