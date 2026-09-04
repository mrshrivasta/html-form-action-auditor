# HTML Form Action Auditor

A real, no-mock-data security auditing tool that issues a single HTTP GET request to a URL you authorize, parses the **actual returned HTML** with a real HTML parser, and audits **every real `<form>` element** on the page for cross-origin submission targets, password fields submitted over plain HTTP or via `GET`, forms missing an apparent CSRF token field, and dangerous `javascript:`/`data:` action URI schemes.

Available as both a **command-line tool** and a **full multi-page web application**.

Developed by **Karanam Shrivasta**
GitHub: https://github.com/mrshrivasta
LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

---

## ⚠️ Disclaimer (read before use)

This tool sends **real HTTP requests** to whatever URL you provide it. It does not use sample data, fixtures, or simulated responses — every finding is derived from the actual HTML received from the target server at scan time.

- **Non-destructive by design.** Each scan is exactly one standard GET request. This tool only *reads and parses* the HTML the server already returned — it never submits any form, never sends form data anywhere, and never follows a form's action URL.
- **Authorized use only.** Only scan URLs and systems that you own, or that you have explicit, contractual, written authorization to test. Sending requests to third-party systems without authorization may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), similar computer-crime laws in other jurisdictions, and the target's Terms of Service — even a single, harmless-looking GET request.
- **No warranty.** This software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.
- **No liability.** The author, Karanam Shrivasta, accepts no liability for any damage, data loss, downtime, legal consequences, financial loss, or any other harm arising from the use, misuse, or inability to use this software.
- **Not a professional audit.** This tool is an educational and productivity aid. It does not replace a certified penetration test, a compliance audit (PCI-DSS, SOC 2, ISO 27001, etc.), or a professional security assessment performed by a qualified practitioner.
- **You are responsible.** By using this tool you accept full responsibility for how you use it and for obtaining any necessary authorization before scanning a target.

---

## Who should use this project

- Web developers and frontend engineers verifying their own forms submit to the correct origin, over HTTPS, with the expected CSRF protections.
- AppSec engineers doing a quick, safe HTML-level review of form security hygiene before a deeper, authorized manual assessment.
- QA teams adding an automated regression check that no form regresses to plaintext HTTP or a GET-based credential submission.
- Students and educators studying real-world HTML form security patterns with a genuine, working, non-destructive tool.

## Why use this project

A page's forms are where user trust and user data most directly meet the server — and small mistakes there (a stray cross-origin action, a password field left on `GET`, a login form still pointed at `http://`) are easy to introduce and easy to miss in review. This tool automates a real, parser-based audit of every form on a page using a single real HTTP request, with clear severities, a full audit trail (scan logs, alerts, incidents), CSV reporting, and six chart types for trend visibility — all self-hosted, all open, all inspectable.

---

## Detection Rules

Every rule below is evaluated against the **actual `<form>` elements** parsed from the real HTML returned by the one real HTTP GET request made during a scan. A single scan can produce multiple findings per rule if the page has multiple offending forms.

| Rule ID | Name | Severity | What it checks |
|---|---|---|---|
| FAA-001 | Form Action Points to a Different Origin | Medium | A form's action attribute resolves to a different scheme+host than the page itself. |
| FAA-002 | Password Form Submits Over Plain HTTP | **Critical** | A form with a password field submits to a plain `http://` URL. |
| FAA-003 | Password Form Uses GET Method | High | A form with a password field uses `method="GET"`, exposing credentials in the URL/history/logs. |
| FAA-004 | POST Form Missing Apparent CSRF Token Field | Medium | A `POST` form has no hidden field whose name resembles a CSRF/anti-forgery token. |
| FAA-005 | Form Action Uses javascript:/data: URI Scheme | High | A form's action uses an unusual `javascript:` or `data:` scheme instead of a normal URL. |
| FAA-006 | Form Missing action Attribute (Implicit Self-Submit) | Low (informational) | A form has no `action` attribute and implicitly submits to the current page URL. |
| FAA-000 | Target Unreachable | Low (informational) | The target could not be reached (DNS failure, connection refused/timeout, TLS error, network policy block). Not a form finding — an operational note. |

---

## Architecture

```
html-form-action-auditor/
├── Authentication        # app/auth — register/login/logout, Flask-Login sessions, hashed passwords
├── Dashboard              # app/dashboard — run a real scan, view live counters and recent scans
├── Security Engine        # app/security_engine — fetches real HTML, parses real <form> elements
├── Detection Rules        # app/detection_rules — 6 pure functions evaluating real parsed forms
├── Logs                   # app/logs — full scan history / audit trail, per-scan detail view
├── Alerts                 # app/alerts — generated from findings by severity threshold
├── Incident Management    # app/incident_management — track/triage/resolve alert-driven incidents
├── Analytics               # app/analytics — 6 real chart types (pie, bar, line, radar, doughnut, polar area)
├── Reports                 # app/reports — CSV export of findings
├── Settings                 # app/settings — per-user alert threshold and notification preferences
├── Database                 # app/database/models.py — SQLAlchemy models (SQLite by default)
├── CLI                       # cli/main.py — standalone command-line scanner
├── Web Application            # app/ (Flask app factory, blueprints, templates, static assets)
├── Tests                       # tests/ — rule-level unit tests + real local-server engine tests
├── Documentation                # this README
└── README.md
```

---

## Setup & Run

### Requirements
- Python 3.9+
- pip

### Install

```bash
cd html-form-action-auditor
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the web application

```bash
python3 run.py
```

Then open `http://127.0.0.1:5000` in your browser, register an account, and run your first scan from the Dashboard by entering a URL you are authorized to test.

### Run the CLI

```bash
# Basic scan
python3 cli/main.py scan https://your-authorized-target.example.com

# JSON output (for piping into other tools)
python3 cli/main.py scan https://your-authorized-target.example.com --json

# Export findings to CSV
python3 cli/main.py scan https://your-authorized-target.example.com --csv findings.csv

# List all detection rules
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings were produced (CI/CD friendly) and `0` on a clean scan.

### Run the tests

```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

Tests include rule-level unit tests against synthetic-but-realistic parsed-form dicts, a real-HTML-parsing unit test against a hand-written HTML fixture, and a genuine end-to-end test that boots a real local HTTP server on an ephemeral `127.0.0.1` port serving real HTML with real forms, then performs an actual HTTP request + real parse against it via the real Security Engine — no third-party network calls are made during testing, and no form is ever submitted.

---

## Frequently Asked Questions

**What does the HTML Form Action Auditor check?**
It issues a single real HTTP GET request to a URL you authorize, parses the actual returned HTML, and audits every real form element for a cross-origin action, a password field submitted over plain HTTP or via GET, a missing CSRF token field, or a dangerous javascript:/data: action URI — never sample data, and no form is ever submitted.

**Who should use the HTML Form Action Auditor?**
Web developers and security engineers auditing form security (action targets, transport, and CSRF hygiene) on sites and applications they own or are explicitly authorized to test.

**Is the HTML Form Action Auditor a replacement for a professional security audit?**
No. It is an educational and productivity aid only. It does not replace a certified penetration test, compliance audit, or professional security assessment. See the disclaimer in the README.

**Does the missing-CSRF-field check mean the form is definitely vulnerable to CSRF?**
No — it's a heuristic. Some frameworks protect against CSRF using same-site cookies, custom headers, or other mechanisms that don't involve a hidden form field. Treat FAA-004 as "worth confirming," not a definitive vulnerability.

**Does this tool submit any forms it finds?**
No, never. It only parses the HTML markup that was already returned by the single GET request. No form is ever submitted, and no data is ever sent to any form action URL.

---

## License & Attribution

Developed by **Karanam Shrivasta**.
GitHub: https://github.com/mrshrivasta · LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

Provided for authorized security auditing and educational use only. See the Disclaimer section above. No warranty of any kind is provided.
