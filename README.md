# Security QA Web/API Portfolio

Resume-ready portfolio project demonstrating **Security QA / Application Security Testing** skills: intentional local lab API, automated security tests, structured defect reports, and dual-mode (lab vs secure) regression design.

> **Ethical use only.** This application is an **authorized local security lab**. Do not deploy it publicly as a production service. Do not test systems you do not own or lack explicit written permission to assess.

**GitHub user:** [qiaoliang999](https://github.com/qiaoliang999)

---

## Purpose

Showcase practical Security QA competence for remote job applications:

- Design and run security-focused API test cases (authn, authz/IDOR, input validation, data exposure)
- Document findings in industry-style defect reports (severity, repro, impact, remediation)
- Build automation with **pytest** + **httpx/TestClient** and optional **Playwright** UI checks
- Demonstrate secure baseline controls via a `LAB_MODE` flag for regression confidence

---

## What this demonstrates for Security QA roles

| Skill | Evidence in this repo |
|-------|------------------------|
| Threat-informed test design | Cases mapped to OWASP API Top 10 themes |
| Broken access control testing | IDOR on users/orders; missing admin function auth |
| Authn/session testing | Enumeration, predictable tokens, negative login cases |
| Sensitive data exposure checks | Response field allow-listing verification |
| Input validation / boundary tests | XSS/SQLi-shaped payloads, length limits, open redirect |
| Defect reporting | Markdown findings under `reports/` |
| Automation & CI | pytest suite + GitHub Actions workflow |
| Secure vs vulnerable baselines | `LAB_MODE=true/false` dual verification |

---

## Architecture

```text
Client (pytest / browser)
        |
        v
 FastAPI app (app/main.py)
        |
        +-- LAB_MODE=true  -> intentional vulnerabilities (default)
        +-- LAB_MODE=false -> secure baseline controls
        |
 In-memory demo users & orders (no real secrets / no external services)
```

### Intentional lab issues (when `LAB_MODE=true`)

1. **IDOR** on `GET /api/users/{id}` and `GET /api/orders/{id}`
2. **Sensitive data exposure** in login/profile responses
3. **Missing function-level authorization** on `GET /api/admin/users`
4. **Username enumeration** via distinct auth errors + predictable session tokens
5. **Open redirect** and weak search input validation / reflection

When `LAB_MODE=false`, the same endpoints enforce authorization, generic auth errors, random tokens, redirect allow-listing, and input checks. Automated tests cover **both** detection and control verification.

---

## Tech stack

- Python 3.11+
- FastAPI + Uvicorn
- pytest + FastAPI TestClient (Starlette; HTTPX-based)
- Playwright (optional UI smoke)
- GitHub Actions CI
- Markdown findings & test-case docs

---

## Repository layout

```text
security-qa-web-api-portfolio/
├── app/                      # Lab API application
│   ├── main.py
│   └── config.py
├── tests/                    # Security + functional automation
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_authorization.py
│   ├── test_input_validation.py
│   └── test_ui_playwright.py
├── reports/                  # Security findings (defect reports)
├── test-cases/               # Manual/functional + security case docs
├── .github/workflows/        # CI
├── requirements.txt
├── pytest.ini
├── LICENSE
└── README.md
```

---

## Quick start

### 1. Create a virtual environment and install dependencies

```bash
cd security-qa-web-api-portfolio
python -m venv .venv

# Windows Git Bash / macOS / Linux
source .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate

pip install -r requirements.txt
```

Optional UI tests:

```bash
python -m playwright install chromium
```

### 2. Run the lab application

```bash
# Intentionally vulnerable (default)
set LAB_MODE=true          # Windows cmd
export LAB_MODE=true       # bash

uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- API docs: http://127.0.0.1:8000/docs  
- Health: http://127.0.0.1:8000/health  
- Login UI: http://127.0.0.1:8000/login  

Secure baseline:

```bash
export LAB_MODE=false
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Demo accounts (local only)

| Username | Password     | Role  |
|----------|--------------|-------|
| alice    | password123  | user  |
| bob      | password123  | user  |
| admin    | admin        | admin |

These are fictional demo credentials for a local lab — not real secrets.

### 3. Run tests

```bash
# From repo root with venv active
pytest -q
```

API/security tests use in-process TestClient fixtures and do not require a running server. Playwright tests start a temporary local server and skip cleanly if browsers are missing.

---

## Sample findings summary

| ID | Severity | Title |
|----|----------|-------|
| SEC-001 | High | IDOR on user profiles |
| SEC-002 | High | Sensitive data exposure in API responses |
| SEC-003 | Critical | Missing function-level authorization on admin users API |
| SEC-004 | Medium | Username enumeration via authentication error messages |
| SEC-005 | Medium | Open redirect and missing search input validation |

Full write-ups: [`reports/`](reports/README.md)

---

## Test suites

| Module | Focus |
|--------|-------|
| `tests/test_auth.py` | Login happy/negative, enumeration, tokens, sensitive login fields |
| `tests/test_authorization.py` | IDOR users/orders, listing scope, admin BFLA |
| `tests/test_input_validation.py` | Search payloads, open redirect, email validation, unauthenticated gates |
| `tests/test_ui_playwright.py` | Login page + lab home smoke (optional) |

Manual cases: [`test-cases/`](test-cases/)

---

## Design note: lab detection vs secure controls

This project intentionally uses **dual-mode testing**:

- **Lab fixtures** assert that insecure behavior is detectable (what a Security QA would file).
- **Secure fixtures** assert that remediations hold (regression / control verification).

That mirrors a real workflow: find → report → verify fix → prevent regression.

---

## Ethical / legal note

- Local demonstration and portfolio use only
- No malware, no weaponized exploits, no targeting of third-party systems
- All “sensitive” values are fake demo data
- Always obtain authorization before security testing

---

## License

MIT — see [LICENSE](LICENSE)
