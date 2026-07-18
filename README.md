# Security QA Lab — Web/API Testing Portfolio

Dual-mode FastAPI lab for **authorized local Security QA practice**: intentional flaws under `LAB_MODE=true`, real secure baseline under `LAB_MODE=false`, and automated suites that both detect issues and verify controls.

[![security-qa-tests](https://github.com/qiaoliang999/security-qa-web-api-portfolio/actions/workflows/security-qa-tests.yml/badge.svg)](https://github.com/qiaoliang999/security-qa-web-api-portfolio/actions/workflows/security-qa-tests.yml)

> **Ethical use only.** Authorized local security lab. Do not deploy as production. Do not test systems you do not own or lack written permission to assess.

---

## For hiring managers / reviewers (60 seconds)

**Role signal:** Security QA (API authn/authz abuse cases + automated regression)

**What you can verify in this repo:**

- Dual-mode lab: intentional flaws (`LAB_MODE=true`) vs secure baseline with real controls (`LAB_MODE=false`) — not payload blacklists
- Parametrized authorization matrix (roles × resources × methods × expected status)
- Structured findings with CVSS 3.1 vectors and request/response evidence samples
- CI runs lab detection **and** secure-control verification as separate jobs (JUnit/HTML artifacts)
- Documented methodology and severity rubric suitable for portfolio review

**Start here (3 links):**

1. Authz matrix tests → [`tests/test_authz_matrix.py`](tests/test_authz_matrix.py)
2. Sample Critical finding → [`reports/SEC-003-missing-function-level-auth.md`](reports/SEC-003-missing-function-level-auth.md)
3. Assessment methodology → [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md)

CI workflow: [`.github/workflows/security-qa-tests.yml`](.github/workflows/security-qa-tests.yml)

---

## What this is

A small multi-role, multi-object API used to practice:

1. Abuse-case design (authn, horizontal/vertical authz, write IDOR, data exposure, redirect)
2. Automated security testing with pytest + FastAPI TestClient
3. Structured defect reporting (CVSS 3.1 + evidence samples)
4. Fix verification against a secure baseline that uses **real controls** (not payload blacklists)

Methodology: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md)  
Severity rubric: [`docs/SEVERITY.md`](docs/SEVERITY.md)

---

## Architecture

```text
app/
  main.py          # app factory + HTML chrome
  config.py        # LAB_MODE, seed metadata, redirect allow-list
  db.py            # SQLite, seed, per-test reset
  security.py      # PBKDF2 password hashing
  models.py        # Pydantic DTOs (response allow-lists)
  auth.py          # get_current_user, require_roles, ownership helpers
  routers/         # auth, users, orders, admin, search
tests/
  test_authz_matrix.py   # roles × resources × methods × status
  test_authorization.py  # IDOR / BFLA / write IDOR
  test_auth.py           # authn, enumeration, token abuse
  test_sensitive_fields.py
  test_input_validation.py
  helpers/contracts.py   # forbidden-key assertions
reports/           # one finding per file + evidence/
```

| Mode | Behavior |
|------|----------|
| `LAB_MODE=true` | Intentional BOLA/BFLA, write IDOR, oversharing DTOs, open redirect, enumeration |
| `LAB_MODE=false` | Central authz dependencies, hashed passwords, public DTO allow-lists, redirect **path map**, scoped listings |

Secure mode does **not** claim “SQLi/XSS prevention” via regex blacklists. Search uses parameterized SQL, length limits, and ownership scoping.

---

## Demo accounts (local only)

| Username | Password    | Role  | org_id |
|----------|-------------|-------|--------|
| alice    | password123 | user  | 10     |
| bob      | password123 | user  | 10     |
| carol    | password123 | user  | 20     |
| admin    | admin       | admin | 10     |

Fictional credentials. Passwords are stored as PBKDF2 digests in SQLite.

---

## Quick start

```bash
cd security-qa-web-api-portfolio
python -m venv .venv
source .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate
pip install -r requirements.txt

# Run API (lab mode default)
export LAB_MODE=true
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Secure baseline
export LAB_MODE=false
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

- OpenAPI: http://127.0.0.1:8000/docs  
- Health: http://127.0.0.1:8000/health  

### Tests

```bash
# Full API suite (in-process; no server required) — primary regression gate
pytest -q -m "not ui"

# By marker (prefer markers over free-text node-id filters)
pytest -q -m authz
pytest -q -m authn
pytest -q -m security
pytest -q -m smoke

# Single module
pytest -q tests/test_authz_matrix.py
pytest -q tests/test_authorization.py

# With artifacts (same shape as CI uploads)
mkdir -p artifacts
pytest -q -m "not ui" \
  --junitxml=artifacts/junit.xml \
  --html=artifacts/report.html --self-contained-html
```

Methodology command reference: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md#exact-commands-local)

Optional UI smoke (requires Playwright browsers):

```bash
python -m playwright install chromium
pytest -q -m ui
```

---

## Findings (lab mode)

| ID | Severity | Title |
|----|----------|-------|
| SEC-001 | High | IDOR on user profiles |
| SEC-002 | High | Sensitive data exposure in API responses |
| SEC-003 | Critical | Missing function-level authorization on admin API |
| SEC-004 | Medium | Username enumeration via auth errors |
| SEC-005 | Medium | Open redirect |
| SEC-006 | High | Horizontal write IDOR on orders |
| SEC-007 | Medium | Unscoped order listing |

Details and CVSS vectors: [`reports/`](reports/README.md)  
Evidence samples: [`reports/evidence/`](reports/evidence/)

---

## CI

GitHub Actions workflow [`.github/workflows/security-qa-tests.yml`](.github/workflows/security-qa-tests.yml):

| Job | Purpose |
|-----|---------|
| `lab-detection` | Full suite with `LAB_MODE=true`; junit/html artifacts |
| `secure-controls` | Full suite with `LAB_MODE=false`; junit/html artifacts |
| `static-qa` | `pip-audit` + `bandit` (best effort, non-blocking) |
| `ui-smoke` | Optional Playwright (non-blocking) |

Fixtures still force per-test mode explicitly; CI env documents the dual baseline.

---

## Residual limitations (honest)

- Session model is an opaque bearer map in SQLite — not JWT/OAuth2/OIDC.
- No rate limiting, account lockout, CSRF (cookie-less API), or MFA.
- Tenancy is a simple `org_id` column, not a full multi-tenant product model.
- Lab mode remains intentionally vulnerable for training; do not expose it on a network.
- Playwright coverage is smoke-level only; primary evidence is API automation.
- CVSS scores are analyst-applied for portfolio realism; re-score for your org's threat model.

---

## License

MIT — see [LICENSE](LICENSE)
