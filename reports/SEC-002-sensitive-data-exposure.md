# SEC-002 — Sensitive Data Exposure in Authentication Responses

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-002 |
| **Title** | Login and profile APIs return sensitive fields (SSN, API key, password hash) |
| **Severity** | High |
| **CVSS (qualitative)** | High — excessive data exposure |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoints** | `POST /api/login`, `GET /api/me`, `GET /api/users/{user_id}`, `GET /api/admin/users` |
| **Component** | Response filtering / data minimization |
| **Environment** | Local demo application — **authorized lab only** |
| **Reporter role** | Security QA / AppSec testing |

## Summary

Successful authentication and subsequent identity endpoints return sensitive user attributes that should never be present in client-facing API responses for a normal application. This maps to **OWASP API3:2023 Broken Object Property Level Authorization** / excessive data exposure patterns and classic sensitive data exposure.

## Prerequisites

- Lab application running with `LAB_MODE=true`
- Knowledge of a valid demo credential

## Steps to reproduce

1. Authenticate:

```http
POST /api/login
Content-Type: application/json

{"username":"alice","password":"password123"}
```

2. Inspect the JSON response `user` object.
3. Optionally call:

```http
GET /api/me
Authorization: Bearer <token>
```

4. Confirm sensitive keys are present.

## Expected result

Login / me responses include only need-to-know public profile fields, for example:

- `id`, `username`, `role`, `email` (if required by UI)
- No SSN, API keys, password hashes, or internal session metrics

## Actual result (lab mode)

Response includes at least:

- `ssn`
- `api_key`
- `password_sha256`
- On login: `session_store_size` (internal operational detail)

## Impact

- Unnecessary expansion of the confidential data surface available to XSS, malicious JS, browser extensions, logs, and intercepting proxies
- Password hash material aids offline attacks if real hashes were used
- API keys enable unauthorized API access if they were real secrets
- Internal metrics leakage can assist attackers in fingerprinting session handling

## Evidence notes

- Automated: `tests/test_auth.py::test_lab_login_leaks_sensitive_fields`
- Secure baseline: `tests/test_auth.py::test_secure_login_no_sensitive_fields`
- Related admin overshare: `tests/test_authorization.py::test_lab_missing_admin_authorization`

## Remediation

1. Define explicit response DTOs / schemas with allow-listed fields
2. Separate internal models from API serializers; never return raw user records
3. Store password hashes with a modern KDF (bcrypt/argon2) and **never** return them
4. Treat API keys as secrets: show only once at creation, store hashed where possible
5. Add contract tests that fail CI if sensitive keys appear in public responses
6. Review logging to ensure sensitive fields are redacted

## References

- OWASP API Security Top 10 — API3:2023 Broken Object Property Level Authorization
- OWASP Top 10 — A02 Cryptographic Failures / sensitive data exposure themes
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-359: Exposure of Private Personal Information to an Unauthorized Actor

---

*This report documents an intentional vulnerability in an authorized local Security QA lab application. Do not use these techniques against systems without explicit written permission.*
