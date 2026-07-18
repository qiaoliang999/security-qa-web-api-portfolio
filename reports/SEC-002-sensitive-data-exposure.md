# SEC-002 — Sensitive Data Exposure in API Responses

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-002 |
| **Title** | Login and profile responses expose SSN, API keys, and password material |
| **Severity** | High |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **CVSS 3.1 score** | 6.5 (qualitative **High** — confidential credential-adjacent material in response body) |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoints** | `POST /api/login`, `GET /api/me`, `GET /api/users/{id}`, `GET /api/admin/users` |
| **Component** | Response serialization / field-level authorization |
| **Environment** | Local demo — **authorized lab only** |

## Summary

Lab-mode serializers intentionally return `ssn`, `api_key`, and `password_sha256` on multiple endpoints. Secure baseline uses Pydantic allow-list DTOs (`PublicUserResponse`) that cannot emit those keys.

## Prerequisites

- `LAB_MODE=true`
- Any valid credentials (or cross-user IDOR for others' data)

## Steps to reproduce

```http
POST /api/login
Content-Type: application/json

{"username":"alice","password":"password123"}
```

Inspect `user` object for `ssn`, `api_key`, `password_sha256`.

## Expected result

Public user projection only: `id`, `username`, `role`, `email`, `org_id`, `bio`.

## Actual result (lab mode)

Sensitive fields present on login, me, foreign profiles, and admin listing.

## Impact

- Confidentiality breach of PII-like attributes and API secrets
- Offline cracking support if password material leaks
- Amplifies impact of any IDOR / missing function auth finding

## Evidence

- Sample: [`evidence/SEC-002-login-leak.json`](evidence/SEC-002-login-leak.json)
- Automated: `tests/test_auth.py::test_lab_login_leaks_sensitive_fields`
- Contract: `tests/test_sensitive_fields.py` (secure mode forbids keys)

## Remediation

1. Response allow-lists (never "strip some fields" ad hoc on full models).
2. Separate admin vs public DTO only when truly needed; still withhold secrets.
3. Store passwords only as strong hashes (PBKDF2/bcrypt/argon2); never return them.
4. Automated contract tests that fail CI if forbidden keys appear.

## References

- OWASP API Security Top 10 — API3:2023 Broken Object Property Level Authorization
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-359: Exposure of Private Personal Information to an Unauthorized Actor

---

*Authorized local lab finding only.*
