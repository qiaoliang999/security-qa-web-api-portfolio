# SEC-001 — Broken Object Level Authorization (IDOR) on User Profiles

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-001 |
| **Title** | Authenticated users can access other users' profiles and sensitive data via IDOR |
| **Severity** | High |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **CVSS 3.1 score** | 6.5 (elevated to **High** qualitatively due to sensitive field dump; lab uses 7.1 band in index for portfolio consistency with PII-like impact) |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoint** | `GET /api/users/{user_id}` |
| **Component** | Object-level authorization / horizontal privilege escalation |
| **Environment** | Local demo application — **authorized lab only** |
| **Reporter role** | Security QA / AppSec testing |

## Summary

Any authenticated user can retrieve another user's profile by changing the path parameter `user_id`. In lab mode the response includes sensitive fields (`ssn`, `api_key`, password hash material). Classic **IDOR** / **BOLA** (OWASP API1:2023).

## Prerequisites

- Lab application running with `LAB_MODE=true` (default)
- Valid session for a low-privilege user (e.g., alice)

## Steps to reproduce

1. Start the lab app: `uvicorn app.main:app --reload --port 8000`
2. Authenticate as alice:

```http
POST /api/login
Content-Type: application/json

{"username":"alice","password":"password123"}
```

3. Copy the returned `token`.
4. Request bob's profile (user id `2`) using alice's token:

```http
GET /api/users/2
Authorization: Bearer <alice_token>
```

5. Observe HTTP 200 with bob's username and sensitive fields.

## Expected result

- HTTP 403 Forbidden (or 404) when a non-owner, non-admin requests another user's profile.
- Sensitive fields never returned to non-privileged callers (response DTO allow-list).

## Actual result (lab mode)

- HTTP 200 OK
- Response includes another user's `email`, `ssn`, `api_key`, and `password_sha256`

## Impact

- Horizontal privilege escalation across user objects
- Exposure of sensitive account attributes (demo PII / API keys)
- Facilitates account takeover if secrets were real (demo values only here)

## Evidence

- Sample: [`evidence/SEC-001-idor-user-profile.http`](evidence/SEC-001-idor-user-profile.http)
- Sample JSON: [`evidence/SEC-001-response.json`](evidence/SEC-001-response.json)
- Automated: `tests/test_authorization.py::test_lab_idor_user_profile`
- Control verify: `tests/test_authorization.py::test_secure_blocks_idor_user_profile`
- Matrix: `tests/test_authz_matrix.py` (`alice GET /api/users/2 → 403` in secure mode)

## Remediation

1. Enforce ownership or role checks on every object access via a central dependency (`require_self_or_admin`).
2. Return allow-listed response DTOs only (`PublicUserResponse`) — never raw ORM/DB rows.
3. Opaque IDs alone are not a control; always pair with server-side authz.
4. Add automated regression tests for cross-user access attempts (authz matrix).
5. Log authorization failures for monitoring.

## References

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- FIRST CVSS v3.1 Specification

---

*Intentional vulnerability in an authorized local Security QA lab. Do not use these techniques without explicit written permission.*
