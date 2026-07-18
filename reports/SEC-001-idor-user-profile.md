# SEC-001 — Broken Object Level Authorization (IDOR) on User Profiles

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-001 |
| **Title** | Authenticated users can access other users' profiles and sensitive data via IDOR |
| **Severity** | High |
| **CVSS (qualitative)** | High — confidentiality impact on account/PII-like demo data |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoint** | `GET /api/users/{user_id}` |
| **Component** | Object-level authorization / horizontal privilege escalation |
| **Environment** | Local demo application — **authorized lab only** |
| **Reporter role** | Security QA / AppSec testing |

## Summary

Any authenticated user can retrieve another user's profile by changing the path parameter `user_id`. In lab mode the response includes sensitive fields (`ssn`, `api_key`, password hash material). This is classic **Insecure Direct Object Reference (IDOR)** / **Broken Object Level Authorization (BOLA)** as described in OWASP API Security Top 10 (API1).

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
- Sensitive fields never returned to non-privileged callers.

## Actual result (lab mode)

- HTTP 200 OK
- Response includes another user's `email`, `ssn`, `api_key`, and `password_sha256`

Example (demo data only):

```json
{
  "id": 2,
  "username": "bob",
  "role": "user",
  "email": "bob@example.local",
  "ssn": "222-33-4444",
  "api_key": "bob-secret-key-demo-only",
  "password_sha256": "..."
}
```

## Impact

- Horizontal privilege escalation across user objects
- Exposure of sensitive account attributes
- Facilitates account takeover if API keys or similar secrets are real (demo values only in this lab)
- Potential privacy / regulatory risk in a real system (PII exposure)

## Evidence notes

- Automated coverage: `tests/test_authorization.py::test_lab_idor_user_profile`
- Secure control verification: `tests/test_authorization.py::test_secure_blocks_idor_user_profile`
- Manual check via OpenAPI UI at `/docs` also reproduces the issue

## Remediation

1. Enforce ownership (or role) checks on every object access:
   - allow if `current_user.id == target.id` or `current_user.role == admin`
2. Never expose secrets/PII in general profile APIs; use field-level authorization and least privilege
3. Prefer opaque resource IDs only if still paired with server-side authz (IDs alone are not a control)
4. Add automated regression tests for cross-user access attempts
5. Log authorization failures for monitoring

## References

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- OWASP Testing Guide — Authorization Testing
- CWE-639: Authorization Bypass Through User-Controlled Key

---

*This report documents an intentional vulnerability in an authorized local Security QA lab application. Do not use these techniques against systems without explicit written permission.*
