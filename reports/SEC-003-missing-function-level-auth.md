# SEC-003 — Missing Function-Level Authorization on Admin Users API

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-003 |
| **Title** | Non-admin authenticated users can list all users via admin endpoint |
| **Severity** | Critical |
| **CVSS (qualitative)** | Critical — vertical privilege escalation + mass data exposure |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoint** | `GET /api/admin/users` |
| **Component** | Function-level authorization / role-based access control |
| **Environment** | Local demo application — **authorized lab only** |
| **Reporter role** | Security QA / AppSec testing |

## Summary

The admin-only users listing endpoint validates authentication but does not enforce role-based authorization when `LAB_MODE=true`. Any logged-in user can retrieve the full user directory with sensitive attributes. This is **Broken Function Level Authorization** (OWASP API5:2023) combined with excessive data exposure.

## Prerequisites

- Lab application running with `LAB_MODE=true`
- Valid low-privilege session (alice or bob)

## Steps to reproduce

1. Login as a normal user:

```http
POST /api/login
Content-Type: application/json

{"username":"alice","password":"password123"}
```

2. Call the admin endpoint with alice's token:

```http
GET /api/admin/users
Authorization: Bearer <alice_token>
```

3. Observe HTTP 200 and a list of all users including sensitive fields.

## Expected result

- HTTP 403 Forbidden for non-admin principals
- Even for admins, responses should omit secrets unless a separate privileged break-glass flow exists

## Actual result (lab mode)

- HTTP 200
- Full user list with `ssn`, `api_key`, and password hash fields for each account

## Impact

- Vertical privilege escalation to administrative data access
- Mass disclosure of user directory and sensitive attributes
- Enables targeted attacks against every account in the system
- Undermines any assumed isolation between user and admin functions

## Evidence notes

- Automated detection: `tests/test_authorization.py::test_lab_missing_admin_authorization`
- Secure control: `tests/test_authorization.py::test_secure_admin_endpoint_forbidden_for_user`
- Admin happy path secure mode: `tests/test_authorization.py::test_secure_admin_endpoint_allowed_for_admin`

## Remediation

1. Enforce explicit role checks on all admin routes server-side (never rely on UI hiding)
2. Centralize authorization (decorator/dependency/policy middleware) to avoid missed checks
3. Use deny-by-default routing for `/admin/*`
4. Add security regression tests for every privileged endpoint with a non-privileged principal
5. Consider separate admin service/network boundary for high-risk operations
6. Audit logs for privileged endpoint access

## References

- OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization
- OWASP Top 10 — A01 Broken Access Control
- CWE-285: Improper Authorization
- CWE-862: Missing Authorization

---

*This report documents an intentional vulnerability in an authorized local Security QA lab application. Do not use these techniques against systems without explicit written permission.*
