# SEC-003 — Missing Function-Level Authorization on Admin Users API

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-003 |
| **Title** | Non-admin authenticated users can list all users via admin API |
| **Severity** | Critical |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` |
| **CVSS 3.1 score** | 7.1 (qualitative **Critical** when combined with sensitive field dump) |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoint** | `GET /api/admin/users` |
| **Component** | Function-level authorization / vertical privilege escalation |
| **Environment** | Local demo — **authorized lab only** |

## Summary

The admin user listing endpoint authenticates the caller but, in lab mode, does not verify `role == admin`. Any user token returns the full directory including sensitive fields. This is **Broken Function Level Authorization** (OWASP API5:2023).

## Prerequisites

- `LAB_MODE=true`
- Low-privilege session (alice)

## Steps to reproduce

```http
POST /api/login
Content-Type: application/json

{"username":"alice","password":"password123"}
```

```http
GET /api/admin/users
Authorization: Bearer <alice_token>
```

## Expected result

HTTP 403 Forbidden for non-admin roles.

## Actual result (lab mode)

HTTP 200 with full user list and sensitive attributes.

## Impact

- Vertical privilege escalation to admin-only data plane
- Mass disclosure of accounts and secrets
- Staging ground for further lateral movement

## Evidence

- Sample: [`evidence/SEC-003-admin-users.http`](evidence/SEC-003-admin-users.http)
- Automated: `tests/test_authorization.py::test_lab_missing_admin_authorization`
- Control: `tests/test_authorization.py::test_secure_admin_endpoint_forbidden_for_user`
- Matrix rows: `alice/bob/carol GET /api/admin/users → 403` (secure)

## Remediation

1. Central role dependency (`require_admin` / `require_roles("admin")`) on every admin route.
2. Deny by default; never rely on UI hiding of admin features.
3. Separate admin router with a shared dependency guard.
4. Authz matrix regression in CI.

## References

- OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization
- CWE-285: Improper Authorization
- CWE-862: Missing Authorization

---

*Authorized local lab finding only.*
