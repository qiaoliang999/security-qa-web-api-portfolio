# SEC-007 — Unscoped Order Listing (Broken Object Listing)

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-007 |
| **Title** | Authenticated users receive all tenants' orders from list endpoint |
| **Severity** | Medium |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **CVSS 3.1 score** | **6.5** Medium |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoint** | `GET /api/orders` |
| **Component** | Collection-level authorization / tenancy scope |
| **Environment** | Local demo — **authorized lab only** |

## Summary

Lab mode returns every order in the database to any authenticated user. Secure mode scopes non-admin listings to `owner_id == current.id` and `org_id == current.org_id` (simple tenant field).

## Prerequisites

- `LAB_MODE=true`
- Alice session

## Steps to reproduce

```http
GET /api/orders
Authorization: Bearer <alice_token>
```

Observe orders for bob, admin, and carol (other org).

## Expected result

Only alice's orders (org-scoped ownership).

## Actual result (lab mode)

Full order catalog including cross-tenant objects.

## Impact

- Confidentiality loss across users and orgs
- Business intelligence leakage
- Facilitates targeted IDOR against discovered IDs

## Evidence

- Automated: `tests/test_authorization.py::test_lab_list_orders_returns_all`
- Control: `tests/test_authorization.py::test_secure_list_orders_scoped`
- Tenancy: `tests/test_authorization.py::test_cross_tenant_order_not_listed_for_alice`

## Remediation

1. Default filter collections by owner (and tenant) at the query layer.
2. Admin-only unscoped listing with explicit role check.
3. Never trust client-provided `org_id` for authorization decisions.
4. List-scope regression tests per role.

## References

- OWASP API1:2023 (collection listing as BOLA variant)
- CWE-639: Authorization Bypass Through User-Controlled Key

---

*Authorized local lab finding only.*
