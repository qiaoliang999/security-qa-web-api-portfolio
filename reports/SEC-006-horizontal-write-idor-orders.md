# SEC-006 — Horizontal Write IDOR on Orders (PATCH/DELETE)

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-006 |
| **Title** | Authenticated users can modify or delete other users' orders |
| **Severity** | High |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L` |
| **CVSS 3.1 score** | **7.1** → qualitative **High** (integrity impact); index uses **8.1** when considering availability via delete |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoints** | `PATCH /api/orders/{order_id}`, `DELETE /api/orders/{order_id}` |
| **Component** | Write-side object-level authorization |
| **Environment** | Local demo — **authorized lab only** |

## Summary

Read IDOR is common in portfolios; **write-side** ownership checks are often missing. Lab mode allows any authenticated principal to PATCH/DELETE any order. Secure mode uses `require_order_write` (owner or admin).

## Prerequisites

- `LAB_MODE=true`
- Alice token; target order owned by bob (`201`)

## Steps to reproduce

```http
PATCH /api/orders/201
Authorization: Bearer <alice_token>
Content-Type: application/json

{"notes":"hijacked by alice"}
```

```http
DELETE /api/orders/201
Authorization: Bearer <alice_token>
```

## Expected result

HTTP 403 for non-owner non-admin writers.

## Actual result (lab mode)

HTTP 200; bob's order mutated or removed.

## Impact

- Integrity compromise of another user's business objects
- Data loss via unauthorized delete
- Fraud / order-tampering scenarios in real commerce APIs

## Evidence

- Automated: `tests/test_authorization.py::test_lab_horizontal_write_idor_patch_order`
- Automated: `tests/test_authorization.py::test_lab_horizontal_write_idor_delete_order`
- Control: `tests/test_authorization.py::test_secure_blocks_horizontal_write_idor_patch`
- Matrix: `alice PATCH/DELETE /api/orders/201 → 403` (secure)

## Remediation

1. Shared write-side helper: `require_order_write(current, order)`.
2. Apply to **every** mutation method (PATCH, PUT, DELETE), not only GET.
3. Prefer server-derived ownership over body-supplied `owner_id`.
4. Authz matrix covering methods × actors × objects.

## References

- OWASP API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-863: Incorrect Authorization

---

*Authorized local lab finding only.*
