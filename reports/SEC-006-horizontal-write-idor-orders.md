# SEC-006 — Horizontal Write IDOR on Orders (PATCH/DELETE)

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-006 |
| **Title** | Authenticated users can modify or delete other users' orders |
| **Severity** | High |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L` |
| **CVSS 3.1 score** | **7.1** (qualitative **High** — integrity of foreign objects; elevates toward **8.1** when availability impact of delete is weighted fully) |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoints** | `PATCH /api/orders/{order_id}`, `DELETE /api/orders/{order_id}` |
| **Component** | Write-side object-level authorization |
| **Environment** | Local demo — **authorized lab only** |
| **Reporter role** | Security QA / AppSec testing |

## Summary

Read IDOR is common in portfolios; **write-side** ownership checks are often missing or applied only to GET. Lab mode allows any authenticated principal to PATCH or DELETE any order by id. Secure mode uses a shared `require_order_write` helper (owner or admin) on every mutation path.

## Prerequisites

- Lab application with `LAB_MODE=true` (default)
- Valid session for a low-privilege user (alice)
- Target object owned by another user (bob's order `201`)

## Steps to reproduce

1. Start the lab: `uvicorn app.main:app --reload --host 127.0.0.1 --port 8000`
2. Authenticate as alice and capture `token`:

```http
POST /api/login
Content-Type: application/json

{"username":"alice","password":"password123"}
```

3. Mutate bob's order (`owner_id = 2`) with alice's token:

```http
PATCH /api/orders/201
Authorization: Bearer <alice_token>
Content-Type: application/json

{"notes":"hijacked by alice"}
```

4. Optionally delete the foreign order:

```http
DELETE /api/orders/201
Authorization: Bearer <alice_token>
```

## Expected result

- HTTP **403 Forbidden** for non-owner, non-admin writers on PATCH and DELETE.
- Bob's order notes and existence remain unchanged when probed with bob's token.

## Actual result (lab mode)

- PATCH → HTTP **200**; `notes` rewritten to attacker-controlled value; `owner_id` still `2`.
- DELETE → HTTP **200** `{"detail":"deleted","id":201}`; bob subsequently gets 404/empty for that id.

## Impact

- Integrity compromise of another user's business objects (order amount, notes, status).
- Data loss via unauthorized delete (availability/integrity).
- Realistic fraud / order-tampering path for any multi-tenant commerce-style API.

## Evidence

| Artifact | Link |
|----------|------|
| HTTP transcript | [`evidence/SEC-006-write-idor.http`](evidence/SEC-006-write-idor.http) |
| Sample PATCH body | [`evidence/SEC-006-patch-response.json`](evidence/SEC-006-patch-response.json) |
| Lab detection (PATCH) | `tests/test_authorization.py::test_lab_horizontal_write_idor_patch_order` |
| Lab detection (DELETE) | `tests/test_authorization.py::test_lab_horizontal_write_idor_delete_order` |
| Secure control (PATCH) | `tests/test_authorization.py::test_secure_blocks_horizontal_write_idor_patch` |
| Secure control (DELETE) | `tests/test_authorization.py::test_secure_blocks_horizontal_delete_idor` |
| Cross-tenant write edge | `tests/test_authorization.py::test_secure_blocks_cross_tenant_order_write` |
| Authz matrix | `tests/test_authz_matrix.py` — `alice PATCH/DELETE /api/orders/201 → 403` (secure) |

## Remediation

1. **Centralize write-side ownership** — call a shared helper (`require_order_write(current, order)`) before any mutate/delete, never only on GET.
2. **Cover every mutation verb** — PATCH, PUT, DELETE, and any bulk update endpoints that accept object ids.
3. **Derive ownership server-side** — load the order by id from the data store; ignore any client-supplied `owner_id` in the body.
4. **Return consistent deny semantics** — 403 for authenticated-but-unauthorized; avoid leaking existence of out-of-scope ids if that is product policy (optional 404).
5. **Regress with an authz matrix** — roles × methods × object ids, including cross-tenant ids, so new endpoints cannot ship without write checks.
6. **Verify controls, not just detection** — keep dual-mode tests: lab proves the flaw is real; secure proves the helper holds after fix.

## References

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-863: Incorrect Authorization
- FIRST CVSS v3.1 Specification

---

*Intentional vulnerability in an authorized local Security QA lab. Do not use these techniques without explicit written permission.*
