# Security Test Cases

Authorized local lab only. Cases cover detection of insecure lab behavior and verification of secure baseline controls.

## Legend

- **Detect**: asserts vulnerable behavior when `LAB_MODE=true`
- **Control**: asserts secure behavior when `LAB_MODE=false`
- **Matrix**: covered in `tests/test_authz_matrix.py`

---

## TC-S-001 — Username enumeration

| Field | Detail |
|-------|--------|
| Category | Authentication |
| Priority | P0 |
| Mode coverage | Detect + Control |
| Endpoint | `POST /api/login` |
| Detect expected | Distinct error details |
| Control expected | Identical generic error |
| Finding | SEC-004 |
| Automation | `test_lab_user_enumeration_via_distinct_errors`, `test_secure_mode_no_user_enumeration` |

## TC-S-002 — Predictable session token

| Field | Detail |
|-------|--------|
| Category | Authentication |
| Detect | `lab-token-{username}` |
| Control | Random token length ≥ 20 |
| Automation | `test_lab_predictable_session_token`, `test_secure_mode_random_session_token` |

## TC-S-003 — Token abuse

| Field | Detail |
|-------|--------|
| Category | Authentication |
| Cases | missing bearer, wrong token, forged lab token, empty bearer, malformed scheme |
| Control expected | 401 |
| Automation | `test_token_abuse_*` |

## TC-S-004 — User profile IDOR

| Field | Detail |
|-------|--------|
| Category | Authorization (horizontal) |
| Detect | alice GET `/api/users/2` → 200 + sensitive fields |
| Control | 403 |
| Finding | SEC-001 |
| Matrix | yes |

## TC-S-005 — Order read IDOR

| Field | Detail |
|-------|--------|
| Category | Authorization (horizontal) |
| Detect | alice GET `/api/orders/201` → 200 |
| Control | 403 |
| Matrix | yes |

## TC-S-006 — Order write IDOR (PATCH/DELETE)

| Field | Detail |
|-------|--------|
| Category | Authorization (horizontal write) |
| Detect | alice mutates/deletes bob order → 200 |
| Control | 403 |
| Finding | SEC-006 |
| Matrix | yes |

## TC-S-007 — Admin function auth

| Field | Detail |
|-------|--------|
| Category | Authorization (vertical) |
| Detect | alice GET `/api/admin/users` → 200 |
| Control | 403; admin → 200 without sensitive keys |
| Finding | SEC-003 |
| Matrix | yes |

## TC-S-008 — Listing scope / tenancy

| Field | Detail |
|-------|--------|
| Category | Authorization (collection) |
| Detect | alice list includes all owners |
| Control | alice only owner_id=1; carol order 401 absent |
| Finding | SEC-007 |

## TC-S-009 — Sensitive field contract

| Field | Detail |
|-------|--------|
| Category | Data exposure |
| Control | forbidden keys never present on secure endpoints |
| Finding | SEC-002 |
| Automation | `tests/test_sensitive_fields.py` |

## TC-S-010 — Open redirect allow-list

| Field | Detail |
|-------|--------|
| Category | Redirect validation |
| Detect | external URL → 302 |
| Control | external / protocol-relative / unknown path → 400; `/health` → 302 |
| Finding | SEC-005 |

## TC-S-011 — Search controls (non-blacklist)

| Field | Detail |
|-------|--------|
| Category | Input / query safety |
| Control | max length 100; parameterized SQL; no `reflected` HTML field; SQLi-shaped strings treated as data |
| Explicit non-goal | regex SQLi/XSS blacklist as "security" |

## TC-S-012 — Email validation on profile update

| Field | Detail |
|-------|--------|
| Category | Input validation |
| Detect | invalid email accepted |
| Control | invalid → 400; valid → 200 |

---

Manual functional cases: [`functional-test-cases.md`](functional-test-cases.md)
