# Security Test Cases

Authorized local lab only. Cases cover detection of insecure lab behavior and verification of secure baseline controls.

## Legend

- **Detect**: asserts vulnerable behavior when `LAB_MODE=true`
- **Control**: asserts secure behavior when `LAB_MODE=false`
- **Regression**: keeps insecure access patterns blocked / validated over time

---

## TC-S-001 — Username enumeration

| Field | Detail |
|-------|--------|
| Category | Authentication |
| Priority | P0 |
| Mode coverage | Detect + Control |
| Endpoint | `POST /api/login` |
| Steps | Compare error for unknown user vs wrong password |
| Detect expected | Distinct error details |
| Control expected | Identical generic error |
| Finding | SEC-004 |
| Automation | `test_lab_user_enumeration_via_distinct_errors`, `test_secure_mode_no_user_enumeration` |

## TC-S-002 — Predictable session token

| Field | Detail |
|-------|--------|
| Category | Session management |
| Priority | P0 |
| Endpoint | `POST /api/login` |
| Detect expected | Token equals `lab-token-<username>` |
| Control expected | Random token, not username-derived |
| Automation | `test_lab_predictable_session_token`, `test_secure_mode_random_session_token` |

## TC-S-003 — Sensitive fields on login

| Field | Detail |
|-------|--------|
| Category | Sensitive data exposure |
| Priority | P0 |
| Endpoint | `POST /api/login` |
| Detect expected | Response contains `ssn`, `api_key`, `password_sha256` |
| Control expected | Those keys absent |
| Finding | SEC-002 |
| Automation | `test_lab_login_leaks_sensitive_fields`, `test_secure_login_no_sensitive_fields` |

## TC-S-004 — IDOR user profile

| Field | Detail |
|-------|--------|
| Category | Authorization / BOLA |
| Priority | P0 |
| Endpoint | `GET /api/users/{id}` |
| Steps | Login as alice; request user id 2 |
| Detect expected | `200` + bob sensitive fields |
| Control expected | `403` |
| Finding | SEC-001 |
| Automation | `test_lab_idor_user_profile`, `test_secure_blocks_idor_user_profile` |

## TC-S-005 — IDOR order object

| Field | Detail |
|-------|--------|
| Category | Authorization / BOLA |
| Priority | P0 |
| Endpoint | `GET /api/orders/{id}` |
| Steps | Login as alice; request order 201 (bob) |
| Detect expected | `200` |
| Control expected | `403` |
| Automation | `test_lab_idor_order_access`, `test_secure_blocks_foreign_order` |

## TC-S-006 — Broken order listing scope

| Field | Detail |
|-------|--------|
| Category | Authorization |
| Priority | P1 |
| Endpoint | `GET /api/orders` |
| Detect expected | All owners returned for alice |
| Control expected | Only alice-owned orders |
| Automation | `test_lab_list_orders_returns_all`, `test_secure_list_orders_scoped` |

## TC-S-007 — Missing function-level authorization

| Field | Detail |
|-------|--------|
| Category | Authorization / BFLA |
| Priority | P0 |
| Endpoint | `GET /api/admin/users` |
| Steps | Call as alice |
| Detect expected | `200` full user dump with secrets |
| Control expected | `403` |
| Finding | SEC-003 |
| Automation | `test_lab_missing_admin_authorization`, `test_secure_admin_endpoint_forbidden_for_user` |

## TC-S-008 — Search reflected payload

| Field | Detail |
|-------|--------|
| Category | Input validation |
| Priority | P1 |
| Endpoint | `POST /api/search` |
| Payload | `<script>alert(1)</script>` |
| Detect expected | Payload reflected in response |
| Control expected | `400` |
| Finding | SEC-005 |
| Automation | `test_lab_search_reflects_unsanitized_payload`, `test_secure_search_rejects_script_payload` |

## TC-S-009 — SQLi-shaped search boundary

| Field | Detail |
|-------|--------|
| Category | Input validation |
| Priority | P1 |
| Endpoint | `POST /api/search` |
| Payload | `' OR '1'='1` |
| Control expected | `400` in secure mode |
| Notes | Non-destructive; lab uses in-memory filters only |
| Automation | `test_secure_search_rejects_sqli_ish_payload` |

## TC-S-010 — Open redirect

| Field | Detail |
|-------|--------|
| Category | URL handling |
| Priority | P1 |
| Endpoint | `GET /api/redirect` |
| Payload | `next=https://evil.example` |
| Detect expected | 302 to external URL |
| Control expected | `400` |
| Finding | SEC-005 |
| Automation | `test_lab_open_redirect`, `test_secure_blocks_open_redirect` |

## TC-S-011 — Invalid email accepted (lab) / rejected (secure)

| Field | Detail |
|-------|--------|
| Category | Input validation |
| Priority | P2 |
| Endpoint | `PATCH /api/me` |
| Payload | `email=not-an-email` |
| Detect expected | `200` stores invalid email |
| Control expected | `400` |
| Automation | `test_lab_profile_update_accepts_invalid_email`, `test_secure_profile_update_rejects_invalid_email` |

## TC-S-012 — Unauthenticated access blocked

| Field | Detail |
|-------|--------|
| Category | Authentication gate |
| Priority | P0 |
| Endpoints | orders, users, search |
| Expected | `401` without token in both modes |
| Automation | `test_unauthenticated_endpoints_blocked`, `test_me_requires_auth` |

---

## Coverage matrix (summary)

| OWASP API Top 10 theme | Cases |
|------------------------|-------|
| API1 BOLA / IDOR | TC-S-004, TC-S-005, TC-S-006 |
| API3 Property-level / excess data | TC-S-003, TC-S-007 |
| API5 Function-level auth | TC-S-007 |
| Authn weaknesses | TC-S-001, TC-S-002, TC-S-012 |
| Input validation / redirect | TC-S-008–TC-S-011 |
