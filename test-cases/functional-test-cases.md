# Functional Test Cases

Scope: authorized local Security QA lab application only.

## TC-F-001 — Health check

| Field | Detail |
|-------|--------|
| Type | Functional |
| Priority | P0 |
| Endpoint | `GET /health` |
| Preconditions | App running |
| Steps | Call `/health` |
| Expected | `200`, `status=ok`, boolean `lab_mode` present |

## TC-F-002 — Login success

| Field | Detail |
|-------|--------|
| Type | Functional |
| Priority | P0 |
| Endpoint | `POST /api/login` |
| Preconditions | Demo user alice exists |
| Steps | POST `{"username":"alice","password":"password123"}` |
| Expected | `200`, token returned, username alice |

## TC-F-003 — Login failure

| Field | Detail |
|-------|--------|
| Type | Functional |
| Priority | P0 |
| Endpoint | `POST /api/login` |
| Steps | POST wrong password |
| Expected | `401` |

## TC-F-004 — Current user profile

| Field | Detail |
|-------|--------|
| Type | Functional |
| Priority | P0 |
| Endpoint | `GET /api/me` |
| Preconditions | Valid token |
| Steps | Call with Bearer token |
| Expected | `200`, matching username |

## TC-F-005 — List own orders (secure mode)

| Field | Detail |
|-------|--------|
| Type | Functional |
| Priority | P1 |
| Endpoint | `GET /api/orders` |
| Mode | `LAB_MODE=false` |
| Preconditions | Logged in as alice |
| Expected | Only orders with `owner_id=1` |

## TC-F-006 — Admin user listing (secure mode)

| Field | Detail |
|-------|--------|
| Type | Functional |
| Priority | P1 |
| Endpoint | `GET /api/admin/users` |
| Mode | `LAB_MODE=false` |
| Preconditions | Logged in as admin |
| Expected | `200`, user list without sensitive fields |

## TC-F-007 — UI login page

| Field | Detail |
|-------|--------|
| Type | Functional / UI |
| Priority | P2 |
| Path | `/login` |
| Steps | Open page, submit alice credentials |
| Expected | Result panel includes token and alice |

## Traceability

| Case | Automated test |
|------|----------------|
| TC-F-001 | `test_health_exposes_lab_mode` |
| TC-F-002 | `test_login_happy_path` |
| TC-F-003 | `test_login_wrong_password` |
| TC-F-004 | `test_me_with_valid_token` |
| TC-F-005 | `test_secure_list_orders_scoped` |
| TC-F-006 | `test_secure_admin_endpoint_allowed_for_admin` |
| TC-F-007 | `test_ui_login_page_renders` |
