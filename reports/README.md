# Security Findings Index

Authorized local lab only. These documents describe intentional weaknesses in the demo application for Security QA practice.

One finding per report. Each report includes CVSS 3.1 vector + qualitative severity and links to evidence samples where available.

| ID | Title | Severity | CVSS 3.1 | Endpoint(s) |
|----|-------|----------|----------|-------------|
| [SEC-001](SEC-001-idor-user-profile.md) | IDOR on user profiles | High | 7.1 | `GET /api/users/{id}` |
| [SEC-002](SEC-002-sensitive-data-exposure.md) | Sensitive data exposure in API responses | High | 7.5 | login / me / users |
| [SEC-003](SEC-003-missing-function-level-auth.md) | Missing function-level auth on admin API | Critical | 8.8 | `GET /api/admin/users` |
| [SEC-004](SEC-004-username-enumeration.md) | Username enumeration via auth errors | Medium | 5.3 | `POST /api/login` |
| [SEC-005](SEC-005-open-redirect.md) | Open redirect via unrestricted `next` | Medium | 6.1 | `GET /api/redirect` |
| [SEC-006](SEC-006-horizontal-write-idor-orders.md) | Horizontal write IDOR on orders | High | 7.1 / 8.1* | `PATCH/DELETE /api/orders/{id}` |
| [SEC-007](SEC-007-mass-order-listing.md) | Unscoped order listing | Medium | 6.5 | `GET /api/orders` |

Evidence samples: [`evidence/`](evidence/)

\*SEC-006 base vector scores **7.1** (I:H/A:L); index band **8.1** is used when full delete availability is weighted. See the finding report for the exact vector.

## Report structure

1. Metadata table (ID, severity, CVSS 3.1 vector, asset, status)
2. Summary
3. Prerequisites
4. Steps to reproduce (HTTP)
5. Expected vs actual
6. Impact
7. Evidence (file links + automated test mapping)
8. Remediation
9. References (OWASP / CWE)

Severity rubric: [`docs/SEVERITY.md`](../docs/SEVERITY.md)  
Methodology: [`docs/METHODOLOGY.md`](../docs/METHODOLOGY.md)

## Ethical note

Do not run these tests against systems you do not own or lack written authorization to assess.
