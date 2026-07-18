# Security Findings Index

Authorized local lab only. These documents describe intentional weaknesses in the demo application for Security QA portfolio practice.

| ID | Title | Severity | Endpoint(s) | Lab mode | Secure mode |
|----|-------|----------|-------------|----------|-------------|
| [SEC-001](SEC-001-idor-user-profile.md) | IDOR on user profiles | High | `GET /api/users/{id}` | Vulnerable | Fixed (403) |
| [SEC-002](SEC-002-sensitive-data-exposure.md) | Sensitive data exposure in API responses | High | login / me / users | Vulnerable | Fixed |
| [SEC-003](SEC-003-missing-function-level-auth.md) | Missing function-level auth on admin API | Critical | `GET /api/admin/users` | Vulnerable | Fixed (403) |
| [SEC-004](SEC-004-username-enumeration.md) | Username enumeration via auth errors | Medium | `POST /api/login` | Vulnerable | Fixed |
| [SEC-005](SEC-005-open-redirect-and-input-validation.md) | Open redirect + weak search validation | Medium | redirect / search | Vulnerable | Fixed |

## Report template (used above)

Each finding includes:

1. Title, severity, affected endpoint
2. Steps to reproduce
3. Expected vs actual
4. Impact
5. Remediation
6. Evidence notes (manual + automated test mapping)
7. References (OWASP / CWE)

## Ethical note

Do not run these tests against systems you do not own or lack written authorization to assess.
