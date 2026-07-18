# SEC-004 — Username Enumeration via Distinct Authentication Errors

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-004 |
| **Title** | Login returns different errors for unknown username vs wrong password |
| **Severity** | Medium |
| **CVSS (qualitative)** | Medium — information disclosure aiding credential attacks |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoint** | `POST /api/login` |
| **Component** | Authentication error handling |
| **Environment** | Local demo application — **authorized lab only** |
| **Reporter role** | Security QA / AppSec testing |

## Summary

Authentication failures use distinct messages depending on whether the username exists. Attackers can harvest valid usernames before attempting password guessing. Related lab issues on the same endpoint include predictable session tokens (`lab-token-<username>`).

## Prerequisites

- Lab application running with `LAB_MODE=true`
- No authentication required to probe

## Steps to reproduce

1. Submit a non-existent username:

```http
POST /api/login
Content-Type: application/json

{"username":"no-such-user","password":"x"}
```

2. Submit a valid username with a wrong password:

```http
POST /api/login
Content-Type: application/json

{"username":"alice","password":"bad"}
```

3. Compare `detail` strings and note they differ.

## Expected result

- Identical generic message for all authentication failures (e.g., "Invalid username or password")
- Uniform timing as much as practical
- Rate limiting / lockout / CAPTCHA for repeated failures (not implemented in this small lab beyond message fix in secure mode)

## Actual result (lab mode)

- Unknown user → `"Username not found"`
- Known user, bad password → `"Incorrect password"`
- Successful login issues predictable token `lab-token-alice`

## Impact

- Enables reliable username enumeration
- Improves efficiency of credential stuffing and password spraying
- Predictable tokens (companion issue) further weaken session integrity in lab mode

## Evidence notes

- Automated: `tests/test_auth.py::test_lab_user_enumeration_via_distinct_errors`
- Secure baseline: `tests/test_auth.py::test_secure_mode_no_user_enumeration`
- Predictable token: `tests/test_auth.py::test_lab_predictable_session_token`

## Remediation

1. Return a single generic authentication failure message
2. Issue cryptographically random session tokens (e.g., 256-bit)
3. Add throttling, account lockout or progressive delays, and monitoring for brute-force patterns
4. Consider MFA for privileged accounts
5. Avoid revealing account existence on registration/forgot-password flows as well

## References

- OWASP Authentication Cheat Sheet
- OWASP Testing Guide — Testing for Account Enumeration
- CWE-204: Observable Response Discrepancy
- CWE-330: Use of Insufficiently Random Values (session token companion)

---

*This report documents an intentional vulnerability in an authorized local Security QA lab application. Do not use these techniques against systems without explicit written permission.*
