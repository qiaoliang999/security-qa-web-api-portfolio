# SEC-004 — Username Enumeration via Authentication Error Messages

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-004 |
| **Title** | Distinct login error messages enable username enumeration |
| **Severity** | Medium |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CVSS 3.1 score** | **5.3** Medium |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoint** | `POST /api/login` |
| **Component** | Authentication / error handling |
| **Environment** | Local demo — **authorized lab only** |

## Summary

Lab mode returns `"Username not found"` vs `"Incorrect password"`. Attackers can build a valid username list before password spraying. Secure mode uses a single generic message. Lab mode also issues predictable tokens (`lab-token-{username}`); secure mode uses `secrets.token_urlsafe`.

## Prerequisites

- Unauthenticated access to login endpoint
- `LAB_MODE=true`

## Steps to reproduce

```http
POST /api/login
Content-Type: application/json

{"username":"no-such-user","password":"x"}
```

```http
POST /api/login
Content-Type: application/json

{"username":"alice","password":"bad"}
```

Compare `detail` strings and HTTP status (both 401, different bodies).

## Expected result

Identical generic error for unknown user and wrong password.

## Actual result (lab mode)

Distinct messages; successful login returns `lab-token-alice`.

## Impact

- Enables targeted credential stuffing / password spraying
- Reduces brute-force search space
- Predictable tokens compound session risks if guessed offline

## Evidence

- Automated: `tests/test_auth.py::test_lab_user_enumeration_via_distinct_errors`
- Control: `tests/test_auth.py::test_secure_mode_no_user_enumeration`
- Token: `tests/test_auth.py::test_lab_predictable_session_token`

## Remediation

1. Single generic error: "Invalid username or password".
2. Constant-time-ish auth flow (always perform password verify work when practical).
3. Cryptographically random session tokens; server-side session store.
4. Rate limiting / lockout / CAPTCHA on auth endpoints (out of scope for this lab but recommended).

## References

- OWASP Authentication Cheat Sheet
- CWE-203: Observable Discrepancy
- CWE-204: Observable Response Discrepancy

---

*Authorized local lab finding only.*
