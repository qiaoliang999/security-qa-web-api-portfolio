# SEC-005 — Open Redirect via Unrestricted `next` Parameter

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-005 |
| **Title** | Open redirect accepts arbitrary external URLs |
| **Severity** | Medium |
| **CVSS 3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **CVSS 3.1 score** | **6.1** Medium |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoint** | `GET /api/redirect?next=` |
| **Component** | URL handling / redirect validation |
| **Environment** | Local demo — **authorized lab only** |

## Summary

Lab mode reflects `next` directly into `Location`. Secure mode allows only an **explicit path allow-list map** (`/`, `/health`, `/docs`, `/login`, `/redoc`), not a hostname blacklist.

> Note: Input validation on search was split out of this report. Search “fixes” that only regex-blacklist SQLi/XSS patterns are **not** claimed as secure controls in this project. Secure search uses max length, parameterized SQL, scoped results, and no reflected HTML field.

## Prerequisites

- App reachable; no auth required for redirect endpoint

## Steps to reproduce

```http
GET /api/redirect?next=https://evil.example
```

Observe `302` with `Location: https://evil.example`.

Also try `//evil.example/phish` (protocol-relative).

## Expected result

HTTP 400 for non-allow-listed targets; 302 only for mapped internal paths.

## Actual result (lab mode)

External and protocol-relative targets accepted.

## Impact

- Phishing via trusted origin redirect chains
- Token leakage in some redirect + fragment/query designs
- OAuth-style `redirect_uri` class of bugs in real systems

## Evidence

- Sample: [`evidence/SEC-005-open-redirect.http`](evidence/SEC-005-open-redirect.http)
- Automated: `tests/test_input_validation.py::test_lab_open_redirect`
- Control: `tests/test_input_validation.py::test_secure_blocks_open_redirect_external`
- Control: `tests/test_input_validation.py::test_secure_blocks_unknown_relative_path`

## Remediation

1. Prefer named destination keys (`?dest=home`) mapped server-side to paths.
2. If paths are required, allow-list exact paths (or strict prefixes) — **not** “block evil.com”.
3. Reject `//`, backslashes, schemes, and userinfo.
4. Regression tests for external, protocol-relative, and unknown relative paths.

## References

- OWASP Unvalidated Redirects and Forwards Cheat Sheet
- CWE-601: URL Redirection to Untrusted Site

---

*Authorized local lab finding only.*
