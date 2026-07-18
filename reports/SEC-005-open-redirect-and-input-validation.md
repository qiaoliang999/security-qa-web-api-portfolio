# SEC-005 — Open Redirect and Missing Input Validation on Search

| Field | Value |
|-------|-------|
| **Finding ID** | SEC-005 |
| **Title** | Open redirect on `/api/redirect` and unsanitized search reflection |
| **Severity** | Medium (Open Redirect); Medium (Input validation gaps) |
| **CVSS (qualitative)** | Medium |
| **Status** | Open in `LAB_MODE=true`; fixed in secure baseline |
| **Affected asset** | Security QA Lab API (authorized local lab only) |
| **Affected endpoints** | `GET /api/redirect?next=`, `POST /api/search` |
| **Component** | URL handling / input validation / output encoding |
| **Environment** | Local demo application — **authorized lab only** |
| **Reporter role** | Security QA / AppSec testing |

## Summary

Two related weaknesses:

1. **Open redirect**: `next` accepts absolute external URLs, enabling phishing flows that start from a trusted origin.
2. **Missing input validation**: search accepts and reflects XSS/SQLi-shaped payloads and overlong input without rejection or sanitization.

These are intentional training surfaces for Security QA boundary testing (non-destructive).

## Prerequisites

- Lab application running with `LAB_MODE=true`
- Search requires any authenticated session; redirect is unauthenticated

## Steps to reproduce — open redirect

```http
GET /api/redirect?next=https://evil.example
```

Observe `302` with `Location: https://evil.example`.

## Steps to reproduce — search reflection

1. Login as alice and obtain a token.
2. Send:

```http
POST /api/search
Authorization: Bearer <token>
Content-Type: application/json

{"query":"<script>alert(1)</script>"}
```

3. Observe payload echoed in `query` and `reflected` fields.
4. Optionally send `' OR '1'='1` and overlong strings; lab mode accepts them.

## Expected result

- Redirect only to relative same-origin paths (e.g., `/health`)
- Search rejects or sanitizes dangerous patterns and enforces max length
- APIs never blindly reflect untrusted input into HTML contexts without encoding (API JSON still benefits from validation)

## Actual result (lab mode)

- External redirect targets accepted
- Unsanitized payloads reflected
- No length enforcement on search query

## Impact

- Open redirect supports phishing and token/redirect chain abuse in real apps
- Weak validation increases risk of injection if the same inputs later touch SQL, templates, or logs
- Reflected content can become stored XSS if persisted into an HTML UI without encoding

## Evidence notes

- `tests/test_input_validation.py::test_lab_open_redirect`
- `tests/test_input_validation.py::test_secure_blocks_open_redirect`
- `tests/test_input_validation.py::test_lab_search_reflects_unsanitized_payload`
- `tests/test_input_validation.py::test_secure_search_rejects_script_payload`

## Remediation

1. Allow-list redirect targets: relative paths only, or map of named destinations
2. Reject `//`, `\\`, absolute URLs, and control characters in redirect parameters
3. Validate search input: length limits, character classes, and known dangerous patterns as defense-in-depth
4. Encode output appropriately for the sink (HTML, JS, SQL parameterized queries)
5. Prefer parameterized data access; never concatenate untrusted input into queries
6. Add security regression tests for redirect and validation controls

## References

- OWASP Unvalidated Redirects and Forwards Cheat Sheet
- OWASP Input Validation Cheat Sheet
- CWE-601: URL Redirection to Untrusted Site
- CWE-20: Improper Input Validation
- CWE-79: Cross-site Scripting (context-dependent)

---

*This report documents an intentional vulnerability in an authorized local Security QA lab application. Do not use these techniques against systems without explicit written permission.*
