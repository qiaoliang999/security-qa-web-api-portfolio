# Severity Rubric

Qualitative severity for findings in this lab follows a CVSS 3.1-informed scale used in application security programs. Scores in reports include the official vector string so readers can recompute.

## Mapping

| Qualitative | Typical CVSS 3.1 | When we use it |
|-------------|------------------|----------------|
| **Critical** | 9.0–10.0 (or high 7.0+ with broad vertical priv + mass secret dump) | Unauthenticated RCE-class impact is out of scope here; **Critical** reserved for admin-function bypass that dumps sensitive identity material to any user |
| **High** | 7.0–8.9 | Authenticated horizontal IDOR with sensitive fields; write IDOR with integrity/loss impact |
| **Medium** | 4.0–6.9 | Enumeration, open redirect, unscoped listings without secret fields, session predictability without direct takeover chain |
| **Low** | 0.1–3.9 | Verbose errors, minor info leaks, missing hardening with limited exploitability |
| **Info** | 0.0 | Defense-in-depth notes, missing headers without demonstrated impact |

## Scoring guidelines used here

- **Confidentiality High** when SSN-like fields, API keys, or password material appear.
- **Integrity High** when an attacker can modify another principal's objects.
- **Privileges Required Low** for any authenticated low-privilege user; **None** for unauthenticated.
- **User Interaction Required** for open redirect phishing scenarios.
- **Scope Changed** when redirect/cross-origin trust boundary is abused.

## Portfolio vs production

Lab findings are **intentional**. Severity reflects what the same bug class would mean in a production multi-tenant API, not risk to this disposable local app.

## Residual risk language

Remediation sections describe durable controls (central authz, DTO allow-lists, hashed passwords, allow-listed redirects). Controls that are merely “blocklist a few payloads” are not accepted as High-quality fixes and are not used in secure mode.
