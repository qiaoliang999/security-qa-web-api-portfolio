# Security Testing Methodology

Authorized local lab methodology used in this portfolio. Adapt to any **in-scope, written-authorized** target. Never test systems without permission.

## 1. Reconnaissance

| Activity | In this lab |
|----------|-------------|
| Map attack surface | OpenAPI at `/docs`, router modules under `app/routers/` |
| Identify roles & objects | Users (`user`/`admin`), Orders (ownership + `org_id`), Sessions |
| Note authn mechanism | Bearer session tokens issued by `/api/login` |
| Config / mode flags | `LAB_MODE` dual baseline for detection vs control verify |
| Data inventory | Seed users/orders in `app/config.py` + SQLite `app/db.py` |

Outputs: endpoint inventory, role matrix sketch, sensitive field candidates.

## 2. Abuse case design

Translate surface into abuse cases, not just happy-path QA:

| Theme | Example abuse case |
|-------|--------------------|
| Horizontal read IDOR | User A reads User B profile / order by id |
| Horizontal write IDOR | User A PATCHes/DELETEs User B order |
| Vertical privilege | User calls admin function |
| Collection scope | List endpoints return other users/tenants |
| Authn flaws | Enumeration, predictable tokens, token abuse |
| Sensitive exposure | Forbidden keys in JSON responses |
| Redirect abuse | External / protocol-relative `next` |
| Input boundaries | Overlong fields, invalid email, search length |

Each abuse case names: actor, action, object, expected deny, lab observed allow (if any).

## 3. Automation

- **In-process** FastAPI `TestClient` for API security suites (fast, deterministic).
- **Per-test DB reset** (`reset_database`) for isolation.
- **Parametrized authz matrix** (`tests/test_authz_matrix.py`): roles × methods × resources × expected status.
- **Sensitive-field contract helper** forbids `ssn` / `api_key` / `password*` in secure responses.
- **Markers**: `security`, `authz`, `authn`, `smoke`, `ui`.
- **Dual fixtures**: `lab_client` asserts detectability; `secure_client` asserts control hold.
- Optional **Playwright** for login UI gate smoke only.

Run:

```bash
pytest -q -m "not ui"
pytest -q -m authz
pytest -q -m security
```

## 4. Reporting

- One primary issue per markdown report under `reports/`.
- Include **CVSS 3.1 vector string** + qualitative severity (see `docs/SEVERITY.md`).
- Attach or link **evidence** (`.http` / JSON) under `reports/evidence/`.
- Map finding → automated test name for fix verification.
- Keep ethical/lab framing explicit.

## 5. Fix verification

1. Implement real controls (central authz deps, DTO allow-lists, hashed passwords, redirect path map).
2. Re-run **secure-mode** suite (`LAB_MODE=false` fixtures / CI job).
3. Confirm lab-mode detection tests still document residual intentional flaws if lab remains for training.
4. CI separates lab detection job vs secure control job; uploads junit/html artifacts.

## 6. What we deliberately avoid

- Regex blacklists advertised as “SQLi/XSS prevention” on JSON search APIs
- Weaponized exploit chains or malware
- Testing out-of-scope third-party systems
- Storing real secrets or production data
