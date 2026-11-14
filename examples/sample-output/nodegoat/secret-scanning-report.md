# Secret Scanning Report

## 1. Executive Summary
The OWASP NodeGoat repository (`https://github.com/OWASP/NodeGoat`) is an intentionally vulnerable training app, and its tracked files contain several hard-coded credentials that are live in the sense that they are used by the running application. The most significant is an RSA private key committed alongside its certificate and loaded by the server for TLS, followed by a hard-coded session cookie secret and symmetric encryption key that are identical in every deployment. A static OWASP ZAP API key and seeded admin/user passwords are also committed. No cloud provider keys, SaaS tokens, or `.env` files were found tracked.

**Overall risk rating:** High

| Severity | Count |
|----------|-------|
| High | 3 |
| Medium | 2 |
| Low | 1 |

| Source | Count |
|--------|-------|
| code | 3 |
| config | 3 |
| history | 0 (not available) |
| docs | 0 |

## 2. Scope
- **Paths scanned:** all tracked files under the repository root, including `app/`, `config/`, `artifacts/`, `test/`, `.github/workflows/`, `Dockerfile`, `docker-compose.yml`, `.travis.yml`, `app.json`, `README.md`, and other Markdown docs. Excluded per instructions: `node_modules/`, `.git/`, vendored assets, `package-lock.json`.
- **Version-control history:** NOT checked. The provided clone is a shallow clone containing a single commit, so `git log` could not reveal previously committed and later removed secrets.
- **Documentation sources:** Only in-repo Markdown and HTML tutorial pages were available. No Confluence or external documentation source was provided or reachable; this is a gap, not a pass.
- **Environment files:** `git ls-files` shows no `.env`, `.env.*`, `*.pem`, `*.p12`, or service-account JSON tracked. `.gitignore` covers `.env` and `.env.local` but not `*.key`, `*.pem`, or `*.crt`.

## 3. Findings Register
| ID | Secret type | Location | Source | Validity | Severity |
|----|-------------|----------|--------|----------|----------|
| S1 | RSA private key (TLS) | `artifacts/cert/server.key:1` | config | Looks live | High |
| S2 | Session cookie signing secret | `config/env/all.js:8` | config | Looks live | High |
| S3 | Symmetric encryption key (AES-256) | `config/env/all.js:9` | config | Looks live | High |
| S4 | OWASP ZAP API key | `config/env/development.js:6`, `config/env/test.js:6` | config | Unclear | Medium |
| S5 | Seeded admin & user passwords | `artifacts/db-reset.js:18,27,35`; `test/e2e/fixtures/users/*.json`; `test/security/profile-test.js:37` | code | Looks live | Medium |
| S6 | Tutorial example cookie secret | `app/views/tutorial/a2.html:153`, `app/views/tutorial/a3.html:176` | docs | Placeholder | Low |

## 4. Detailed Findings

### [HIGH] S1: RSA private key in `artifacts/cert/server.key`
- **Type:** RSA private key (PEM, unencrypted). **Source:** config. **Validity:** Looks live.
- **Location:** `artifacts/cert/server.key:1` (paired with `artifacts/cert/server.crt`); consumed at `server.js:25-26`.
- **Evidence:** `-----BEG...` header, followed by an unencrypted 1024-bit RSA key body.
- **Exposure:** Public to anyone who can read the GitHub repository. The key is loaded by the application to terminate HTTPS. Anyone running NodeGoat with the HTTPS option uses this key, so any TLS session to any such deployment can be decrypted or impersonated by anyone with the repo. Even though this is a training app, forks commonly leave it in place.
- **Construct:** Unencrypted PEM private key committed to the repository next to its certificate and read from disk by the web server at startup to serve HTTPS.
- **Remediation:** Rotate: generate a new key pair per deployment at provision time (or via a script that is run locally and ignored by git). Remove the key from the repo, add `*.key` and `*.pem` to `.gitignore`, and have `server.js` read the key path from an environment variable. Because this is a public repo, treat the key as permanently compromised; rewriting history is secondary to never reusing it.

### [HIGH] S2: Session cookie signing secret in `config/env/all.js`
- **Type:** express-session cookie signing secret. **Source:** config. **Validity:** Looks live (used at runtime).
- **Location:** `config/env/all.js:8`, consumed by `server.js:82`.
- **Evidence:** `session_...` (a readable fixed string, not a placeholder that fails to run).
- **Exposure:** Public. Every deployment that does not override it signs session cookies with the same secret, so an attacker can forge or tamper with any session cookie for any default NodeGoat instance, including the public demo listed in the README. Production config (`config/env/production.js`) is empty and does not override it.
- **Construct:** Fixed session-signing secret hard-coded in the shared default configuration module, with no environment-variable override and no production-specific value.
- **Remediation:** Rotate by generating a random, per-deployment secret and reading it from `process.env.SESSION_SECRET` (fail fast if absent in production). Remove the literal from the repo.

### [HIGH] S3: AES-256 encryption key in `config/env/all.js`
- **Type:** Symmetric encryption key (used with `aes256` for profile field encryption). **Source:** config. **Validity:** Looks live.
- **Location:** `config/env/all.js:9`; used in `app/data/profile-dao.js:26-37` for PBKDF2 derivation and `createCipheriv`.
- **Evidence:** `a_secure...`
- **Exposure:** Public. All data encrypted by any default deployment (profile SSN/DOB fields) can be decrypted by anyone with the repo. Also lacks a per-deployment IV strategy, but that is a design issue outside secret-scanning scope.
- **Construct:** Fixed symmetric encryption key hard-coded in the shared default configuration module and used directly to encrypt sensitive user profile fields.
- **Remediation:** Rotate: generate a strong random key per deployment, supply via environment or a secret manager, and re-encrypt existing data under the new key. Remove the literal from source.

### [MEDIUM] S4: OWASP ZAP API key in `config/env/development.js` and `config/env/test.js`
- **Type:** OWASP ZAP REST API key. **Source:** config. **Validity:** Unclear.
- **Location:** `config/env/development.js:6`, `config/env/test.js:6`; used throughout `test/security/profile-test.js`.
- **Evidence:** `v9dn0bal...` paired with a private-range host (`192.168.56.x:8080`).
- **Exposure:** Public. The key targets a ZAP instance on a private LAN/VM address, so remote exploitation is unlikely, but anyone on the same network as a developer running this setup can drive their ZAP instance (spider, active scan, read reports). The value is high-entropy and matches ZAP's generated-key format rather than a placeholder.
- **Construct:** High-entropy security-scanner API key hard-coded in development and test configuration files alongside the scanner's internal network address.
- **Remediation:** Rotate the ZAP API key on any developer machine that used this value. Load it from an environment variable (`ZAP_API_KEY`) and replace the literal with an empty default.

### [MEDIUM] S5: Seeded admin and user passwords in `artifacts/db-reset.js`
- **Type:** Application account passwords (plaintext). **Source:** code. **Validity:** Looks live.
- **Location:** `artifacts/db-reset.js:18,27,35`; duplicated in `test/e2e/fixtures/users/admin.json:3`, `test/e2e/fixtures/users/user.json`, and `test/security/profile-test.js:37`.
- **Evidence:** `Admin_1...`, `User1_1...`, `User2_1...` (also present as commented-out bcrypt hashes).
- **Exposure:** Public. The seed script is run automatically on Heroku deploy (`app.json` postdeploy) and by `docker-compose.yml`, so every unmodified deployment has an admin account with a publicly known password. For a training app this is intended, but forks deployed to real infrastructure inherit it.
- **Construct:** Default administrator and user passwords written in plaintext inside the database seed script that runs automatically on deploy.
- **Remediation:** Rotate/change the admin password immediately on any non-training deployment. Have the seed script accept an `ADMIN_PASSWORD` environment variable or generate a random password and print it once. Keep fixtures for E2E tests but make them clearly test-only.

### [LOW] S6: Example cookie secret in tutorial HTML
- **Type:** Example session secret in educational text. **Source:** docs. **Validity:** Placeholder.
- **Location:** `app/views/tutorial/a2.html:153`, `app/views/tutorial/a3.html:176`.
- **Evidence:** `s3Cur3` inside an illustrative `session({...})` snippet.
- **Exposure:** Public, but not used by any code path. Included for completeness; readers may copy the snippet verbatim.
- **Construct:** Short illustrative secret string embedded in an HTML tutorial code sample rather than in executable configuration.
- **Remediation:** No rotation needed. Replace with an obvious placeholder such as `<RANDOM_SECRET_FROM_ENV>` to discourage copy-paste.

## 5. Documentation & Confluence Coverage
| Source | Reached? | Secrets found |
|--------|----------|---------------|
| `README.md` (in repo) | Yes | None (connection strings are `<username>:<password>` placeholders) |
| `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` | Yes | None |
| `app/views/tutorial/*.html` (in-repo tutorial pages) | Yes | S6 (placeholder only) |
| Confluence / external wiki | Not provided, not reachable | Unknown, gap |

## 6. Remediation Roadmap
**P0 – Rotate now**
1. S1: Generate a new TLS key pair for every deployment; never reuse the committed key.
2. S2: Generate a random session cookie secret per deployment and supply via environment.
3. S3: Generate a random AES key per deployment, supply via environment, re-encrypt stored profile data.
4. S4: Regenerate the ZAP API key on any machine that used the committed value.
5. S5: Change the seeded admin password on any instance that is not purely a disposable training sandbox.

**P1 – Remove from working tree**
- Delete `artifacts/cert/server.key` from the repo; read key/cert paths from `TLS_KEY_PATH` / `TLS_CERT_PATH`.
- Replace literals in `config/env/all.js` with `process.env.*` reads that throw when `NODE_ENV=production` and the value is missing.
- Add `*.key`, `*.pem`, `*.p12`, `*.crt` to `.gitignore`.

**P2 – History**
- This clone is shallow, so history was not reviewed. On the full repository, run a history scan (gitleaks or trufflehog) to confirm whether any additional secrets were committed and later removed. Because the repo is public, history rewriting offers little benefit; rotation is the effective control.

**P3 – Secret management**
- For Heroku/Docker deployments, move all secrets to config vars / Docker secrets and document this in the README so forks do not inherit shared values.

## 7. Prevention
- **`.gitignore`:** add `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.crt`, `secrets.*`, and `**/service-account*.json`. The current file only ignores `.env` and `.env.local`.
- **Pre-commit scanning:** add a `gitleaks protect --staged` or `detect-secrets` pre-commit hook. None exists today.
- **CI secret detection:** add a gitleaks or trufflehog job to `.github/workflows/lint.yml` so pull requests fail on new secrets; the current workflows only lint and run E2E tests.
- **Fail-fast config:** in `config/config.js`, refuse to start in production when `cookieSecret`, `cryptoKey`, or TLS paths are absent, instead of silently falling back to shared defaults.
- **Seed data:** generate the admin password at seed time and read it from an environment variable, printing it once to stdout.
- **Training-app caveat:** since NodeGoat is intentionally vulnerable, keep the insecure behaviour available behind an explicit flag (for example `NODEGOAT_INSECURE_DEFAULTS=true`) so that the lesson remains but accidental real-world reuse is harder.

## Coverage Notes
- **Reviewed:** all tracked source, config, IaC (Dockerfile, docker-compose, app.json), CI (GitHub Actions, Travis), test fixtures, seed scripts, README and tutorial HTML, with targeted grep for key prefixes, connection strings, webhook URLs, and private-key headers.
- **Skipped:** `node_modules/`, vendored front-end assets, `package-lock.json`, binary assets. Git history was not available (shallow single-commit clone). No Confluence or external docs were provided.
- **Not verified:** the certificate's subject and validity dates (an `openssl` inspection was not permitted in this environment); it is almost certainly a self-signed development certificate, which does not change the severity of the committed private key.
- **Confidence:** High for in-tree findings at quick depth; low for history and external documentation because those sources were not reachable.