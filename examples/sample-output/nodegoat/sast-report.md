# SAST Report

## 1. Executive Summary

OWASP NodeGoat (`https://github.com/OWASP/NodeGoat`) is an Express 4 / MongoDB application that is intentionally vulnerable for training purposes, and the static review confirms the planted defects are real and reachable. Any self-registered user can achieve server-side JavaScript execution via `eval()` on form input, perform server-side request forgery to arbitrary URLs with the response reflected back as HTML, inject into a MongoDB `$where` clause, and read or modify other users' records through missing object-level and function-level authorization. Template autoescaping is globally disabled, so every rendered field is a stored or reflected XSS vector, and passwords are stored and compared in plaintext. Secrets and seeded admin credentials are hardcoded in the repository.

**Overall risk rating:** Critical

| Severity | Count |
|----------|-------|
| High | 6 |
| Medium | 5 |
| Low | 1 |

## 2. Scope

- **Languages / frameworks:** Node.js (CommonJS), Express 4, express-session (MemoryStore), Swig templates via consolidate, MongoDB native driver 2.x, marked 0.3.5, needle 2.2.4, node-esapi.
- **Reviewed:** `server.js`, `app/routes/*.js` (all 10 files), `app/data/*.js` (all 7 DAOs), `config/config.js`, `config/env/*.js`, `artifacts/db-reset.js`, `app/views/*.html` (layout, login, signup, profile, allocations, memos, benefits, contributions, error-template), `package.json`.
- **Excluded:** `node_modules/`, `.git/`, `app/assets/vendor/**` (third-party front-end bundles, `*.min.js`), `test/**` (Cypress and Mocha fixtures), `app/views/tutorial/**` (static educational pages with no template variables), `artifacts/cert/*` (noted only as committed key material; covered by Secret Scanning).

## 3. Findings Register

| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | Server-side JS injection via `eval()` on POST body | High | CWE-95 | A03:2021 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | `app/routes/contributions.js:32-34` | Confirmed |
| F2 | SSRF with raw response body reflected as HTML | High | CWE-918 | A10:2021 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N | `app/routes/research.js:15-26` | Confirmed |
| F3 | NoSQL injection via `$where` string interpolation | High | CWE-943 | A03:2021 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H | `app/data/allocations-dao.js:77-79` | Confirmed |
| F4 | IDOR: allocations looked up by URL `userId`, not session | High | CWE-639 | A01:2021 | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | `app/routes/allocations.js:16-23` | Confirmed |
| F5 | Missing admin check on `/benefits` (function-level access control) | High | CWE-862 | A01:2021 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N | `app/routes/index.js:55-56` | Confirmed |
| F6 | Global template autoescape disabled; stored and reflected XSS | High | CWE-79 | A03:2021 | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | `server.js:135-137`, `app/views/layout.html:75` | Confirmed |
| F7 | Passwords stored and compared in plaintext | Medium | CWE-256 | A02:2021 | AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N | `app/data/user-dao.js:25`, `:61` | Confirmed |
| F8 | Open redirect on `/learn?url=` | Medium | CWE-601 | A01:2021 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | `app/routes/index.js:70-73` | Confirmed |
| F9 | Hardcoded session secret, crypto key, and seeded admin credentials | Medium | CWE-798 | A07:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | `config/env/all.js:8-9`, `artifacts/db-reset.js:15-18` | Conditional |
| F10 | CSRF protection disabled on all state-changing POST handlers | Medium | CWE-352 | A01:2021 | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | `server.js:104-113`, `app/views/profile.html:73` | Confirmed |
| F11 | ReDoS via nested quantifier on bank routing validator | Medium | CWE-1333 | unverified | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H | `app/routes/profile.js:59-61` | Confirmed |
| F12 | Session cookie lacks `httpOnly`/`secure`; no regeneration on login; error page echoes raw error | Low | CWE-1004 | A05:2021 | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N | `server.js:78-102`, `app/routes/session.js:116`, `app/routes/error.js:10-12` | Confirmed |

## 4. Detailed Findings

### [HIGH] F1: Server-side JS injection via `eval()` on POST body
- **Severity:** High
- **CWE:** CWE-95
- **OWASP:** A03:2021
- **Verdict:** Confirmed
- **Location:** `app/routes/contributions.js:32-34`
- **Description:** The contributions update handler passes three fields from `req.body` straight into `eval()`. Any authenticated user (self-registration is open at `/signup`) can POST `preTax=require('child_process').execSync('id').toString()` or `preTax=process.exit()` to `/contributions` and execute arbitrary code in the Node process, or crash the server. The `isNaN` validation runs after the eval, so it does not constrain the payload.
- **Vulnerable code:**
```js
const preTax = eval(req.body.preTax);
const afterTax = eval(req.body.afterTax);
const roth = eval(req.body.roth);
```
- **Construct:** Request body fields passed directly to a JavaScript eval call before any type validation.
- **Recommendation:** Replace `eval()` with `parseInt(value, 10)` (or `Number()`), reject `NaN`, negative, and out-of-range values, and validate the body with a schema before use.

### [HIGH] F2: SSRF with raw response body reflected as HTML
- **Severity:** High
- **CWE:** CWE-918
- **OWASP:** A10:2021
- **Verdict:** Confirmed
- **Location:** `app/routes/research.js:15-26`
- **Description:** `/research?symbol=X&url=Y` concatenates two query parameters into a URL and fetches it server-side with `needle.get`. The attacker fully controls the scheme, host, and path, so they can reach cloud metadata endpoints, internal services, or `localhost:27017`. The fetched body is written into the response as `text/html` without encoding, so this is also a reflected XSS and internal-content disclosure channel.
- **Vulnerable code:**
```js
const url = req.query.url + req.query.symbol;
return needle.get(url, (error, newResponse, body) => {
    ...
    if (body) { res.write(body); }
```
- **Construct:** Outbound HTTP request whose entire target URL is built from query-string parameters, with the upstream body echoed verbatim into an HTML response.
- **Recommendation:** Drop the `url` parameter entirely. Hardcode the upstream base URL, validate `symbol` against `^[A-Z]{1,6}$`, pass it as a URL-encoded path segment, and HTML-encode (or JSON-return) the upstream body instead of writing it as HTML.

### [HIGH] F3: NoSQL injection via `$where` string interpolation
- **Severity:** High
- **CWE:** CWE-943
- **OWASP:** A03:2021
- **Verdict:** Confirmed
- **Location:** `app/data/allocations-dao.js:77-79`
- **Description:** The `threshold` query parameter from `/allocations/:userId?threshold=` is interpolated unquoted into a MongoDB `$where` JavaScript expression. `threshold=0'; return true; '` returns every allocation document for every user, and `threshold=0'; while(true){}'` pins the database CPU. The `$where` operator executes server-side JavaScript in MongoDB.
- **Vulnerable code:**
```js
return {
    $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
};
```
- **Construct:** Database query filter built as a JavaScript source string by template interpolation of a query-string value, executed via the server-side where operator.
- **Recommendation:** Remove `$where`. Parse `threshold` with `parseInt`, bound it to 0-99, and use a structured filter: `{ userId: parsedUserId, stocks: { $gt: parsedThreshold } }`.

### [HIGH] F4: IDOR: allocations looked up by URL `userId`, not session
- **Severity:** High
- **CWE:** CWE-639
- **OWASP:** A01:2021
- **Verdict:** Confirmed
- **Location:** `app/routes/allocations.js:16-23`
- **Description:** The handler reads `userId` from `req.params` rather than `req.session` and never checks it matches the caller. Any logged-in user can request `/allocations/1`, `/allocations/2`, and so on to enumerate every user's name and asset allocation, and user IDs are sequential integers.
- **Vulnerable code:**
```js
const { userId } = req.params;
const { threshold } = req.query;
allocationsDAO.getByUserIdAndThreshold(userId, threshold, ...
```
- **Construct:** Record lookup keyed on a path parameter supplied by the client with no comparison against the authenticated principal.
- **Recommendation:** Use `req.session.userId` for the lookup and change the route to `/allocations`. If admins must view others' allocations, gate that path behind the existing `isAdmin` middleware.

### [HIGH] F5: Missing admin check on `/benefits` (function-level access control)
- **Severity:** High
- **CWE:** CWE-862
- **OWASP:** A01:2021
- **Verdict:** Confirmed
- **Location:** `app/routes/index.js:55-56`
- **Description:** Both benefits routes are protected only by `isLoggedIn`; the `isAdmin` middleware exists but is commented out. Any user can GET `/benefits` to list all non-admin users, and POST `/benefits` with an arbitrary `userId` to change any other user's `benefitStartDate`. The DAO returns the complete user documents (including plaintext `password`, `ssn`, `bankAcc`) into the template context.
- **Vulnerable code:**
```js
app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
/* Fix for A7 ... app.get("/benefits", isLoggedIn, isAdmin, ...
```
- **Construct:** Administrative read and write endpoints registered with only an authentication guard, while the role-check middleware is left unused.
- **Recommendation:** Add `isAdmin` to both routes, and project only the needed fields in the users query (`{ projection: { firstName: 1, lastName: 1, benefitStartDate: 1 } }`).

### [HIGH] F6: Global template autoescape disabled; stored and reflected XSS
- **Severity:** High
- **CWE:** CWE-79
- **OWASP:** A03:2021
- **Verdict:** Confirmed
- **Location:** `server.js:135-137`, `app/views/layout.html:75`
- **Description:** Swig autoescaping is turned off globally, so every `{{ }}` in every template emits raw HTML. Stored XSS: a user sets `firstName` to `<script>...</script>` via `/profile`; it is rendered unescaped in their own navbar, in every other user's view via `/allocations/{{id}}` (F4), and in the admin's `/benefits` table. Reflected XSS: on login failure, `userName` is echoed into the login form value attribute; on profile validation failure, raw `firstName` is placed into an `href` (`javascript:` URI). The `encodeForHTML` on `website` is the only encoding and is the wrong context for the `href` where `firstNameSafeString` is used.
- **Vulnerable code:**
```js
swig.setDefaults({
    // Autoescape disabled
    autoescape: false
```
```html
<a href="#" ...> {{firstName}} {{lastName}} <b class="caret"></b></a>
```
- **Construct:** Template engine configured with output escaping globally disabled, with user-sourced profile fields and request values rendered directly into HTML body and attribute contexts.
- **Recommendation:** Set `autoescape: true` (the default), remove the manual `encodeForHTML` call, use a URL-encoded variant (`encodeForURL`) for any value placed in an `href`, and add a Content-Security-Policy via helmet.

### [MEDIUM] F7: Passwords stored and compared in plaintext
- **Severity:** Medium
- **CWE:** CWE-256
- **OWASP:** A02:2021
- **Verdict:** Confirmed
- **Location:** `app/data/user-dao.js:25`, `app/data/user-dao.js:61`
- **Description:** `addUser` persists the raw password, and `validateLogin` compares with `===`. `bcrypt-nodejs` is imported but unused. Combined with F3 (dump via `$where`) or F5 (full user docs to template), the plaintext passwords are directly retrievable by any authenticated user; this is the stated precondition for the AC:H rating.
- **Vulnerable code:**
```js
password //received from request param
...
const comparePassword = (fromDB, fromUser) => {
    return fromDB === fromUser;
```
- **Construct:** Credential stored as the raw submitted string and verified by plain string equality.
- **Recommendation:** Hash with `bcrypt.hashSync(password, bcrypt.genSaltSync(12))` on create and verify with `bcrypt.compareSync(fromUser, fromDB)`. Prefer the maintained `bcrypt` or `argon2` package over `bcrypt-nodejs`.

### [MEDIUM] F8: Open redirect on `/learn?url=`
- **Severity:** Medium
- **CWE:** CWE-601
- **OWASP:** A01:2021
- **Verdict:** Confirmed
- **Location:** `app/routes/index.js:70-73`
- **Description:** The handler redirects to whatever the `url` query parameter contains. A phishing link such as `/learn?url=https://evil.example/login` carries the trusted origin and lands a logged-in victim on an attacker page.
- **Vulnerable code:**
```js
app.get("/learn", isLoggedIn, (req, res) => {
    return res.redirect(req.query.url);
});
```
- **Construct:** HTTP redirect whose target is taken unvalidated from a query-string parameter.
- **Recommendation:** Map a fixed key (`?topic=iras`) to a server-side allowlist of destination URLs, or validate that the parsed URL's host is in an explicit allowlist before redirecting.

### [MEDIUM] F9: Hardcoded session secret, crypto key, and seeded admin credentials
- **Severity:** Medium
- **CWE:** CWE-798
- **OWASP:** A07:2021
- **Verdict:** Conditional (precondition: deployment uses the committed defaults or runs the seed script against a reachable instance)
- **Location:** `config/env/all.js:8-9`, `artifacts/db-reset.js:15-18`
- **Description:** The express-session signing secret and the AES key are literal strings in a public repository, and `production.js` overrides nothing. The seed script creates `admin / Admin_123`, `user1 / User1_123`, `user2 / User2_123`. Anyone who knows the project can log in as admin on a seeded deployment with no prior access. A private TLS key is also committed under `artifacts/cert/`.
- **Vulnerable code:**
```js
cookieSecret: "session_cookie_secret_key_here",
cryptoKey: "a_secure_key_for_crypto_here",
```
```js
"userName": "admin", ... "password": "Admin_123", "isAdmin": true
```
- **Construct:** Session-signing and encryption secrets as string literals in a committed config module, plus a database seed script that creates a privileged account with a fixed password.
- **Recommendation:** Read `SESSION_SECRET` and `CRYPTO_KEY` from environment variables and fail startup if absent. Have the seed script generate a random admin password and print it once, or require it from the environment. Rotate and remove the committed certificate key.

### [MEDIUM] F10: CSRF protection disabled on all state-changing POST handlers
- **Severity:** Medium
- **CWE:** CWE-352
- **OWASP:** A01:2021
- **Verdict:** Confirmed
- **Location:** `server.js:104-113`, `app/views/profile.html:73`
- **Description:** The `csurf` middleware is commented out, so `res.locals.csrftoken` is never set and every form's hidden `_csrf` field renders empty. POST `/profile`, `/contributions`, `/benefits`, and `/memos` accept cross-origin form submissions from a logged-in victim's browser, letting an attacker change their bank account number or (via F1) execute code as the victim's session.
- **Vulnerable code:**
```js
/*
// Fix for A8 - CSRF
app.use(csrf());
```
```html
<input type="hidden" name="_csrf" value="{{csrftoken}}" />
```
- **Construct:** Session-cookie-authenticated form POST endpoints with the anti-forgery middleware commented out, leaving the token field in templates permanently empty.
- **Recommendation:** Enable a CSRF middleware (`csurf` or a double-submit cookie implementation), set the token in `res.locals`, and set `SameSite=Lax` or `Strict` on the session cookie.

### [MEDIUM] F11: ReDoS via nested quantifier on bank routing validator
- **Severity:** Medium
- **CWE:** CWE-1333
- **OWASP:** unverified
- **Verdict:** Confirmed
- **Location:** `app/routes/profile.js:59-61`
- **Description:** The pattern `/([0-9]+)+\#/` has a nested unbounded quantifier. A `bankRouting` value of thirty or more digits followed by a non-`#` character causes exponential backtracking in V8's regex engine and blocks the single Node event loop, denying service to all users.
- **Vulnerable code:**
```js
const regexPattern = /([0-9]+)+\#/;
const testComplyWithRequirements = regexPattern.test(bankRouting);
```
- **Construct:** Regular expression with a repeated group that itself contains an unbounded repeat, applied to a request body field with no length limit.
- **Recommendation:** Use `/^[0-9]{1,20}#$/` (anchored, bounded, no nesting) and cap input length before matching.

### [LOW] F12: Session cookie lacks `httpOnly`/`secure`; no regeneration on login; error page echoes raw error
- **Severity:** Low
- **CWE:** CWE-1004
- **OWASP:** A05:2021
- **Verdict:** Confirmed
- **Location:** `server.js:78-102`, `app/routes/session.js:116`, `app/routes/error.js:10-12`
- **Description:** The session is served over plain HTTP with default cookie options (no `httpOnly`, no `secure`, default `connect.sid` name) and `saveUninitialized: true`. Login sets `req.session.userId` without `regenerate()`, so a pre-login session ID fixed by an attacker becomes authenticated. The global error handler renders the error object directly into an unescaped template, exposing internal messages (for example Mongo `$where` evaluation errors containing the injected payload). The login failure path also logs the raw `userName`, allowing CRLF log forging. These amplify F6 (cookie theft via XSS) rather than being independently exploitable.
- **Vulnerable code:**
```js
app.use(session({
    secret: cookieSecret,
    saveUninitialized: true,
    resave: true
}));
...
req.session.userId = user._id;
```
- **Construct:** Session middleware with default cookie flags over plaintext HTTP, authentication that reuses the pre-login session identifier, and an error handler rendering the raw exception into HTML.
- **Recommendation:** Set `cookie: { httpOnly: true, secure: true, sameSite: "lax", maxAge }`, use a non-default `name`, wrap the login success path in `req.session.regenerate()`, serve over HTTPS, and render a generic error message while logging details server-side with user input sanitized of CR/LF.

## 5. Taint Summary

| Source | Sink | Path | Sanitized? |
|--------|------|------|------------|
| `req.body.preTax/afterTax/roth` (POST /contributions) | `eval()` | `contributions.js:32-34` | No |
| `req.query.url`, `req.query.symbol` (GET /research) | `needle.get(url)` then `res.write(body)` as HTML | `research.js:15-26` | No |
| `req.query.threshold` (GET /allocations/:userId) | MongoDB `$where` JS string | `allocations.js:19-23` → `allocations-dao.js:78` | No |
| `req.params.userId` (GET /allocations/:userId) | `allocationsCol.find({userId})` cross-user read | `allocations.js:16-23` → `allocations-dao.js:57-86` | `parseInt` only; no ownership check |
| `req.body.userId`, `benefitStartDate` (POST /benefits) | `usersCol.update` on arbitrary `_id` | `benefits.js:30-35` → `benefits-dao.js:23-30` | `parseInt` only; no role check |
| `req.body.firstName/lastName/...` (POST /profile) | Mongo `$set` then unescaped `{{firstName}}` in `layout.html:75`, `allocations.html:35`, `benefits.html:51-52` | `profile.js:42-90` → `profile-dao.js:42-82` → templates | No (autoescape off) |
| `req.body.firstName` (POST /profile, validation failure) | `href="{{firstNameSafeString}}"` | `profile.js:64-75` → `profile.html:78` | No |
| `req.body.userName` (POST /login, failure) | `value="{{userName}}"` in `login.html:110`; `console.log` | `session.js:82-98` | No |
| `req.body.memo` (POST /memos) | `marked(doc.memo)` rendered to all users | `memos.js:13` → `memos-dao.js:15-23` → `memos.html:31` | Partial: `marked` `sanitize:true` (version 0.3.5, bypass risk is an SCA matter) |
| `req.query.url` (GET /learn) | `res.redirect()` | `index.js:70-73` | No |
| `req.body.bankRouting` (POST /profile) | `/([0-9]+)+\#/.test()` | `profile.js:59-61` | No length bound |
| `req.body.password` (POST /signup) | `usersCol.insert` plaintext | `session.js:220` → `user-dao.js:17-46` | No hashing |

## 6. Remediation Roadmap

**P0 (blocking):**
- F1: remove `eval()`, use `parseInt` with range validation.
- F2: remove client-controlled `url`, allowlist `symbol`, do not echo upstream body as HTML.
- F3 and F4 (shared root fix in allocations): drop `$where`, use structured filter, source `userId` from session.
- F5: add `isAdmin` middleware to `/benefits` routes and project only needed user fields.

**P1:**
- F6 and F12 (shared root: output encoding and session hardening): enable Swig autoescape, add helmet with CSP, set cookie flags, regenerate session on login, generic error page.
- F7: bcrypt hashing and comparison.
- F9: move secrets to environment, randomize seeded admin password, remove committed TLS key.

**P2:**
- F8: allowlisted redirect targets.
- F10: enable CSRF middleware and `SameSite` cookie.
- F11: anchored, bounded routing-number regex.

**P3:**
- F12 (remaining): sanitize CR/LF from logged `userName`; use non-default session cookie name.

## 7. Code-Fix Appendix

All diffs below are illustrative and untested.

**F1: contributions eval**
```diff
--- a/app/routes/contributions.js
+++ b/app/routes/contributions.js
-        const preTax = eval(req.body.preTax);
-        const afterTax = eval(req.body.afterTax);
-        const roth = eval(req.body.roth);
+        const toPct = v => (typeof v === "string" && /^\d{1,2}$/.test(v)) ? parseInt(v, 10) : NaN;
+        const preTax = toPct(req.body.preTax);
+        const afterTax = toPct(req.body.afterTax);
+        const roth = toPct(req.body.roth);
```

**F2: research SSRF**
```diff
--- a/app/routes/research.js
+++ b/app/routes/research.js
+const UPSTREAM = "https://finance.example.com/quote/";
+const SYMBOL_RE = /^[A-Z]{1,6}$/;
     this.displayResearch = (req, res) => {
-        if (req.query.symbol) {
-            const url = req.query.url + req.query.symbol;
+        const symbol = String(req.query.symbol || "");
+        if (symbol) {
+            if (!SYMBOL_RE.test(symbol)) return res.status(400).send("Invalid symbol");
+            const url = UPSTREAM + encodeURIComponent(symbol);
             return needle.get(url, (error, newResponse, body) => {
                 ...
-                if (body) { res.write(body); }
+                if (body) { res.write(ESAPI.encoder().encodeForHTML(String(body))); }
```

**F3 and F4: allocations injection and IDOR**
```diff
--- a/app/routes/allocations.js
+++ b/app/routes/allocations.js
-        const { userId } = req.params;
+        const { userId } = req.session;
--- a/app/data/allocations-dao.js
+++ b/app/data/allocations-dao.js
-            if (threshold) {
-                return {
-                    $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
-                };
-            }
+            const t = parseInt(threshold, 10);
+            if (threshold !== undefined && Number.isInteger(t) && t >= 0 && t <= 99) {
+                return { userId: parsedUserId, stocks: { $gt: t } };
+            }
             return { userId: parsedUserId };
```

**F5: benefits authorization**
```diff
--- a/app/routes/index.js
+++ b/app/routes/index.js
-    app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
-    app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
+    app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
+    app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);
```

**F6, F12: template escaping and session hardening**
```diff
--- a/server.js
+++ b/server.js
+const helmet = require("helmet");
+app.use(helmet());
     app.use(session({
-        secret: cookieSecret,
+        secret: process.env.SESSION_SECRET,
+        name: "sid",
         saveUninitialized: false,
         resave: false,
+        cookie: { httpOnly: true, secure: true, sameSite: "lax", maxAge: 30 * 60 * 1000 }
     }));
     swig.setDefaults({
-        autoescape: false
+        autoescape: true
     });
--- a/app/routes/session.js
+++ b/app/routes/session.js
-            req.session.userId = user._id;
-            return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
+            return req.session.regenerate(() => {
+                req.session.userId = user._id;
+                return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
+            });
```

**F7: password hashing**
```diff
--- a/app/data/user-dao.js
+++ b/app/data/user-dao.js
-            password //received from request param
+            password: bcrypt.hashSync(password, bcrypt.genSaltSync(12))
...
-            return fromDB === fromUser;
+            return bcrypt.compareSync(fromUser, fromDB);
```

**F9: secrets from environment**
```diff
--- a/config/env/all.js
+++ b/config/env/all.js
-    cookieSecret: "session_cookie_secret_key_here",
-    cryptoKey: "a_secure_key_for_crypto_here",
+    cookieSecret: process.env.SESSION_SECRET,
+    cryptoKey: process.env.CRYPTO_KEY,
```

## Coverage Notes

Reviewed every route handler, every DAO, the server bootstrap, configuration modules, the database seed script, and the templates that render user-controlled data. Third-party front-end bundles under `app/assets/vendor`, test fixtures, and the static tutorial pages were skipped as out of scope for code-level SAST. Dependency versions (marked 0.3.5, needle 2.2.4, mongodb 2.x, bcrypt-nodejs 0.0.3) were noted but not assessed; that belongs to the SCA skill. Memos rendering through `marked` with `sanitize:true` was traced but not rated as an independent finding, since its exploitability depends on the library version rather than the application code. No external references were needed. Confidence in this assessment is high: every finding was located in source and traced from an HTTP entry point to the sink, and the application's own inline comments corroborate each defect.