# The twenty vibe-coding vulnerabilities — how to actually check each one

Read this **after** `scripts/scan.sh` has told you what surface exists. Read it before
and you will score items against an app the user does not have.

Each item below carries three things: the check that produces evidence, what counts as a
pass, and the condition under which it is genuinely not applicable. "Not applicable" is a
real verdict, but it needs a reason — "no database" is a reason, "probably fine" is not.

**Most of these need a public app with users, a database, or uploads.** If the user has
none of those, expect roughly thirteen N/As, and expect the audit's value to come from
items 1, 2, 5, 11 and 18 plus the exposures in `SKILL.md` that this list does not cover at
all: cloud-synced secrets, abandoned deployments, and unrevoked keys from closed products.

---

## Credential exposure — where the findings actually come from

### 1. Secrets committed to a repo
**Check:** `git ls-files | grep -i '\.env'` for the current tree, and
`git log --all --diff-filter=A --name-only` for history. Both, always.
**Pass:** only `.env.example` files, and each one contains placeholders rather than
live-format values. Verify that — an example file with a real key in it is the same leak
with a friendlier filename.
**Why history matters more than the tree:** GitHub serves a deleted file's blob at its
original URL indefinitely. Removing the file in a later commit removes nothing.
**Extend it:** a secret does not need git to escape. Anything inside a cloud-synced
folder (Google Drive, iCloud, Dropbox, OneDrive) is copied to a second system with its
own sharing rules and version history. Treat a `.env` there as published.

### 2. Real API keys in the front end
**Check:** `NEXT_PUBLIC_*` variables in source, and key patterns in the served HTML and
JS bundle of any live domain.
**Pass:** no live-format key reaches the browser. Anything prefixed `NEXT_PUBLIC_` is
inlined into the bundle at build time and is readable by every visitor — that prefix is a
declaration that the value is public, so a secret behind it is already leaked.
**N/A when:** there is no front end that ships JavaScript.

---

## Data-layer items — all need a database

### 3. Row-level security off
**Check:** Supabase/Firebase project settings; grep for `supabase`/`firebase` clients.
**Pass:** RLS enabled on every table holding user data.
**N/A when:** no database exists. State that plainly.

### 6. SQL built by string concatenation
**Check:** grep for query construction with template literals or `+` around user input.
**Pass:** parameterised queries or an ORM everywhere.
**N/A when:** no SQL.

### 14. Predictable IDs with no ownership check
**Check:** sequential integer IDs in routes, and whether the handler verifies the row
belongs to the requester.
**Pass:** the handler checks ownership regardless of ID format. Unguessable IDs are not
an access control — they are a delay.
**N/A when:** no user-owned records.

### 15. Saving the whole request body
**Check:** `update({...req.body})` or equivalent mass-assignment.
**Pass:** an explicit allow-list of fields. Otherwise a caller can set `role: "admin"` by
adding it to the payload.
**N/A when:** no persistence layer.

---

## Auth items — all need accounts

### 4. Permissions checked in the front end
**Pass:** every permission decision is re-made server-side. Hiding a button hides nothing;
the endpoint is still callable.
**N/A when:** no permission system.

### 9. Passwords stored in plain text
**Pass:** bcrypt, scrypt or argon2. **N/A when:** no accounts.

### 10. Auth tokens in localStorage
**Pass:** httpOnly cookies. localStorage is readable by any script on the page, so one XSS
becomes full account takeover.
**N/A when:** no tokens issued.

### 13. No email verification on signup
**Pass:** verification before the account can act. **N/A when:** no signup.

### 19. No password strength or breach check
**Pass:** a length floor plus a HaveIBeenPwned range check. **N/A when:** no passwords.

---

## Endpoint items — check even for local apps, then weight by exposure

### 5. No rate limiting
**Check:** any HTTP service in the PHASE 1 listening list; does it throttle?
**Pass:** limits on anything that costs money, sends messages or attempts auth.
**Weight it:** a service bound to `127.0.0.1` is reachable only by processes already
running as that user, so this is a low finding, not a critical one. A service on `*` is
reachable by everything on the same network. The scan labels which is which — use that label
rather than assuming.

### 11. Admin panel with no auth
**Check:** unauthenticated request to a health or index route; grep API route handlers for
any auth reference.
**Pass:** authentication on anything that performs actions.
**Careful:** do not probe a state-changing endpoint to test it. A route like
`GET /messages` can consume a queue and destroy real data the moment you call it. Probe
`/health`, then reason about the rest and label the conclusion as inferred.

### 7. No server-side input validation
**Pass:** schema validation at the boundary. Client validation is a UX feature.
**N/A when:** no endpoint accepts input from anyone but the user themselves.

### 12. CORS set to `*`
**Pass:** an explicit origin allow-list. A wildcard plus credentials means any site can
make authenticated calls on a visitor's behalf.

### 16. Webhooks with no signature check
**Pass:** HMAC verification against the provider's secret. Without it the endpoint accepts
a forged "payment succeeded" from anyone who knows the URL.
**N/A when:** no webhook handlers exist.

### 20. File uploads with no validation
**Pass:** type, size and extension checks, and storage outside the web root.
**N/A when:** no upload endpoints.

---

## Output and operational items

### 8. Rendering user content as raw HTML
**Check:** `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`.
**Pass:** escaped by default, sanitised where raw HTML is genuinely needed.
**N/A when:** no user-submitted content is displayed.

### 17. Stack traces in production
**Check:** error responses on the live domain; `NODE_ENV` handling in error paths.
**Pass:** a generic message to the client, the detail in the logs. A stack trace names file
paths, package versions and sometimes credentials.
**N/A when:** nothing dynamic runs in production.

### 18. Never updating dependencies
**Check:** `npm audit` per project.
**Pass:** zero critical, and highs triaged rather than ignored.
**Weight it:** on a local-only tool this is low — nothing hostile is reaching it. On
anything deployed it moves up immediately. Report the counts either way so the trend is
visible next time.

---

## What this list does not cover, and should

Twenty-point lists like this one assume the reader has shipped an app. The exposure that
actually turns up sits in three places they never mention, and every one of them produced
a real finding on the first run of this audit:

1. **Synced folders.** A `.env` inside a Drive, iCloud, Dropbox or OneDrive folder was
   never committed, and is still copied to a second system with its own sharing and
   version history.
2. **Closed products with live keys.** Shutting a business down does not revoke its API
   keys. A payments key for a dead product is the highest-downside item on this page,
   because it is the only one that can move money.
3. **Abandoned deployments.** A linked Vercel or Netlify project outlives the product and
   keeps its environment variables. Unlinking locally changes nothing.

Check these three first. They are faster than the twenty and they are where the findings
have actually been.
