---
name: exposure-audit
description: >
  Audit what you are actually exposed to — live API keys sitting in cloud-synced folders, secrets committed to public repos, unauthenticated local services, abandoned deployments still holding environment variables, and the twenty classic vibe-coding app vulnerabilities. Use this skill whenever the user says "am I exposed", "check my security", "did I leak a key", "is anything of mine hackable", "audit my machine", "check my repos for secrets", "are we at risk of this", or pastes a security scare (a reel, a thread, a news story, a vulnerability list) and wants to know whether it applies to them. Also use it before making a repo public, before handing a project to a collaborator, and after shutting a product down. Reach for it even when the user does not say the word "security" — if the honest answer needs to know what is actually exposed, audit first, then answer.
---

# Exposure Audit

Most people running this are not shipping a SaaS with users, a database and file
uploads. So most published vulnerability checklists mostly do not apply, and saying
"you're fine" after skimming one is useless.

The real exposure is usually a different shape: **live credentials in the wrong place**,
and **things that were switched off but are still switched on somewhere**. The first
audit run with this method found live production API keys sitting in a cloud-synced
folder, one of them a payments key for a business that had closed a month earlier. Every
app-vulnerability item on the twenty-point list came back clean or not-applicable.

That is the lesson to carry in: scope the surface before running the checklist, or you
will spend the whole audit writing N/A next to things the user was never at risk of, and
miss the thing that can actually cost them money.

## The order that works

**1. Scope first, checklist second.**
Run `scripts/scan.sh` before reading any checklist. It answers: which repos exist and
which are public, what is listening, what is deployed, which domains resolve. Until you
know the surface, you cannot say whether "row-level security off" is a finding or a
non-event.

**2. Run the sweep.**

```bash
bash skills/exposure-audit/scripts/scan.sh
```

Adjust the path to wherever the skill is installed (`~/.claude/skills/exposure-audit/`
for a user-scoped install). Two optional inputs:

```bash
DOMAINS="yoursite.com another.com" \
SYNC_DIRS="$HOME/Desktop $HOME/Dropbox" \
bash skills/exposure-audit/scripts/scan.sh
```

Takes 3-6 minutes. Writes a plain-text findings file to a temp path and prints it. Every
line is prefixed with a marker (`FINDING:`, `CLEAN:`, `NOTRUN:`, `SCOPE:`) so you can
read it straight into the report without re-deriving anything.

It never prints a secret value. Where it needs to prove a key is live-format, it prints
the variable name and the first 7 characters only. Keep that discipline in everything
you write afterwards — the report gets read on a screen, sometimes a shared one.

**3. Map the findings against `references/checklist-20.md`.**
That file has the twenty classic vibe-coding vulnerabilities, each with the exact check,
what counts as a pass, and the condition under which it is genuinely not applicable.
Read it after the scan, not before.

**4. Chase what the scan could not reach.**
Cloud-sync clients (Google Drive, iCloud, Dropbox, OneDrive) do not always materialise a
file locally, so a read just hangs. The scan wraps every synced-folder read in a
`perl -e 'alarm N'` guard and emits `NOTRUN:` when it stalls. Those are not clean, and
they are not findings either. Retry each one once. If it stalls again, it ships as
**NOT RUN** with the reason.

Writing "clean" over a check that never completed is the one failure that makes the whole
audit worthless.

**5. Write the report.**
Use `assets/report-template.html`. Structure, in this order:

- **Verdict** — one sentence. How many of the checklist items actually bite, and what the
  real exposure is. If the honest headline is "the list mostly does not apply to you, but
  here are two live keys", say exactly that.
- **Do now** — ranked. Live credentials always outrank everything else, because a key
  that can move money or spend budget is the only category with an unbounded downside.
- **Later** — local-only and low-impact, with a one-line reason it can wait.
- **Clean** — what was checked and passed, each with the method. This section is not
  padding. It is the difference between "I looked and it's fine" and "I ran these
  commands and here is what they returned".
- **All 20** — the item-by-item table, with N/A items carrying a reason, not a shrug.

Every finding gets a **Fix** line that is a specific action, not advice. "Revoke it in
the payment provider's dashboard, then delete the file" beats "consider rotating
credentials". Where the order matters, say why — revoking before deleting matters because
deleting a synced file locally leaves the key in that service's version history.

Open the finished file in the browser and print the absolute path on its own line.

## Rules that stop this audit doing harm

- **Never print a secret value.** Variable name plus a 7-character prefix is enough to
  prove a key is real and live-format. The full string is never needed to make the point.
- **Never call an endpoint that changes state to test it.** A queue-draining route like
  `GET /messages` destroys real data the moment you probe it. Probe `/health` instead and
  reason about the rest. Say in the report that you inferred it rather than tested it.
- **Never `curl -L`.** A dead page that redirects to a homepage returns 200 and reads as
  alive. Follow nothing, and judge the status code you actually got.
- **Respect each site's terms.** Some platforms prohibit automated access outright. Check
  before pointing a browser or a scraper at one.
- **Do not fix anything.** This skill reports. Revoking a key, deleting a deployment and
  rotating a token are the user's calls, and some are irreversible. Rank them, make each
  one a two-minute action, and let them press the button.

## Reporting honestly

Report every finding you have evidence for, ranked, including the ones that turn out to
be low. Suppressing a minor finding to keep the report tidy removes the user's ability to
judge it. Ranking is the filter, never omission.

Three states, and they are not interchangeable:

- **Finding** — you ran a check and it failed. Name the command's result.
- **Clean** — you ran a check and it passed. Name the method.
- **NOT RUN** — the check did not complete. Say why, and what would complete it.

An audit that quietly turns a stalled read into a clean result is worse than no audit,
because the user will act on it.

## Scope and limits

- Built and tested on macOS. `lsof` and the synced-folder defaults are macOS shaped;
  Linux works with minor adjustment, Windows is untested.
- Requires `git`, `curl` and `perl`. Uses the GitHub CLI (`gh`) for repository visibility
  and `npm` for the dependency check. Each is optional — the sweep marks anything it
  cannot run as `NOTRUN:` rather than skipping it silently.
- It reads. It never writes to a repo, never revokes anything, never calls a
  state-changing endpoint.
