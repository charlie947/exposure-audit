# Exposure Audit

A Claude skill that audits your own setup and tells you which API keys you have left lying around.

There are twenty classic ways an AI-built app gets hacked. Run all twenty against a machine that isn't running a SaaS and most of them cannot even apply — no users, no database, no uploads. That is why "you're fine" after skimming a checklist is useless.

The exposure that actually turns up is a different shape: **live credentials in the wrong place**, and **things you switched off that are still switched on somewhere**. This skill scopes your surface first, then scores the checklist against it, so you spend the audit on the things that can genuinely cost you money.

## What it catches that the lists miss

1. **Live keys inside cloud-synced folders.** A `.env` in Drive, iCloud, Dropbox or OneDrive was never committed to git and is still copied to a second system with its own sharing rules and version history.
2. **Unrevoked keys from products you shut down.** Closing a business does not revoke its API keys. A payments key for a dead product is the highest-downside item on the page, because it is the only one that can move money.
3. **Abandoned deployments.** A linked Vercel or Netlify project outlives the product and keeps its environment variables attached. Unlinking locally changes nothing.

It also checks git history, not just the working tree. Deleting a key out of your code does nothing — GitHub serves the old blob at its original URL indefinitely.

## What it never does

- **Never prints a secret value.** Variable name plus a 7-character prefix is enough to prove a key is real and live-format.
- **Never calls a state-changing endpoint to test it.** A route that drains a queue destroys real data the moment you probe it.
- **Never follows redirects.** A dead page that redirects to a homepage returns 200 and reads as alive.
- **Never fixes anything.** It reports. Revoking a key and deleting a deployment are your calls, and some are irreversible.
- **NOT RUN is a first-class verdict.** When a check does not complete, it says so and tells you what would complete it. An audit that quietly turns a stalled read into a clean result is worse than no audit, because you will act on it.

## Install

### Claude Code plugin marketplace

```bash
/plugin marketplace add charlie947/exposure-audit
/plugin install exposure-audit
```

### Clone and copy

```bash
git clone https://github.com/charlie947/exposure-audit.git
cp -r exposure-audit/skills/exposure-audit ~/.claude/skills/
```

### Claude Desktop

```bash
git clone https://github.com/charlie947/exposure-audit.git
cd exposure-audit/skills
zip -r exposure-audit.skill exposure-audit
# Upload exposure-audit.skill through Customise skills in the Claude app
```

## Use it

Ask Claude any of these and the skill triggers:

```
"Am I exposed?"
"Did I leak a key?"
"Check my repos for secrets"
"Audit my machine"
```

Or run the sweep directly:

```bash
bash ~/.claude/skills/exposure-audit/scripts/scan.sh
```

Three optional inputs:

```bash
DOMAINS="yoursite.com"                    # check served HTML, build vars, security headers
SYNC_DIRS="$HOME/Desktop $HOME/Dropbox"   # which folders your cloud client syncs
OWNERS="my-login my-org"                  # whose repos get the deep history scan
```

The sweep takes 3-6 minutes and writes a marker-prefixed findings file (`FINDING:`, `CLEAN:`, `NOTRUN:`, `SCOPE:`) that Claude reads straight into a report. `assets/report-template.html` is the report format: verdict, do now, later, clean-with-method, then the item-by-item table.

## Requirements

Built and tested on macOS. Needs `git`, `curl` and `perl`. Uses the GitHub CLI (`gh`) for repository visibility and `npm` for the dependency check — both optional, and the sweep marks anything it cannot run as `NOTRUN:` rather than skipping it silently. Linux works with minor adjustment. Windows is untested.

## What's in here

| Path | What it is |
|---|---|
| `skills/exposure-audit/SKILL.md` | The workflow. Scope first, checklist second. |
| `skills/exposure-audit/scripts/scan.sh` | The sweep. Read-only, time-capped, redacting. |
| `skills/exposure-audit/references/checklist-20.md` | All twenty items, each with the check, the pass condition, and when it is genuinely N/A. |
| `skills/exposure-audit/assets/report-template.html` | Self-contained report template. |

## License

[MIT](LICENSE). Use it however you like.

Built by [Charlie Hills](https://charliehills.substack.com). Subscribe to the [MarTech AI newsletter](https://charliehills.substack.com) for weekly breakdowns of how this system works in practice.

— Charlie
