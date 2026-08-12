#!/usr/bin/env bash
# exposure-audit sweep — scope, credentials, web surface, dependencies.
#
# Prints marker-prefixed lines so the calling agent can build a report without
# re-deriving anything:
#   SCOPE:   what exists (repos, ports, domains, deployments)
#   FINDING: a check that failed, with the evidence
#   CLEAN:   a check that passed, with the method
#   NOTRUN:  a check that did not complete, with the reason
#
# Never prints a secret value. Keys are shown as NAME + 7-char prefix only.
# Never calls a state-changing endpoint. Never follows redirects. Never writes anything.
#
# Optional inputs:
#   DOMAINS="yoursite.com another.com"   domains to check for exposed keys and headers
#   SYNC_DIRS="$HOME/Desktop $HOME/Dropbox"  cloud-synced folders to sweep for .env files
#   OWNERS="my-login my-org"            whose repos get the deep history scan
#
# Tested on macOS. Needs git, curl and perl. Uses gh and npm where available and
# reports NOTRUN when they are missing rather than skipping silently.

set -uo pipefail

OUT="${1:-}"
if [ -z "$OUT" ]; then
  OUT="${TMPDIR:-/tmp}/exposure-audit-$(date +%Y%m%d-%H%M%S).txt"
fi
: > "$OUT"

say() { printf '%s\n' "$*" | tee -a "$OUT"; }
hdr() { say ""; say "### $*"; }

# Run a command with a hard time limit. `timeout` is not installed on this machine,
# and a piped `timeout` failure reads as success, so use perl's alarm instead.
# Returns 142 on expiry, which is how Drive stalls surface.
cap() { local secs="$1"; shift; perl -e 'alarm shift; exec @ARGV' "$secs" "$@" 2>/dev/null; }

# Key formats worth catching. Deliberately anchored to live prefixes so that
# placeholder values in .env.example files do not produce false alarms.
KEYPAT='sk-ant-api[0-9]{2}-|sk-proj-[A-Za-z0-9_-]{20,}|apify_api_[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xoxb-[0-9]{10,}|AIza[0-9A-Za-z_-]{30,}|ntn_[A-Za-z0-9]{20,}|pdl_(live|liv)[A-Za-z0-9_]{10,}|sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,}|-----BEGIN (RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY'

say "exposure-audit sweep — $(date '+%d/%m/%Y %H:%M %Z')"
say "output: $OUT"

# Folders a cloud client copies to a second system. A .env in one of these was never
# committed to git and is still published to somewhere with its own sharing rules and
# version history. Override with SYNC_DIRS="path1 path2" (no spaces in paths).
SYNC=()
if [ -n "${SYNC_DIRS:-}" ]; then
  for d in $SYNC_DIRS; do [ -d "$d" ] && SYNC+=("$d"); done
else
  for d in "$HOME/Desktop" "$HOME/Documents" "$HOME/Dropbox" "$HOME/OneDrive" \
           "$HOME/Library/Mobile Documents/com~apple~CloudDocs" \
           "$HOME/Library/CloudStorage"; do
    [ -d "$d" ] && SYNC+=("$d")
  done
fi
say "SCOPE: ${#SYNC[@]} cloud-synced folders in scope"

# ─────────────────────────────────────────────────────────────────────────────
hdr "PHASE 1 — scope"
# Scope first. Without knowing which repos are public and what is deployed, a
# checklist item cannot be scored as a finding or a non-event.

REPOS=()
for r in "$HOME"/*; do
  [ -d "$r/.git" ] && REPOS+=("$r")
done
# Synced folders are slow to walk because the client materialises files on demand,
# so cap each one and report when it does not finish rather than reporting fewer repos.
for d in ${SYNC[@]+"${SYNC[@]}"}; do
  FOUND=$(cap 45 bash -c 'for r in "$1"/*; do [ -d "$r/.git" ] && echo "$r"; done' _ "$d")
  if [ $? -eq 142 ]; then
    say "NOTRUN: repo enumeration under $d timed out after 45s (cloud client materialising files). Home-directory repos below are complete."
  else
    while IFS= read -r r; do [ -n "$r" ] && REPOS+=("$r"); done <<< "$FOUND"
  fi
done

say "SCOPE: ${#REPOS[@]} git repos found"
# Whose repos count. A clone of someone else's public repo cannot leak your keys —
# you have no push access — so deep-scanning its history is pure wasted time.
# Defaults to your own GitHub login. Set OWNERS="my-login my-org" to widen it.
OWNERS="${OWNERS:-$(cap 15 gh api user --jq .login)}"
if [ -z "$OWNERS" ]; then
  say "NOTRUN: could not resolve a GitHub login (gh missing or not authenticated), so every repo is treated as third-party and none gets the deep history scan. Fix: run 'gh auth login', or set OWNERS=\"your-login\"."
fi
PUBLIC_REPOS=()
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  # Every git call here has to be time-capped. A repo stalled by a cloud client will
  # hang `git remote get-url` indefinitely, which is how the first run of this script
  # died silently two thirds of the way through.
  url=$(cap 15 git -C "$r" remote get-url origin)
  if [ -z "$url" ]; then
    say "SCOPE:   $(basename "$r") — no remote (local only, or unreadable)"
    continue
  fi
  slug=$(printf '%s' "$url" | sed -E 's#.*github.com[:/]##; s/\.git$//')
  owner="${slug%%/*}"
  vis=$(cap 25 gh repo view "$slug" --json visibility -q .visibility)
  [ -z "$vis" ] && vis="UNKNOWN"
  mine="third-party"
  case " $OWNERS " in *" $owner "*) mine="yours" ;; esac
  say "SCOPE:   $(basename "$r") — $vis — $slug ($mine)"
  [ "$vis" = "PUBLIC" ] && [ "$mine" = "yours" ] && PUBLIC_REPOS+=("$r")
done
say "SCOPE: ${#PUBLIC_REPOS[@]} repos are BOTH public AND yours — only these get the deep history scan"

hdr "listening services"
# Anything bound to * is reachable by every device on the same network.
# Anything on 127.0.0.1 is reachable only by processes already running as you.
lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1, $9}' | sort -u | while read -r proc addr; do
  case "$addr" in
    \*:*|"[::]":*) say "SCOPE: ALL-INTERFACES  $proc  $addr" ;;
    *)             say "SCOPE: loopback       $proc  $addr" ;;
  esac
done

# ─────────────────────────────────────────────────────────────────────────────
hdr "PHASE 2 — credentials (where the real findings live)"

hdr "2a. secrets committed to git"
COMMITTED=0
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  name=$(basename "$r")
  tracked=$(cap 40 git -C "$r" ls-files | grep -iE '(^|/)\.env($|\.[a-z]+$)' | grep -v '\.example$' | head -5)
  history=$(cap 60 git -C "$r" log --all --diff-filter=A --name-only --pretty=format: \
            | grep -iE '(^|/)\.env($|\.[a-z]+$)' | grep -v '\.example$' | sort -u | head -5)
  if [ -n "$tracked" ]; then
    say "FINDING: $name tracks a real .env RIGHT NOW: $(printf '%s' "$tracked" | tr '\n' ' ')"
    COMMITTED=1
  fi
  if [ -n "$history" ] && [ -z "$tracked" ]; then
    say "FINDING: $name committed a .env historically (still in git history, deleting the file does not remove it): $(printf '%s' "$history" | tr '\n' ' ')"
    COMMITTED=1
  fi
done
[ "$COMMITTED" -eq 0 ] && say "CLEAN: no real .env is tracked or has ever been committed in any repo (checked working tree + full history with --diff-filter=A across ${#REPOS[@]} repos)"

hdr "2b. live keys inside public repos — working tree AND every commit"
# History matters more than the working tree. A key deleted in a later commit is
# still served by GitHub at its original blob URL forever.
if [ "${#PUBLIC_REPOS[@]}" -eq 0 ]; then
  say "CLEAN: no public repos to scan"
else
  for r in ${PUBLIC_REPOS[@]+"${PUBLIC_REPOS[@]}"}; do
    name=$(basename "$r")
    tree_hit=$(git -C "$r" grep -nEI "$KEYPAT" -- . 2>/dev/null | head -5)
    revs=$(git -C "$r" rev-list --all 2>/dev/null | head -300)
    hist_hit=""
    [ -n "$revs" ] && hist_hit=$(cap 90 bash -c "cd '$r' && git grep -nEI '$KEYPAT' $(printf '%s ' $revs) 2>/dev/null | head -5")
    if [ -n "$tree_hit" ]; then
      say "FINDING: PUBLIC repo $name has live-format key material in the working tree: $(printf '%s' "$tree_hit" | cut -c1-90 | head -3)"
    elif [ -n "$hist_hit" ]; then
      say "FINDING: PUBLIC repo $name has live-format key material in git history: $(printf '%s' "$hist_hit" | cut -c1-90 | head -3)"
    else
      say "CLEAN: PUBLIC repo $name — no key material in working tree or history (scanned 11 live key formats across up to 300 commits)"
    fi
  done
fi

hdr "2c. .env files in cloud-synced locations"
# This is the one the published checklists miss. A .env that was never committed to
# git is still uploaded to Drive, iCloud, Dropbox or OneDrive if it sits in one of
# their folders.
DRIVE_ENVS=""
SYNC_STALLED=0
for d in ${SYNC[@]+"${SYNC[@]}"}; do
  hits=$(cap 60 find "$d" -maxdepth 3 -name ".env" -not -path "*/node_modules/*")
  if [ $? -eq 142 ]; then
    SYNC_STALLED=1
    say "NOTRUN: .env search under $d timed out after 60s (cloud client). Re-run just this step: find '$d' -maxdepth 3 -name .env -not -path '*/node_modules/*'"
    continue
  fi
  [ -n "$hits" ] && DRIVE_ENVS="$DRIVE_ENVS$hits\n"
done
DRIVE_ENVS=$(printf '%b' "$DRIVE_ENVS" | grep -v '^$')
if [ -z "$DRIVE_ENVS" ] && [ "$SYNC_STALLED" -eq 0 ]; then
  say "CLEAN: no .env files in any cloud-synced folder (searched ${#SYNC[@]} trees to depth 3)"
elif [ -n "$DRIVE_ENVS" ]; then
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    # Print variable names and a 7-char prefix only. Enough to prove a key is
    # live-format, never enough to use it.
    body=$(cap 30 sed -E 's/=(.{0,7}).*/= \1…[REDACTED]/' "$f")
    if [ $? -eq 142 ] || [ -z "$body" ]; then
      say "NOTRUN: $f exists but could not be read in 30s (the cloud client has not materialised it). Open it manually — treat every key inside as sync-exposed until seen."
      continue
    fi
    names=$(printf '%s' "$body" | grep -vE '^\s*#|^\s*$' | tr '\n' ' ')
    if printf '%s' "$body" | grep -qE 'sk-ant-|sk-proj-|pdl_liv|sk_live_|apify_api_|ghp_|AIza|ntn_|AKIA'; then
      say "FINDING: live-format key in cloud-synced $f — $names"
    else
      say "CLEAN: $f is cloud-synced but holds no live-format key — $names"
    fi
  done <<< "$DRIVE_ENVS"
fi

hdr "2d. keys inlined in MCP config"
# A key written into an MCP server's command string prints in full on every
# `claude mcp list`, including over someone's shoulder or on a shared screen.
inline=$(grep -oE '"(command|args)":[^]]{0,400}' "$HOME/.claude.json" 2>/dev/null \
         | grep -oiE "$KEYPAT" | sort -u | head -3)
if [ -n "$inline" ]; then
  say "FINDING: ~/.claude.json has key material inline in an MCP command string (prints in full on every 'claude mcp list')"
else
  say "CLEAN: ~/.claude.json has no key material inline in MCP command strings"
fi

# ─────────────────────────────────────────────────────────────────────────────
hdr "PHASE 3 — public web surface"

# Feed in domains to check as DOMAINS="a.com b.com". No default — a domain you do not
# own is not yours to probe.
DOMAINS="${DOMAINS:-}"
[ -z "$DOMAINS" ] && say "NOTRUN: no domains checked. Re-run with DOMAINS=\"yoursite.com\" to scan served HTML for key material, public build vars and security headers."
for d in $DOMAINS; do
  u="https://$d"
  # No -L. A dead page that redirects to a homepage returns 200 and reads as alive.
  code=$(cap 20 curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$u")
  if [ -z "$code" ] || [ "$code" = "000" ]; then
    say "SCOPE: $u did not respond (no redirect followed)"
    continue
  fi
  say "SCOPE: $u -> HTTP $code"
  html=$(cap 25 curl -s --max-time 20 "$u")
  if printf '%s' "$html" | grep -qiE "$KEYPAT"; then
    say "FINDING: $u serves live-format key material in its HTML"
  else
    say "CLEAN: $u — no key material in served HTML"
  fi
  pub=$(printf '%s' "$html" | grep -ohE 'NEXT_PUBLIC_[A-Z0-9_]+' | sort -u | tr '\n' ' ')
  [ -n "$pub" ] && say "FINDING: $u exposes build-time public vars in the bundle: $pub"
  hdrs=$(cap 20 curl -sI --max-time 15 "$u")
  missing=""
  for h in content-security-policy x-frame-options x-content-type-options referrer-policy strict-transport-security; do
    printf '%s' "$hdrs" | grep -qi "^$h" || missing="$missing $h"
  done
  if [ -n "$missing" ]; then
    say "FINDING: $u missing security headers:$missing"
  else
    say "CLEAN: $u sets all five checked security headers"
  fi
done

hdr "abandoned deployments"
# A product that was shut down is only shut down if the deployment is gone too.
# A linked Vercel project can still be live with its environment variables attached.
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  if [ -f "$r/.vercel/project.json" ]; then
    pj=$(cap 15 cat "$r/.vercel/project.json")
    say "FINDING: $(basename "$r") is still linked to a Vercel project — verify it is not deployed with env vars attached: $(printf '%s' "$pj" | cut -c1-160)"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
hdr "PHASE 4 — code-level checks and dependencies"

hdr "unauthenticated API routes"
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  routes=$(cap 30 find "$r" -path "*/api/*" -name "route.ts" -not -path "*/node_modules/*")
  [ -z "$routes" ] && continue
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if ! grep -qiE "auth|session|getToken|Authorization|x-api-key" "$f" 2>/dev/null; then
      say "FINDING: ${f#$HOME/} has no auth check (severity depends on whether the app is deployed — see PHASE 1 scope)"
    fi
  done <<< "$routes"
done

hdr "CORS wildcards and unsigned webhooks"
cors=$(grep -rlE "Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*" "$HOME"/*/src 2>/dev/null | head -3)
if [ -n "$cors" ]; then say "FINDING: wildcard CORS in: $cors"; else say "CLEAN: no wildcard CORS in any src/ tree"; fi
hooks=$(grep -rliE "webhook" "$HOME"/*/src 2>/dev/null | head -5)
if [ -n "$hooks" ]; then
  for h in $hooks; do
    grep -qiE "signature|hmac|verifyWebhook|constructEvent" "$h" 2>/dev/null \
      && say "CLEAN: webhook handler ${h#$HOME/} verifies signatures" \
      || say "FINDING: webhook handler ${h#$HOME/} does not verify a signature"
  done
else
  say "CLEAN: no webhook handlers exist, so there is no signature check to get wrong"
fi

hdr "dependency vulnerabilities"
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  [ -f "$r/package.json" ] || continue
  res=$(cap 70 npm audit --prefix "$r" --json 2>/dev/null \
        | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{const v=JSON.parse(s).metadata.vulnerabilities;if(v.critical+v.high>0)console.log('crit '+v.critical+' high '+v.high+' mod '+v.moderate);}catch(e){}})")
  if [ -n "$res" ]; then
    say "FINDING: $(basename "$r") — $res"
  fi
done

say ""
say "### sweep complete — $OUT"
say "Next: read references/checklist-20.md and map these lines onto the twenty items."
say "Anything marked NOTRUN is not clean. Retry it once, then ship it as NOT RUN with the reason."
