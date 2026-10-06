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
# Never calls a state-changing endpoint. Never follows redirects. Never writes anything
# except the findings file.
#
# Usage: scan.sh [findings-file]   (default: a timestamped file in $TMPDIR)
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
# Repos sit in nested folders (~/code/client/app), so look three levels down, not one.
# Library and hidden folders are skipped: they hold caches and tool clones, and are slow
# to walk. Synced folders are pruned here and walked below with their own time limit.
find_repos() { # find_repos SECS DIR [extra prune tests...]
  local secs="$1" dir="$2"; shift 2
  cap "$secs" find "$dir" -mindepth 1 -maxdepth 3 \( "$@" -name Library -o -name node_modules \
    -o \( -name '.*' -not -name .git \) \) -prune -o -type d -name .git -print -prune
}
PRUNE=()
for d in ${SYNC[@]+"${SYNC[@]}"}; do PRUNE+=(-path "$d" -o); done
ALL_GIT=$(find_repos 90 "$HOME" ${PRUNE[@]+"${PRUNE[@]}"})
if [ $? -eq 142 ]; then
  say "NOTRUN: repo search under $HOME (3 levels deep) timed out after 90s. Repos found before the limit are listed below. Others may be missing."
fi
# Synced folders are slow to walk because the client materialises files on demand,
# so cap each one and report when it does not finish rather than reporting fewer repos.
for d in ${SYNC[@]+"${SYNC[@]}"}; do
  FOUND=$(find_repos 45 "$d")
  if [ $? -eq 142 ]; then
    say "NOTRUN: repo search under $d timed out after 45s (cloud client materialising files). Repos found before the limit are still listed."
  fi
  ALL_GIT="$ALL_GIT"$'\n'"$FOUND"
done
while IFS= read -r g; do [ -n "$g" ] && REPOS+=("${g%/.git}"); done <<< "$(printf '%s\n' "$ALL_GIT" | sort -u)"

say "SCOPE: ${#REPOS[@]} git repos found"
# Whose repos count. A clone of someone else's public repo cannot leak your keys —
# you have no push access — so deep-scanning its history is pure wasted time.
# Defaults to your own GitHub login. Set OWNERS="my-login my-org" to widen it.
OWNERS="${OWNERS:-$(cap 15 gh api user --jq .login)}"
if [ -z "$OWNERS" ]; then
  say "NOTRUN: could not resolve a GitHub login (gh missing or not authenticated), so every repo is treated as third-party and none gets the deep history scan. Fix: run 'gh auth login', or set OWNERS=\"your-login\"."
fi
PUBLIC_REPOS=()
LOCAL_REPOS=()
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  # Every git call here has to be time-capped. A repo stalled by a cloud client will
  # hang `git remote get-url` indefinitely, which is how the first run of this script
  # died silently two thirds of the way through.
  url=$(cap 15 git -C "$r" remote get-url origin)
  if [ -z "$url" ]; then
    say "SCOPE:   $(basename "$r"): no remote (local only, or unreadable). Gets the deep history scan, because making it public later publishes that history"
    LOCAL_REPOS+=("$r")
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
say "SCOPE: ${#PUBLIC_REPOS[@]} repos are BOTH public AND yours, and ${#LOCAL_REPOS[@]} have no remote. Only these get the deep history scan"

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
# Capture each git call's own exit status BEFORE piping into grep. Piping first
# throws the status away, so a read that hit the alarm (142) or a corrupt ref
# (128) returns empty output and reads exactly like a clean repo. That is the one
# failure this whole audit is built to avoid, so a stalled read must become
# NOTRUN, never silence.
COMMITTED=0
SCANNED_2A=0
NOTRUN_2A=0
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  name=$(basename "$r")

  raw_tracked=$(cap 40 git -C "$r" ls-files 2>/dev/null); rc_tracked=$?
  if [ "$rc_tracked" -ne 0 ]; then
    say "NOTRUN: $name working tree read did not complete (git ls-files exit $rc_tracked; 142 = timed out, 128 = git error such as a corrupt ref). Retry with a longer guard, or fix the repo."
    NOTRUN_2A=1
    continue
  fi
  tracked=$(printf '%s\n' "$raw_tracked" | grep -iE '(^|/)\.env($|\.[a-z]+$)' | grep -v '\.example$' | head -5)

  raw_history=$(cap 60 git -C "$r" log --all --diff-filter=A --name-only --pretty=format: 2>/dev/null); rc_history=$?
  if [ "$rc_history" -ne 0 ]; then
    # A full-history walk stalls on large repos inside a cloud-synced folder. A
    # pathspec-limited query answers the same question for a fraction of the work,
    # so try that before giving up on the repo.
    raw_history=$(cap 90 git -C "$r" log --all --name-only --pretty=format: -- '.env' '**/.env' '*.env' 2>/dev/null); rc_history=$?
    if [ "$rc_history" -ne 0 ]; then
      say "NOTRUN: $name git history was not scanned (--diff-filter=A walk and pathspec fallback both exit $rc_history; 142 = timed out, 128 = git error such as a corrupt ref). This repo is UNVERIFIED for committed secrets."
      NOTRUN_2A=1
      continue
    fi
  fi
  history=$(printf '%s\n' "$raw_history" | grep -iE '(^|/)\.env($|\.[a-z]+$)' | grep -v '\.example$' | sort -u | head -5)

  SCANNED_2A=$((SCANNED_2A + 1))
  if [ -n "$tracked" ]; then
    say "FINDING: $name tracks a real .env RIGHT NOW: $(printf '%s' "$tracked" | tr '\n' ' ')"
    COMMITTED=1
  fi
  if [ -n "$history" ] && [ -z "$tracked" ]; then
    say "FINDING: $name committed a .env historically (still in git history, deleting the file does not remove it): $(printf '%s' "$history" | tr '\n' ' ')"
    COMMITTED=1
  fi
done
if [ "$COMMITTED" -eq 0 ]; then
  if [ "$NOTRUN_2A" -eq 1 ]; then
    say "CLEAN: no real .env is tracked or has ever been committed in the $SCANNED_2A of ${#REPOS[@]} repos that completed (working tree + history). The repos above marked NOTRUN are NOT covered by this line."
  else
    say "CLEAN: no real .env is tracked or has ever been committed in any repo (checked working tree + full history across all ${#REPOS[@]} repos)"
  fi
fi

hdr "2b. live keys in public and local-only repos, working tree AND every commit"
# History matters more than the working tree. A key deleted in a later commit is
# still served by GitHub at its original blob URL forever. A repo with no remote is
# scanned too, because making it public later publishes all of that history.
# Only locations are printed (file:line, or commit:file:line). The matched line holds
# the key itself, so it never reaches the output. git grep exits 1 for no match, so
# any higher exit status is a scan that did not complete.
deep_scan() { # deep_scan REPO LABEL
  local r="$1" kind="$2" name revs rc_r tree_hit rc_t hist_hit rc_h
  name=$(basename "$r")
  revs=$(cap 30 git -C "$r" rev-list --all --max-count=300); rc_r=$?
  tree_hit=$(cap 60 git -C "$r" grep -nIE -e "$KEYPAT" -- .); rc_t=$?
  hist_hit=""; rc_h=1
  if [ -n "$revs" ]; then
    # $revs is unquoted on purpose: one argument per commit.
    hist_hit=$(cap 90 git -C "$r" grep -nIE -e "$KEYPAT" $revs --); rc_h=$?
  fi
  if [ -n "$tree_hit" ]; then
    say "FINDING: $kind $name has live-format key material in the working tree at (file:line): $(printf '%s\n' "$tree_hit" | cut -d: -f1-2 | head -3 | tr '\n' ' ')"
  elif [ -n "$hist_hit" ]; then
    say "FINDING: $kind $name has live-format key material in git history at (commit:file:line): $(printf '%s\n' "$hist_hit" | cut -d: -f1-3 | head -3 | tr '\n' ' ')"
  elif [ "$rc_r" -ne 0 ] || [ "$rc_t" -gt 1 ] || [ "$rc_h" -gt 1 ]; then
    say "NOTRUN: $kind $name was not fully scanned (rev-list exit $rc_r, tree grep exit $rc_t, history grep exit $rc_h. 142 = timed out). It is UNVERIFIED for key material."
  else
    say "CLEAN: $kind $name: no key material in working tree or history (scanned 13 live key formats across up to 300 commits)"
  fi
}
if [ "${#PUBLIC_REPOS[@]}" -eq 0 ] && [ "${#LOCAL_REPOS[@]}" -eq 0 ]; then
  say "CLEAN: no public or local-only repos to scan"
fi
for r in ${PUBLIC_REPOS[@]+"${PUBLIC_REPOS[@]}"}; do deep_scan "$r" "PUBLIC repo"; done
for r in ${LOCAL_REPOS[@]+"${LOCAL_REPOS[@]}"}; do deep_scan "$r" "LOCAL-ONLY repo (no remote)"; done

hdr "2c. .env files in cloud-synced locations"
# This is the one the published checklists miss. A .env that was never committed to
# git is still uploaded to Drive, iCloud, Dropbox or OneDrive if it sits in one of
# their folders.
DRIVE_ENVS=""
SYNC_STALLED=0
for d in ${SYNC[@]+"${SYNC[@]}"}; do
  hits=$(cap 60 find "$d" -maxdepth 3 \( -name '.env' -o -name '.env.*' \) -not -name '*.example' -not -path "*/node_modules/*")
  if [ $? -eq 142 ]; then
    SYNC_STALLED=1
    say "NOTRUN: .env search under $d timed out after 60s (cloud client). Re-run just this step: find '$d' -maxdepth 3 -name '.env*' -not -name '*.example' -not -path '*/node_modules/*'"
    continue
  fi
  [ -n "$hits" ] && DRIVE_ENVS="$DRIVE_ENVS$hits\n"
done
DRIVE_ENVS=$(printf '%b' "$DRIVE_ENVS" | grep -v '^$')
if [ -z "$DRIVE_ENVS" ] && [ "$SYNC_STALLED" -eq 0 ]; then
  say "CLEAN: no .env or .env.* files in any cloud-synced folder (searched ${#SYNC[@]} trees to depth 3)"
elif [ -n "$DRIVE_ENVS" ]; then
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    # Print variable names and a 7-char prefix only. Enough to prove a key is
    # live-format, never enough to use it. Only NAME=value lines are printed. The
    # lines inside a multi-line value (a PEM private key, say) are the secret itself,
    # and base64 padding puts an "=" in them, so they are skipped by tracking the
    # open quote or BEGIN block rather than by looking for "=".
    body=$(cap 30 awk '
      inpem { if ($0 ~ /-----END/) { inpem = 0; if (inq && index($0, q)) inq = 0 }; next }
      inq   { if (index($0, q)) inq = 0; next }
      /^[[:space:]]*(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_.]*[[:space:]]*=/ {
        i = index($0, "="); val = substr($0, i + 1); v = val; sub(/^[[:space:]]+/, "", v)
        c = substr(v, 1, 1)
        if ((c == "\"" || c == "\047") && index(substr(v, 2), c) == 0) { inq = 1; q = c }
        if (val ~ /-----BEGIN/ && val !~ /-----END/) inpem = 1
        print substr($0, 1, i) " " substr(val, 1, 7) "…[REDACTED]"
      }' "$f"); rc_body=$?
    if [ "$rc_body" -ne 0 ] || { [ -z "$body" ] && [ ! -s "$f" ]; }; then
      say "NOTRUN: $f exists but could not be read in 30s (the cloud client has not materialised it). Open it manually — treat every key inside as sync-exposed until seen."
      continue
    fi
    names=$(printf '%s' "$body" | grep -vE '^\s*#|^\s*$' | tr '\n' ' ')
    # Match the full KEYPAT against the raw file, never the redacted text, so PEM
    # keys, rk_live_, xoxb- and github_pat_ count too. grep -q prints nothing.
    cap 30 grep -qE "$KEYPAT" "$f"; rc_key=$?
    if [ "$rc_key" -eq 0 ]; then
      say "FINDING: live-format key in cloud-synced $f: $names"
    elif [ "$rc_key" -eq 1 ]; then
      say "CLEAN: $f is cloud-synced but holds no live-format key: $names"
    else
      say "NOTRUN: $f could not be matched against the key formats (grep exit $rc_key. 142 = timed out). Treat it as sync-exposed until checked."
    fi
  done <<< "$DRIVE_ENVS"
fi

hdr "2d. keys inlined in MCP config"
# A key written into an MCP server's command string prints in full on every
# `claude mcp list`, including over someone's shoulder or on a shared screen.
# Each grep's exit status is kept. macOS grep rejects a repetition count above 255,
# and that error, hidden by 2>/dev/null, used to read as CLEAN.
CJ="$HOME/.claude.json"
if [ ! -f "$CJ" ]; then
  say "CLEAN: no ~/.claude.json, so there are no MCP command strings to check"
else
  cmds=$(cap 30 grep -oE '"(command|args)":[^]]*' "$CJ"); rc_cmd=$?
  rc_key=1
  if [ "$rc_cmd" -eq 0 ]; then grep -qiE "$KEYPAT" <<< "$cmds"; rc_key=$?; fi
  if [ "$rc_key" -eq 0 ]; then
    say "FINDING: ~/.claude.json has key material inline in an MCP command string (prints in full on every 'claude mcp list')"
  elif [ "$rc_cmd" -gt 1 ] || [ "$rc_key" -gt 1 ]; then
    say "NOTRUN: ~/.claude.json could not be searched (grep exit $rc_cmd then $rc_key. 142 = timed out). Not checked, so not clean."
  else
    say "CLEAN: ~/.claude.json has no key material inline in MCP command strings"
  fi
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
VERCEL=0
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  if [ -f "$r/.vercel/project.json" ]; then
    pj=$(cap 15 cat "$r/.vercel/project.json")
    VERCEL=1
    say "FINDING: $(basename "$r") is still linked to a Vercel project — verify it is not deployed with env vars attached: $(printf '%s' "$pj" | cut -c1-160)"
  fi
done
if [ "$VERCEL" -eq 0 ]; then
  say "CLEAN: none of the ${#REPOS[@]} repos is linked to a Vercel project (no .vercel/project.json)"
fi

# ─────────────────────────────────────────────────────────────────────────────
hdr "PHASE 4 — code-level checks and dependencies"

hdr "unauthenticated API routes"
ROUTES_SEEN=0
ROUTE_FINDING=0
ROUTE_NOTRUN=0
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  routes=$(cap 30 find "$r" -path "*/api/*" -name "route.ts" -not -path "*/node_modules/*")
  if [ $? -eq 142 ]; then
    say "NOTRUN: API route search in $(basename "$r") timed out after 30s"
    ROUTE_NOTRUN=1
  fi
  [ -z "$routes" ] && continue
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    ROUTES_SEEN=$((ROUTES_SEEN + 1))
    if ! grep -qiE "auth|session|getToken|Authorization|x-api-key" "$f" 2>/dev/null; then
      say "FINDING: ${f#$HOME/} has no auth check (severity depends on whether the app is deployed, see PHASE 1 scope)"
      ROUTE_FINDING=1
    fi
  done <<< "$routes"
done
if [ "$ROUTE_FINDING" -eq 0 ]; then
  if [ "$ROUTES_SEEN" -eq 0 ]; then
    say "CLEAN: no API route files (api/**/route.ts) in any of the ${#REPOS[@]} repos"
  else
    say "CLEAN: all $ROUTES_SEEN API route files mention an auth check (auth, session, token or API key)"
  fi
  [ "$ROUTE_NOTRUN" -eq 1 ] && say "NOTRUN: the repos marked NOTRUN above are not covered by that CLEAN line"
fi

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
DEPS_CHECKED=0
DEPS_FINDING=0
DEPS_NOTRUN=0
for r in ${REPOS[@]+"${REPOS[@]}"}; do
  [ -f "$r/package.json" ] || continue
  res=$(cap 70 npm audit --prefix "$r" --json 2>/dev/null \
        | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{const v=JSON.parse(s).metadata.vulnerabilities;console.log(v.critical+v.high>0?'crit '+v.critical+' high '+v.high+' mod '+v.moderate:'none');}catch(e){console.log('unreadable')}})")
  case "$res" in
    crit*) say "FINDING: $(basename "$r"): $res"; DEPS_FINDING=1 ;;
    none)  DEPS_CHECKED=$((DEPS_CHECKED + 1)) ;;
    *)     say "NOTRUN: $(basename "$r") npm audit gave no readable result (npm or node missing, no lockfile, or offline)"; DEPS_NOTRUN=1 ;;
  esac
done
if [ "$DEPS_FINDING" -eq 0 ]; then
  if [ "$DEPS_CHECKED" -gt 0 ]; then
    say "CLEAN: npm audit found no critical or high vulnerabilities (repos audited: $DEPS_CHECKED)"
  elif [ "$DEPS_NOTRUN" -eq 0 ]; then
    say "CLEAN: no repo has a package.json, so there are no npm dependencies to audit"
  fi
fi

say ""
say "### sweep complete — $OUT"
say "Next: read references/checklist-20.md and map these lines onto the twenty items."
say "Anything marked NOTRUN is not clean. Retry it once, then ship it as NOT RUN with the reason."
