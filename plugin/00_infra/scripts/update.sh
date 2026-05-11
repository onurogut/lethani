#!/usr/bin/env bash
# update.sh — pull latest lethani, surface what changed, warn on Kali drift.
# Workspace-mode update path. Plugin-mode users use `/plugin update lethani`.
#
# Flags:
#   --quiet     suppress informational lines; only warnings + summary.
#               Used by scheduled (cron) invocations.
set -euo pipefail

QUIET=0
for arg in "$@"; do
  case "$arg" in
    --quiet) QUIET=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

say()  { [[ $QUIET -eq 1 ]] && return 0; printf '[lethani:update] %s\n' "$*"; }
warn() { printf '[lethani:update] WARN: %s\n' "$*" >&2; }

# 0. sanity: must be a git repo
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  warn "$ROOT is not a git repo — nothing to pull."
  warn "use plugin mode (/plugin update lethani) or clone the repo for updates."
  exit 1
fi

# 1. capture pre-pull state for diff
BEFORE="$(git rev-parse HEAD)"

# 2. fetch + fast-forward only (refuse to merge anything ambiguous)
say "git fetch + fast-forward"
git fetch --quiet
if ! git merge --ff-only @{u} 2>/dev/null; then
  warn "fast-forward not possible — you have local changes ahead of upstream."
  warn "review with: git status; git log @{u}..HEAD"
  exit 2
fi

AFTER="$(git rev-parse HEAD)"

if [[ "$BEFORE" == "$AFTER" ]]; then
  say "already up to date."
  exit 0
fi

# 3. current version
if [[ -x "$ROOT/bin/lethani" ]]; then
  say "version: $("$ROOT/bin/lethani" version)"
fi

# 4. detect Kali setup script changes
if git diff --quiet "$BEFORE" "$AFTER" -- 00_infra/scripts/setup-kali.sh; then
  say "Kali toolchain script unchanged."
else
  warn "setup-kali.sh changed — re-run on Kali to pick up new tools:"
  echo "  scp $ROOT/00_infra/scripts/setup-kali.sh talon-kali:/tmp/"
  echo "  ssh talon-kali 'bash /tmp/setup-kali.sh'"
fi

# 5. detect execution_environment.md changes (tool inventory)
if ! git diff --quiet "$BEFORE" "$AFTER" -- 00_infra/execution_environment.md; then
  say "tool inventory doc changed — review 00_infra/execution_environment.md"
fi

# 6. show recent Learning Mode patches
if [[ -f 00_infra/_changelog.md ]]; then
  RECENT="$(tail -n 10 00_infra/_changelog.md | grep -E '^[0-9]{4}-' || true)"
  if [[ -n "$RECENT" ]]; then
    say "recent Learning Mode patches:"
    printf '%s\n' "$RECENT" | sed 's/^/  /'
  fi
fi

# 7. summary of changed playbook files
say "playbook files changed:"
git diff --name-only "$BEFORE" "$AFTER" -- '01_recon/*.md' '02_vuln_testing/*.md' '03_reporting/*.md' '04_automation/*.md' '05_osint/*.md' \
  | sed 's/^/  /' || true

say "done. $BEFORE -> $AFTER"
