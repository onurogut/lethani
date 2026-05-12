#!/usr/bin/env bash
# check-update.sh — compare local lethani version to the latest GitHub release,
# print a status line, and (in --quiet mode for cron) only write output when
# there is something to act on.
#
# Usage:
#   check-update.sh                interactive (always prints status)
#   check-update.sh --quiet        cron-friendly (only prints when an update
#                                  is available or learning is stale)
#   check-update.sh --json         machine-readable
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"           # plugin/ root
PLUGIN_JSON="$ROOT/.claude-plugin/plugin.json"
CHANGELOG="$ROOT/00_infra/_changelog.md"
PENDING="$ROOT/00_infra/_pending_patches.md"

MODE="text"
for arg in "$@"; do
  case "$arg" in
    --quiet) MODE="quiet" ;;
    --json)  MODE="json"  ;;
    -h|--help)
      sed -n '2,11p' "$0"
      exit 0
      ;;
  esac
done

# local version
LOCAL="unknown"
if [[ -f "$PLUGIN_JSON" ]] && command -v jq >/dev/null 2>&1; then
  LOCAL=$(jq -r '.version // "unknown"' "$PLUGIN_JSON")
fi

# latest release
LATEST="unknown"
if command -v gh >/dev/null 2>&1; then
  LATEST=$(gh api repos/onurogut/lethani/releases/latest --jq '.tag_name' 2>/dev/null | sed 's/^v//' || echo unknown)
elif command -v curl >/dev/null 2>&1; then
  LATEST=$(curl -sf https://api.github.com/repos/onurogut/lethani/releases/latest 2>/dev/null \
    | grep -m1 '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')
  LATEST="${LATEST:-unknown}"
fi

# compare (simple string compare; semver-safe for X.Y.Z)
UPDATE_AVAILABLE="no"
if [[ "$LOCAL" != "unknown" && "$LATEST" != "unknown" && "$LOCAL" != "$LATEST" ]]; then
  # lexically less means older for X.Y.Z up to ~99
  if [[ "$(printf '%s\n%s' "$LOCAL" "$LATEST" | sort -V | head -1)" == "$LOCAL" ]]; then
    UPDATE_AVAILABLE="yes"
  fi
fi

# learning freshness
LAST_LEARN=""
LEARN_DAYS=""
if [[ -f "$CHANGELOG" ]]; then
  LAST_LEARN=$(grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}' "$CHANGELOG" | tail -1 | cut -c1-10 || true)
  if [[ -n "$LAST_LEARN" ]]; then
    # macOS date vs GNU date
    if date -j -f "%Y-%m-%d" "$LAST_LEARN" "+%s" >/dev/null 2>&1; then
      LEARN_TS=$(date -j -f "%Y-%m-%d" "$LAST_LEARN" "+%s")
    else
      LEARN_TS=$(date -d "$LAST_LEARN" "+%s")
    fi
    NOW_TS=$(date "+%s")
    LEARN_DAYS=$(( (NOW_TS - LEARN_TS) / 86400 ))
  fi
fi

# pending patches
PENDING_COUNT=0
if [[ -f "$PENDING" ]]; then
  PENDING_COUNT=$(grep -c '^STATUS *: *pending' "$PENDING" 2>/dev/null || echo 0)
fi

# decide whether to surface in quiet mode
NEEDS_ACTION="no"
[[ "$UPDATE_AVAILABLE" == "yes" ]] && NEEDS_ACTION="yes"
[[ -n "$LEARN_DAYS" && "$LEARN_DAYS" -gt 7 ]] && NEEDS_ACTION="yes"
[[ "$PENDING_COUNT" -gt 0 ]] && NEEDS_ACTION="yes"

emit_text() {
  printf 'LETHANI HEALTH — %s\n' "$(date '+%Y-%m-%d %H:%M')"
  printf -- '─────────────────────────────────────────\n'
  printf 'plugin version  : v%s\n' "$LOCAL"
  printf 'latest release  : v%s' "$LATEST"
  [[ "$UPDATE_AVAILABLE" == "yes" ]] && printf '  (UPDATE AVAILABLE)\n' || printf '  (up to date)\n'
  if [[ -n "$LAST_LEARN" ]]; then
    printf 'last learning   : %s  (%d days ago)\n' "$LAST_LEARN" "$LEARN_DAYS"
  else
    printf 'last learning   : never\n'
  fi
  printf 'pending patches : %s\n' "$PENDING_COUNT"
  printf -- '─────────────────────────────────────────\n'
  RECS=()
  [[ "$UPDATE_AVAILABLE" == "yes" ]] && RECS+=("Update plugin: /plugin marketplace update lethani  →  /plugin install lethani@lethani")
  [[ -n "$LEARN_DAYS" && "$LEARN_DAYS" -gt 7 ]] && RECS+=("Run /learn-fetch (last update was $LEARN_DAYS days ago)")
  [[ -z "$LAST_LEARN" ]] && RECS+=("No Learning Mode run yet — try /learn-fetch")
  [[ "$PENDING_COUNT" -gt 0 ]] && RECS+=("Review staged patches: /learn-pending  ($PENDING_COUNT pending)")
  if [[ ${#RECS[@]} -gt 0 ]]; then
    printf 'RECOMMENDATIONS\n'
    for r in "${RECS[@]}"; do printf '  - %s\n' "$r"; done
  fi
}

emit_json() {
  printf '{"local":"v%s","latest":"v%s","update_available":"%s","last_learning":"%s","learn_days":"%s","pending_patches":%d,"needs_action":"%s"}\n' \
    "$LOCAL" "$LATEST" "$UPDATE_AVAILABLE" "$LAST_LEARN" "$LEARN_DAYS" "$PENDING_COUNT" "$NEEDS_ACTION"
}

case "$MODE" in
  text)  emit_text ;;
  json)  emit_json ;;
  quiet) [[ "$NEEDS_ACTION" == "yes" ]] && emit_text ;;
esac
