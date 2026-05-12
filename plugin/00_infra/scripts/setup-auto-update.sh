#!/usr/bin/env bash
# setup-auto-update.sh — opt-in scheduled updates via cron.
#
# Usage:
#   setup-auto-update.sh                 interactive menu
#   setup-auto-update.sh weekly          install (Mon 09:00 local)
#   setup-auto-update.sh daily           install (every day 09:00 local)
#   setup-auto-update.sh on-claude       run update.sh from Claude Code SessionStart hook
#   setup-auto-update.sh off             remove the cron entry
#   setup-auto-update.sh status          show current state
#
# Default: no auto-update. lethani never schedules itself; this script is
# only invoked when the operator explicitly asks for it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG="$HOME/.lethani-update.log"
MARK_START="# BEGIN lethani auto-update"
MARK_END="# END lethani auto-update"

say() { printf '[lethani:auto-update] %s\n' "$*"; }
warn() { printf '[lethani:auto-update] WARN: %s\n' "$*" >&2; }

usage() { sed -n '2,12p' "$0"; exit "${1:-0}"; }

read_crontab() {
  crontab -l 2>/dev/null || true
}

strip_block() {
  read_crontab | awk -v s="$MARK_START" -v e="$MARK_END" '
    $0 == s { skip = 1; next }
    $0 == e { skip = 0; next }
    !skip
  '
}

install_block() {
  local schedule="$1"
  local current
  current="$(strip_block)"
  {
    [[ -n "$current" ]] && printf '%s\n' "$current"
    printf '%s\n' "$MARK_START"
    printf '%s cd %s && ./00_infra/scripts/update.sh --quiet && ./00_infra/scripts/check-update.sh --quiet >> %s 2>&1\n' \
      "$schedule" "$ROOT" "$LOG"
    printf '%s\n' "$MARK_END"
  } | crontab -
  say "installed. schedule: $schedule"
  say "log: $LOG"
  case "$(uname -s)" in
    Darwin)
      say "macOS note: if cron is silent, give /usr/sbin/cron Full Disk Access:"
      say "  System Settings → Privacy & Security → Full Disk Access → +cron"
      ;;
  esac
}

remove_block() {
  if ! read_crontab | grep -q "$MARK_START"; then
    say "nothing to remove."
    return 0
  fi
  strip_block | crontab -
  say "removed lethani auto-update block from crontab."
}

show_status() {
  local block
  block="$(read_crontab | awk -v s="$MARK_START" -v e="$MARK_END" '
    $0 == s { p = 1; next }
    $0 == e { p = 0; next }
    p
  ')"
  if [[ -z "$block" ]]; then
    say "status: OFF (no scheduled update)"
  else
    say "status: ON"
    printf '%s\n' "$block" | sed 's/^/  /'
  fi
  [[ -f "$LOG" ]] && {
    say "last 5 log lines:"
    tail -5 "$LOG" | sed 's/^/  /'
  }
}

install_on_claude_hook() {
  local settings="$ROOT/.claude/settings.json"
  if ! command -v jq >/dev/null 2>&1; then
    warn "jq required to patch settings.json safely. Install jq and retry."
    exit 1
  fi
  if [[ ! -f "$settings" ]]; then
    warn "$settings missing — nothing to patch."
    exit 1
  fi
  local cmd
  cmd="(cd $ROOT && ./00_infra/scripts/update.sh --quiet >> $LOG 2>&1 &) 2>/dev/null; true"
  # Append a SessionStart hook entry idempotently.
  local tmp
  tmp="$(mktemp)"
  jq --arg cmd "$cmd" '
    .hooks = (.hooks // {}) |
    .hooks.SessionStart = ((.hooks.SessionStart // []) +
      [{ "hooks": [ { "type": "command", "command": $cmd, "_lethani_auto_update": true } ] }] |
      unique_by(.hooks[0]._lethani_auto_update // .hooks[0].command))
  ' "$settings" > "$tmp" && mv "$tmp" "$settings"
  say "installed on-claude-launch hook in $settings"
  say "the hook fires update.sh in the background each time you start Claude here."
}

cmd_interactive() {
  cat <<EOF
[lethani:auto-update] Choose a schedule:
  1) Weekly — Mondays 09:00 local  (recommended)
  2) Daily  — every day 09:00 local
  3) On Claude launch — background update each time you open Claude here
  4) Off (or skip)
  5) Show status

EOF
  read -r -p "  > " choice
  case "$choice" in
    1) install_block "0 9 * * 1" ;;
    2) install_block "0 9 * * *" ;;
    3) install_on_claude_hook ;;
    4) remove_block ;;
    5) show_status ;;
    *) warn "unrecognized choice." ; exit 1 ;;
  esac
}

case "${1:-}" in
  weekly)     install_block "0 9 * * 1" ;;
  daily)      install_block "0 9 * * *" ;;
  on-claude)  install_on_claude_hook ;;
  off)        remove_block ;;
  status)     show_status ;;
  "")         cmd_interactive ;;
  -h|--help)  usage ;;
  *)          usage 1 ;;
esac
