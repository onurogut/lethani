#!/usr/bin/env bash
# setup-host.sh — wire the local (host-side) prerequisites for lethani.
#
# What it does:
#   1. Verifies required binaries (ssh, scp, jq, curl, git).
#   2. Ensures an SSH key pair exists at ~/.ssh/talon_kali (generates if missing).
#   3. Checks ~/.ssh/config for a Host talon-kali block (prints a template if missing).
#   4. Writes a sample MCP server entry to ~/.claude.json.lethani.example
#      that the operator merges into their real Claude Code MCP config.
#   5. Probes ssh talon-kali "uname -a" and reports.
#
# Idempotent. Never overwrites existing files; appends or writes side-by-side
# samples.
set -euo pipefail

LETHANI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SSH_KEY="$HOME/.ssh/talon_kali"
SSH_CFG="$HOME/.ssh/config"
MCP_SAMPLE="$HOME/.claude.json.lethani.example"

say() { printf '[lethani:host] %s\n' "$*"; }
warn() { printf '[lethani:host] WARN: %s\n' "$*" >&2; }
die()  { printf '[lethani:host] ERROR: %s\n' "$*" >&2; exit 1; }

# 1. binaries
for bin in ssh scp jq curl git; do
  command -v "$bin" >/dev/null 2>&1 || die "missing binary: $bin"
done
say "host binaries OK (ssh scp jq curl git)"

# 2. SSH key
if [[ ! -f "$SSH_KEY" ]]; then
  say "generating SSH key at $SSH_KEY"
  ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "lethani-kali" >/dev/null
  say "public key:"
  cat "${SSH_KEY}.pub"
  warn "copy this public key into Kali's ~/.ssh/authorized_keys (ssh-copy-id is easiest)"
else
  say "SSH key exists at $SSH_KEY"
fi

# 3. ~/.ssh/config
mkdir -p "$HOME/.ssh"
touch "$SSH_CFG"
chmod 600 "$SSH_CFG"
if grep -q '^Host talon-kali' "$SSH_CFG"; then
  say "ssh config: 'Host talon-kali' already present"
else
  warn "ssh config has no 'Host talon-kali' block — add one like:"
  cat <<EOT

Host talon-kali
    HostName <kali-ip-or-host>
    Port 2222
    User kali
    IdentityFile $SSH_KEY
    StrictHostKeyChecking accept-new

EOT
fi

# 4. MCP sample
if [[ ! -f "$MCP_SAMPLE" ]]; then
  cat > "$MCP_SAMPLE" <<'JSON'
{
  "mcpServers": {
    "kali-ssh": {
      "command": "npx",
      "args": ["-y", "@yourorg/kali-ssh-mcp"],
      "env": {
        "SSH_HOST_ALIAS": "talon-kali",
        "SSH_DEFAULT_CWD": "/tmp/lethani"
      }
    }
  }
}
JSON
  say "wrote MCP sample to $MCP_SAMPLE — merge into your real Claude Code MCP config"
else
  say "MCP sample already exists at $MCP_SAMPLE"
fi

# 5. probe
if ssh -o BatchMode=yes -o ConnectTimeout=5 talon-kali "uname -a" >/dev/null 2>&1; then
  say "ssh talon-kali OK"
  ssh talon-kali "uname -a" | sed 's/^/[lethani:host]   /'
else
  warn "ssh talon-kali failed — fix the Host block + key, then re-run this script"
fi

say "done. next: copy + run setup-kali.sh on Kali:"
echo "  scp $LETHANI_ROOT/00_infra/scripts/setup-kali.sh talon-kali:/tmp/"
echo "  ssh talon-kali \"bash /tmp/setup-kali.sh\""

# 6. opt-in: automated updates
echo
if [[ -t 0 ]]; then
  read -r -p "[lethani:host] Set up automatic lethani updates? (n = manual only)
  1) Weekly  — Mondays 09:00 local  (recommended for active users)
  2) Daily   — every day 09:00 local
  3) On Claude launch — background update each time you start Claude here
  4) No, I'll update manually with update.sh
  > " choice
  case "$choice" in
    1) "$LETHANI_ROOT/00_infra/scripts/setup-auto-update.sh" weekly ;;
    2) "$LETHANI_ROOT/00_infra/scripts/setup-auto-update.sh" daily ;;
    3) "$LETHANI_ROOT/00_infra/scripts/setup-auto-update.sh" on-claude ;;
    *) say "skipped. you can change your mind later: ./00_infra/scripts/setup-auto-update.sh" ;;
  esac
else
  say "non-interactive shell — skipping auto-update prompt."
  say "set it later: ./00_infra/scripts/setup-auto-update.sh"
fi
