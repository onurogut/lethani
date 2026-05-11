# Setup Guide

This document walks through getting lethani working end-to-end: host
prerequisites, Kali VM provisioning, kali-ssh MCP server wiring, and the
tool inventory that the playbooks expect.

For the impatient, two helper scripts:

```bash
# 1. host-side wiring (SSH config + MCP server)
plugin/00_infra/scripts/setup-host.sh

# 2. kali-side tool install (run after the host can reach Kali)
scp plugin/00_infra/scripts/setup-kali.sh talon-kali:/tmp/
ssh talon-kali "bash /tmp/setup-kali.sh"
```

Both scripts are idempotent — re-running them is safe.

---

## 1. Host prerequisites

- macOS 13+ or Linux (Ubuntu 22.04+ tested)
- [Claude Code](https://claude.com/claude-code) installed and logged in
- `ssh`, `scp`, `git`, `jq`, `curl` on `$PATH`
- A reachable Kali Linux VM (multipass, UTM, Parallels, VirtualBox, or
  Docker — anything that gives you SSH access works)

### SSH key

```bash
# only if you don't have one yet
ssh-keygen -t ed25519 -f ~/.ssh/talon_kali -N "" -C "lethani-kali"

# push it to Kali (assumes you can password-SSH once to bootstrap)
ssh-copy-id -i ~/.ssh/talon_kali.pub kali@<kali-ip-or-host>
```

### `~/.ssh/config`

Add a block like:

```sshconfig
Host talon-kali
    HostName <kali-ip-or-host>     # often localhost if you use a port-forwarded VM
    Port 2222                      # change to your Kali SSH port
    User kali
    IdentityFile ~/.ssh/talon_kali
    StrictHostKeyChecking accept-new
```

Test it:

```bash
ssh talon-kali "uname -a"
```

You should see Kali's `uname` output. If not, fix this before continuing —
lethani assumes `talon-kali` works without prompts.

### kali-ssh MCP server

`lethani` invokes Kali via the `kali-ssh` MCP server. Add the server to
Claude Code's MCP config — for Claude Code that means editing
`~/.claude.json` or running `claude mcp add`. Concrete entry (adjust the
`command`/`args` if your install of the server differs):

```json
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
```

If you already maintain a different MCP server name or transport, just
make sure these four tool names resolve to actions against your Kali VM:

- `mcp__kali-ssh__runRemoteCommand`
- `mcp__kali-ssh__runCommandBatch`
- `mcp__kali-ssh__checkConnectivity`
- `mcp__kali-ssh__uploadFile` / `mcp__kali-ssh__downloadFile`

The `setup-host.sh` helper writes a sample block to `~/.claude.json.lethani.example`
that you can merge into your real config.

---

## 2. Kali tool inventory

Run `setup-kali.sh` on the Kali VM. It will:

- `apt update && apt install` the package list in
  `00_infra/execution_environment.md` (nmap, masscan, ffuf, sqlmap, nikto, …
  plus build prerequisites)
- `go install` the ProjectDiscovery suite (subfinder, httpx, naabu, nuclei,
  interactsh-client, …) into `$HOME/go/bin`
- `pipx install` Python tools (theHarvester, arjun, paramspider)
- Download SecLists into `/usr/share/seclists/`
- Configure `nuclei -update-templates`
- Print a summary of installed binaries vs. expected inventory

After it finishes, verify with:

```bash
ssh talon-kali "which subfinder httpx nuclei ffuf sqlmap interactsh-client"
```

Every line should print a path.

---

## 3. First engagement

In Claude Code, inside the lethani workspace:

```
/new-target acme.com
/recon acme
```

lethani will:

1. Scaffold `engagements/acme/` with a `scope.md` template (Phase 0).
2. Fan out Phase 1 recon to 6 parallel sub-agents.
3. Drop findings into `engagements/acme/recon/` and a summary in
   `engagements/acme/recon/_summary.md`.

It will **not** ask "is this target in scope?" — authorization is implicit
once you create the engagement (see `00_infra/behavior_rules.md` §1).

---

## 4. Troubleshooting

| Symptom                                       | Fix                                                                  |
|-----------------------------------------------|----------------------------------------------------------------------|
| MCP shows "kali-ssh unavailable"              | `claude mcp list` → check the entry; `ssh talon-kali` must work first |
| `command not found: subfinder` on Kali        | `export PATH=$PATH:$HOME/go/bin` or call by absolute path             |
| `setup-kali.sh` fails on `go install`         | `export GOPROXY=direct` and re-run                                   |
| `interactsh-client` not registering domains   | check outbound DNS/HTTPS on Kali; firewall blocks `oast.live`?       |
| Slash commands missing in Claude Code         | Did you `cd ~/lethani` before `claude`? Or `/plugin install` the repo |
| Hooks not firing                              | `~/lethani/.claude/settings.json` exists?                            |

---

## 5. Updating

```bash
cd ~/lethani
git pull
# optionally re-run setup-kali.sh on the Kali side to pick up new tools
ssh talon-kali "bash /tmp/setup-kali.sh"
```

Tool inventory drift is tracked in `00_infra/execution_environment.md` —
update that file when you add or remove tools from Kali.
