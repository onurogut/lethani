# Security Policy

## Reporting a vulnerability in lethani

lethani is itself a security tool, which is supposed to be ironic and isn't.

If you find a vulnerability in lethani — in the playbooks (e.g. a payload
that ships with a backdoor), in the helper scripts (`00_infra/scripts/*.sh`,
`bin/lethani`), in the plugin commands/agents/skills, or in any of the
generated artifacts — please tell us before disclosing publicly.

### How to report

Preferred: open a [private security advisory](https://github.com/onurogut/lethani/security/advisories/new)
on the GitHub repository. This is the standard GitHub flow for embargoed
vulnerability disclosure and gives us a private space to triage.

Alternative: email the maintainer listed in `.claude-plugin/plugin.json`
homepage profile. Use the maintainer's listed contact, not a guess at their
identity.

### What to include

- A description of the vulnerability and its impact.
- Reproduction steps — exact files, exact commands, exact versions.
- The lethani commit hash or version (`.claude-plugin/plugin.json` `version`
  field).
- Your suggested fix, if you have one.
- Whether you want public credit and under what name.

### What we will do

- Acknowledge receipt within **72 hours**.
- Triage within **7 days** (severity + scope of impact).
- Coordinate a fix with you on the private advisory thread.
- Issue a patch release and public CVE (if applicable) once a fix is
  available.
- Credit you in the release notes and the `_changelog.md` entry unless you
  ask us not to.

### Scope

In scope:

- Anything in the lethani repository (playbooks, scripts, plugin metadata,
  docs).
- Helper scripts that ship in this repo and run on the host or on Kali.
- The setup helpers (`setup-host.sh`, `setup-kali.sh`).

Out of scope:

- Vulnerabilities in third-party tools that lethani invokes (subfinder,
  nuclei, ffuf, etc.) — report those upstream to ProjectDiscovery, etc.
- Vulnerabilities in Claude Code, the kali-ssh MCP server, or the Anthropic
  API — report those to Anthropic directly.
- Findings that lethani produced *against your test target* — those are
  bug bounty submissions for that target's program, not for lethani.

### Hall of fame

Researchers who report valid vulnerabilities and choose to be credited will
be listed here:

- *(none yet — be the first)*

---

## Authorization model reminder (for users, not researchers)

lethani is designed for **authorized security testing only**. The operator
is responsible for verifying that the target is in scope before invoking
lethani. The tool treats invocation as authorization (see
`00_infra/behavior_rules.md` §1); it does not verify legality on your
behalf.

If you are unsure whether you have authorization, do not run lethani.
