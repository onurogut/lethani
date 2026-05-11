# Contributing to lethani

This project lives or dies by the quality of its playbooks. The single rule
that matters: **every playbook is a reproducible procedure.** If someone
reading it in three months cannot run it against a target and get the same
class of output, the playbook is broken and should not be merged.

---

## What lethani accepts

- New playbooks for a vuln class or recon technique not yet covered.
- Refinements to existing playbooks: new payloads, new bypasses, new tool
  flags, new platform-specific notes.
- Bug fixes in scripts (`00_infra/scripts/`, `bin/lethani`).
- Documentation: README, SETUP.md, examples, CONTRIBUTING.md itself.
- Sub-agent definitions and slash commands.

## What lethani does **not** accept

- "Interesting reads" added to playbooks without a procedure attached. If
  the technique is novel and demonstrated, run it through Learning Mode
  (`00_infra/learning_mode.md`) — that path enforces the quality bar.
- Tooling that requires a paid license unless there is a free fallback.
- Playbooks that target a specific vendor's product without generalization
  (exception: very widely-deployed products — top 50 SaaS, top 10 CDN, top
  10 IdP).
- Personally-identifying information of any kind. The repo uses
  `Tester : [redacted]` for a reason; keep it that way.
- Changes that re-introduce per-call "are you sure?" prompts. lethani is a
  tool; the operator approved when they invoked it (see
  `00_infra/behavior_rules.md` §1).

---

## Playbook template

Place new playbooks in the phase directory that matches their stage:

- Reconnaissance → `01_recon/`
- Manual vulnerability testing → `02_vuln_testing/`
- Reporting → `03_reporting/`
- Automation → `04_automation/`
- OSINT → `05_osint/`

Filename: `lower_snake_case.md`. Avoid abbreviations unless they are the
common term (`xss`, `ssrf`, `oauth`, `jwt`).

### Required sections (in order)

```markdown
# <Playbook Name>

One-paragraph description: what this playbook tests, in plain English.
Include the one sentence that tells a reader whether to load it for this
target.

---

## When to run

- Concrete triggers (e.g. "any endpoint that accepts a URL parameter").
- Tech-stack overlap (link to `00_infra/tech_attack_matrix.md` if appropriate).

## Procedure

Numbered steps. Each step is testable on its own. For each step:

1. What to send (exact payload or curl command in a code block).
2. What to look for in the response.
3. Pass / Fail / N-A criteria.

## Bypasses and variants

If applicable: encoding tricks, parser quirks, filter evasions. One line
per variant + a code block with a sample payload.

## Evidence to capture

The exact files / screenshots / log lines a finding from this playbook
must include for the report writer to compose a submission.

## False positives

Common reasons this playbook produces apparent findings that are not real.
Cuts triage time later.

## References

Links to original research, CVE numbers, public writeups. Keep to 3–5.
```

### Don't

- Don't write multi-paragraph narrative. Playbooks are procedures, not
  essays.
- Don't include "best practice" advice for the defender. That belongs in
  the report's remediation section (`00_infra/report_templates.md`), not
  the playbook.
- Don't paste entire blog posts. Extract the testable nugget and link the
  source.
- Don't use emojis in playbook files. Plain text only.

---

## Sub-agent contributions (`agents/`)

A sub-agent is a focused, single-deliverable worker. Front-matter format:

```markdown
---
name: <kebab-case-name>
description: <one sentence; triggers when this agent should be dispatched>
tools: <comma-separated tool whitelist, no spaces — Bash, Read, Write, WebFetch>
---

Body: numbered procedure, output paths, constraints, "report back" budget.
```

Rules:

- Sub-agents return a < 200-word summary plus a list of files they wrote.
- Findings go into `engagements/<target>/findings*.md`, not the summary.
- Sub-agents do **not** call other sub-agents (no recursion).
- One sub-agent owns one phase bucket. If you find yourself wanting two
  sub-agents for "the same thing", merge them; if you want one sub-agent
  to do "two things", split them.

---

## Slash command contributions (`commands/`)

Front-matter:

```markdown
---
description: <one sentence shown in the / picker>
argument-hint: <example argument shape>
---

Body: what the command does, prerequisites, what it dispatches.
```

Rules:

- Commands compose phases or single playbooks; they do not duplicate
  playbook content.
- A command may invoke `/<other-command>` only at end-of-phase as a
  suggestion to the operator — never auto-chain phases.

---

## Skill contributions (`skills/`)

Skills are loaded when their trigger phrases match. Front-matter:

```markdown
---
name: <kebab-case-name>
description: <when to use this skill; list trigger phrases>
---

Body: the procedure the skill follows when invoked.
```

Skills are *behaviour overlays*, not commands. If you want the operator to
type `/foo`, write a command. If you want the agent to switch into a mode
when the operator says "do X", write a skill.

---

## Pull request checklist

Before opening a PR, run through this:

- [ ] Playbook follows the template above.
- [ ] Procedure is reproducible — at least one step has a concrete payload
      or command in a code block.
- [ ] No emojis added to playbook files.
- [ ] No PII, no real credentials, no real target names (use `example.com`
      or `acme.example` as the placeholder).
- [ ] References cited (no orphan techniques).
- [ ] If a new sub-agent / command / skill: front-matter is valid and the
      name is unique across the workspace.
- [ ] Markdown lints cleanly (`npx markdownlint-cli2 "**/*.md"`).
- [ ] CLAUDE.md and `00_infra/workflow.md` updated if the playbook should
      be added to a phase routing table.

---

## Reporting security issues in lethani itself

See [SECURITY.md](SECURITY.md).
