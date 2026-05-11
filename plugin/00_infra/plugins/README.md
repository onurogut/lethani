# Drop-in Plugins

This directory is an extension point. Drop a markdown file here following
the template below and lethani will:

1. Route trigger phrases to your plugin via the slash router in CLAUDE.md.
2. Load your plugin file on demand (not at session start) to stay inside the
   context budget.
3. List your plugin under `/status --plugins`.

This is intentionally lighter than the formal `commands/` + `agents/` +
`skills/` plugin layout under `.claude-plugin/` — drop-in plugins are for
**adding a new vuln class or technique** without restructuring the
workspace.

---

## When to write a drop-in plugin vs. a real playbook

Use a drop-in plugin (this directory) when:

- The technique is **emerging** and you are not yet sure it deserves a full
  playbook slot.
- It is a **niche** vuln class (e.g. WebTransport, QUIC-only smuggling)
  that only one engagement in twenty hits.
- You want to **prototype** before merging into `02_vuln_testing/`.

Use a full playbook (`02_vuln_testing/<name>.md`) when:

- The technique is established and has its own widely-cited corpus.
- You want it to be reachable from the main slash routing table in
  CLAUDE.md (Phase 3 priority list).
- You want a slot in `00_infra/tech_attack_matrix.md`.

A drop-in plugin **graduates** to a full playbook by being moved to its
phase directory and added to CLAUDE.md routing + `00_infra/workflow.md`.

---

## Template

Save the file as `00_infra/plugins/<kebab-case-name>.md`.

```markdown
---
name: <kebab-case-name>
description: <one sentence — what this plugin tests and when to load it>
triggers:
  - <trigger phrase 1>
  - <trigger phrase 2>
phase: <0|1|2|3|4|5>        # which phase this plugin slots into
playbook_kind: <recon|vuln|automation|osint|reporting>
status: <experimental|beta|stable>
---

# <Plugin Name>

One-paragraph description.

## When to load

Concrete triggers. Tech-stack overlap. Endpoint patterns.

## Procedure

Numbered steps, exactly like a playbook. Same template as
`CONTRIBUTING.md`'s playbook section:

1. Step
2. Step
3. Step

## Evidence to capture

What goes into the finding record.

## False positives

What looks like a hit but isn't.

## References

3–5 links.
```

---

## Example: a minimal experimental plugin

```markdown
---
name: webtransport-smuggling
description: Detect HTTP-to-WebTransport request smuggling in dual-stack endpoints
triggers:
  - webtransport
  - quic smuggling
  - h3 smuggling
phase: 3
playbook_kind: vuln
status: experimental
---

# WebTransport Smuggling

Some servers terminate HTTP/3 and HTTP/1.1 on separate stacks behind the
same domain. If they normalize requests differently, smuggling between
the two stacks is possible.

## When to load

- Target advertises `alt-svc: h3=":443"` AND HTTP/1.1 on the same host.
- CDN known to terminate H3 (Cloudflare, Fastly with recent config).

## Procedure

1. Probe both stacks: `curl --http3` and `curl --http1.1`.
   Compare response normalization (header casing, transfer-encoding).
2. ...

(snip)
```

---

## How CLAUDE.md picks up new plugins

CLAUDE.md does not statically list drop-in plugins (it would bloat the
context). Instead, the routing rule is:

> If the user message contains a phrase that does NOT match the main slash
> routing table, glob `00_infra/plugins/*.md` and `grep` the `triggers:`
> front-matter. Load the matching plugin file.

This keeps the context budget under control: plugins live on disk until a
trigger phrase pulls them in.

---

## Conventions

- One plugin per file. No multi-vuln plugins.
- Plugin names are unique across `commands/`, `agents/`, `skills/`,
  `00_infra/plugins/`, and phase directories.
- Plugins use `[redacted]` for any contributor identity (same rule as
  playbooks).
- Plugins under `status: experimental` may be removed without notice when
  proven unreliable.
