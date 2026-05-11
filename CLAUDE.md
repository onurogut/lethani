# lethani — repo root

This directory is the **lethani repository**, not the workspace itself.
The orchestrator (CLAUDE.md router, playbooks, slash commands, sub-agents,
skills) lives under `plugin/`.

## Two ways to use lethani

### As a Claude Code plugin (recommended)

```
/plugin marketplace add onurogut/lethani
/plugin install lethani@lethani
```

After that, every Claude Code session has the slash commands available
(`/new-target`, `/recon`, `/scan`, …) regardless of which directory you
open Claude in.

### As a workspace (legacy)

```bash
cd plugin
claude
```

Inside `plugin/` you have the full router (`plugin/CLAUDE.md`) and all
playbooks. Engagements are written one level up under `../engagements/`
so they stay out of the plugin's own tree.

---

See `README.md` for the full project overview.
