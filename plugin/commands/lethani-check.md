---
description: Check for new lethani releases and remind about Learning Mode cadence
---

Health check + freshness report for the lethani installation.

Steps:

1. **Plugin version** — read `.claude-plugin/plugin.json` `version` field
   (relative to the plugin's install location, not the user's CWD).
2. **Latest release** — fetch via `gh api repos/onurogut/lethani/releases/latest --jq '.tag_name'`.
   - If `gh` is not available, fall back to `curl -sf https://api.github.com/repos/onurogut/lethani/releases/latest`.
3. **Compare** — strip leading `v` from both, compare as semver strings:
   - Equal → "up to date".
   - Local older → "newer release available: vX.Y.Z" + give the update path.
4. **Last Learning Mode run** — read the most recent line of
   `00_infra/_changelog.md`. Compute days since last entry.
   - 0–7 days: fine.
   - 8–30 days: suggest `/learn` or `/learn-fetch`.
   - >30 days: stronger nudge plus `/learn-fetch` recommendation.
5. **Pending patches** — count `STATUS: pending` lines in
   `00_infra/_pending_patches.md` (if file exists). If >0, suggest
   `/learn-pending`.

Output format:

```
LETHANI HEALTH — <YYYY-MM-DD>
─────────────────────────────────────────
plugin version  : v<X.Y.Z>
latest release  : v<X.Y.Z>  (<up to date | UPDATE AVAILABLE>)
last learning   : <YYYY-MM-DD>  (<N days ago>)
pending patches : <count>  (<status>)
─────────────────────────────────────────
RECOMMENDATIONS
  - <only if there is something to do; one line each>
```

Update paths (only print when relevant):

- Plugin mode:    `/plugin marketplace update lethani` then `/plugin install lethani@lethani`
- Workspace mode: `cd ~/lethani && ./plugin/00_infra/scripts/update.sh`

Do not run any updates from this command. It is read-only.
