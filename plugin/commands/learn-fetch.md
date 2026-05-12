---
description: Learning Mode — fetch + filter only. Stage proposed playbook patches without applying.
argument-hint: [category-or-empty]
---

Run Learning Mode in **fetch-only** mode per `00_infra/learning_mode.md`.

The full `/learn` command does fetch + filter + propose + apply (interactive).
This command does only fetch + filter + propose, then **writes the proposed
patches to `00_infra/_pending_patches.md`** without applying anything.

Use this when:
- a cron job kicks off Learning Mode unattended
- you want to review patches in your own time before approving
- you want to see what's available without committing to apply

Workflow (per `learning_mode.md` §2, stop at step 6):

1. Scope the run (category, cadence, time bound).
   - If `$1` is empty: weekly cadence, last 14 days, max 10 sources.
   - If `$1` is a vuln class: restrict to that category.
   - If invoked non-interactively (cron): default to weekly, last 14 days,
     all categories, max 10 sources, no questions asked.
2. Pick sources from `learning_sources.md`.
3. Fetch via WebFetch (or `gh api` for GitHub sources).
4. Apply the hard quality bar — PoC required, not duplicated, generalizable,
   actionable, recent.
5. Diff against existing playbooks.
6. **Stop. Do NOT propose interactively. Do NOT apply.**

Instead, append to `00_infra/_pending_patches.md` (create if missing) using
this exact block per surviving novel technique:

```
─────────────────────────────────────────────────────────
PATCH #<N>                              STAGED: <YYYY-MM-DD>
SOURCE       : <full URL>
PUBLISHED    : <YYYY-MM-DD>
VULN CLASS   : <e.g. SSRF, prototype pollution, OAuth>
DELTA TYPE   : <NEW_BYPASS | NEW_CHAIN | NEW_PRIMITIVE | NEW_DETECTION | TOOL_UPDATE | CVE_PATTERN>

TECHNIQUE SUMMARY (2 lines max)
  Line 1: what the technique does.
  Line 2: what makes it new vs. current playbook coverage.

TARGET PLAYBOOK : <relative path>
TARGET SECTION  : <heading text or "NEW SECTION: <name>">
INSERT MODE     : <APPEND | REPLACE_LINES <start>-<end> | NEW_SUBSECTION_AFTER "<heading>">

PROPOSED TEXT BLOCK
```text
<exact markdown to insert>
```

STATUS       : pending
NOTES        : <optional>
─────────────────────────────────────────────────────────
```

Patch numbers are monotonically increasing across the file's lifetime.
Renumber from 1 every time the operator clears the file (after applying).

Final output to the conversation: a one-paragraph summary:
- N sources tried, M failed
- K items fetched, J passed the quality bar
- P new patches staged in `_pending_patches.md`
- Suggested follow-up: `/learn-pending` to review and apply

Do NOT print the patches inline — the operator reads them from the file.
