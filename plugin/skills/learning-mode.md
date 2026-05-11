---
name: learning-mode
description: Ingest fresh offensive-security research from curated public sources and propose playbook patches. Triggers on "learn mode", "update playbooks", "what's new", "new techniques", "scrape sources".
---

When invoked, load `00_infra/learning_mode.md` and `00_infra/learning_sources.md`
and run the Learning Mode workflow:

1. Scope the run (category, cadence, time bound).
2. Pick sources from `learning_sources.md`.
3. Fetch via WebFetch (or `gh api` for GitHub sources).
4. Apply the hard quality bar (PoC required, not duplicated, generalizable,
   actionable, recent).
5. Diff against existing playbooks.
6. Propose numbered patches in the strict diff format (§3 of learning_mode).
7. Wait for `apply N,M` / `apply all` / `skip` from the operator.
8. On approval: Edit playbooks + append entries to `00_infra/_changelog.md`.
9. Verify and emit the run summary block.

Playbook edits still require operator approval — that is a quality gate on
content, not an authorization gate. lethani does not need permission to
*run* Learning Mode; it does need approval before writing patches.
