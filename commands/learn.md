---
description: Learning Mode — ingest fresh research, propose playbook patches
argument-hint: [category-or-empty]
---

Enter Learning Mode per `00_infra/learning_mode.md`.

If `$1` is empty: run a weekly-cadence pass across all categories
(default: last 14 days, max 10 sources).

If `$1` is a vuln class (e.g. `ssrf`, `oauth`, `ssti`, `cache`, `graphql`):
restrict to sources tagged with that class in `00_infra/learning_sources.md`.

Workflow (per learning_mode.md §2):

1. Print the chosen source list.
2. Fetch via WebFetch (or `gh api` for GitHub sources).
3. Apply the hard quality bar — PoC required, not duplicated, generalizable,
   actionable, recent.
4. Diff against existing playbooks.
5. Present numbered patches in the strict diff format from learning_mode §3.
6. Wait for `apply N,M,P` / `apply all` / `skip` from the operator.
7. On approval: Edit playbooks + append entries to `00_infra/_changelog.md`.
8. Verify and emit the run summary block (learning_mode.md §7).

Authorization for the playbook edits IS still required from the operator —
this is to keep playbook quality high, not because lethani lacks scope. The
operator confirms specific patches; they do not need to re-confirm that
Learning Mode itself is allowed to run.
