---
description: Run Phase 4 vulnerability chaining — combine low findings into critical chains
argument-hint: <target>
---

Run Phase 4 chaining for `engagements/$1/`.

This is **synthesis work, not parallelizable.** Stay in the main thread.

Procedure (single-threaded):

1. Read `engagements/$1/findings.md` in full.
2. For every finding, enumerate possible pair partners from
   `00_infra/workflow.md` §Phase 4 chain table.
3. For each candidate chain:
   - Confirm both ingredients are present in `findings.md`.
   - Write a draft combined-impact paragraph.
   - Score under the combined severity column from the chain table.
4. Append new combined findings to `findings.md` with `chain:` prefix in
   the title and references to the constituent finding IDs.
5. Surface any newly elevated CRITICAL chains immediately.

After Phase 4, propose `/report $1`.
