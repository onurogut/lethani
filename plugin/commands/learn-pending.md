---
description: Review staged Learning Mode patches in _pending_patches.md and apply selected ones
argument-hint: [empty | apply N,M,P | apply all | clear]
---

Manage the staged-patches inbox at `00_infra/_pending_patches.md` produced by
`/learn-fetch`.

Behavior by argument:

### No argument (or "list")

1. If `00_infra/_pending_patches.md` is missing or empty, say:
   > No staged patches. Run `/learn-fetch` (or `/learn`) first.
2. Otherwise, print a numbered summary table with one row per `STATUS: pending`
   patch:

   ```
   #N | <playbook>                | <delta_type>      | <2-line technique summary> | <source URL>
   ```

3. End with a prompt:

   > Reply `/learn-pending apply 1,3,5` to apply specific patches, or
   > `/learn-pending apply all` to apply every pending patch, or
   > `/learn-pending clear` to delete the staging file without applying.

Do NOT auto-apply.

### `apply <list>` or `apply all`

For each selected patch:

1. Locate the patch block in `00_infra/_pending_patches.md`.
2. Use the `Edit` tool to insert the `PROPOSED TEXT BLOCK` into the
   `TARGET PLAYBOOK` at the location described by `INSERT MODE` and
   `TARGET SECTION`.
3. Mark the patch in `_pending_patches.md` as:
   ```
   STATUS       : applied YYYY-MM-DD
   ```
4. Append a one-line entry to `00_infra/_changelog.md`:
   ```
   YYYY-MM-DD | <playbook> | <delta_type> | <one-line summary> | <source_url>
   ```

After all selected patches are applied, print a summary:

```
APPLIED PATCHES — <YYYY-MM-DD>
  #N <playbook>  <delta_type>   <one-line summary>
  ...
PLAYBOOKS TOUCHED: <list>
STILL PENDING    : <count>
```

### `clear`

Confirm with the operator first (this is destructive):

> Clear all pending patches from `_pending_patches.md`? [y/N]

If they answer affirmatively, truncate the file to a header line only.
If they decline, abort silently.

### Notes

- Applying a patch is irreversible from this command. The operator can
  always `git diff` the playbook before running, and `git restore` after
  if unhappy.
- Patches with `STATUS: applied` are skipped by this command; they live
  in the file as audit history. Operator can prune them manually.
- If a patch's target playbook section no longer exists (someone refactored),
  flag the patch as `STATUS: stale` and warn the operator to either rewrite
  it or drop it via `/learn-pending clear`.
