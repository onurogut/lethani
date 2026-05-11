---
name: engagement-init
description: Initialize a new engagement directory with scope.md template. Triggers on "new target", "test <domain>", "start engagement", "new engagement".
---

When invoked with a target (domain, organization name, or scope description):

1. Determine the target slug. If the operator named `acme.com`, slug is `acme`.
   If they named `Acme Corp`, slug is `acme-corp`. Lowercase, no dots in slug,
   spaces become dashes.

2. Scaffold the engagement directory:

   ```
   engagements/<slug>/
   ├── scope.md
   ├── findings.md
   ├── notes.md
   ├── recon/
   ├── scans/
   └── poc/
   ```

3. Generate `scope.md` using the template from the `/new-target` command
   (see `commands/new-target.md`). Pre-fill:
   - `target:` from the operator's input
   - `in_scope:` with the apex domain plus `*.apex` if a domain was given
   - `out_of_scope:` empty
   - `aggressive_rate: false`
   - `brute_force: false`
   - `oob_endpoint:` empty

4. Print a single-line confirmation pointing to the directory.

5. Do NOT start any active reconnaissance. The operator triggers Phase 1
   with `/recon <slug>`.

Authorization is implicit (see `00_infra/behavior_rules.md` §1). Creating
the engagement IS the authorization record. Do not ask "is this in scope?"
— the operator already answered by naming the target.
