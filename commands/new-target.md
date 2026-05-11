---
description: Scaffold an engagement directory for a new target with scope.md template
argument-hint: <domain-or-target>
---

Create a new engagement under `engagements/$1/` with this exact layout:

```
engagements/$1/
├── scope.md
├── findings.md
├── notes.md
├── recon/
├── scans/
└── poc/
```

The `scope.md` file is generated with the following content (replace `<target>`
with the argument):

```markdown
# Scope — <target>

target          : <target>
created         : <YYYY-MM-DD>
in_scope        :
  - <target>
  - "*.<target>"
out_of_scope    : []
program         : (bug bounty platform / contract / internal — fill if known)

aggressive_rate : false       # set true to allow nuclei/naabu high-rate profile
brute_force     : false       # set true to allow hydra/crackmapexec
oob_endpoint    :             # filled in by oob.sh on first OOB-requiring test

notes           : |
  (assumptions, special instructions, excluded vuln types, mandatory headers)
```

After scaffolding, print a one-line confirmation:

> Engagement scaffolded: engagements/$1/ — scope.md ready, edit if needed.

Do not start any recon. The operator triggers Phase 1 with `/recon $1`.

Authorization is implicit (see `00_infra/behavior_rules.md` §1). Do not ask
"is this in scope?" — the operator created the engagement; that is the
authorization record.
