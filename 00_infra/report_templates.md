# Report Templates

## Playbook Output Format (used by every playbook step)

```
PLAYBOOK : [name]
TARGET   : [asset/URL/domain]
─────────────────────────────────────────────────────
STEP N   : [step name]
STATUS   : [DONE / SKIP / BLOCKED / N/A]
RESULT   : [finding or output]
─────────────────────────────────────────────────────
FINDINGS SUMMARY
  [CRITICAL] ...
  [HIGH]     ...
  [MEDIUM]   ...
  [LOW]      ...
  [INFO]     ...
─────────────────────────────────────────────────────
CHAINS IDENTIFIED
  [vuln A] + [vuln B] → [combined impact]
─────────────────────────────────────────────────────
NEXT STEPS
  1. ...
  2. ...
```

---

## Full Pentest Report (per engagement)

```
========================================================================
         PENTEST REPORT — [target]
         Date   : [date]
         Tester : [redacted]
         Scope  : [scope description]
========================================================================

EXECUTIVE SUMMARY
  [2-3 paragraphs for non-technical stakeholders]

TARGET INFORMATION
  [domain, IP, tech stack, TLS, purpose]

FINDINGS (ordered by severity)
  [FINDING #N] [SEVERITY] — [title]
  ─────────────────────────────────────────────────────
  ENDPOINT      : [URL]
  DESCRIPTION   : [what was found]
  POC           : [reproduction steps / curl commands]
  IMPACT        : [what an attacker can do]
  CVSS          : [score and vector]
  REMEDIATION   : [specific fix steps]

POSITIVE FINDINGS
  [+] [security controls that are working correctly]

PRIORITY MATRIX
  IMMEDIATE  : [critical items]
  SHORT TERM : [1-2 week items]
  MEDIUM TERM: [1 month items]

OVERALL ASSESSMENT
  [holistic security evaluation]

NOTES
  [scope limitations, things not tested, methodology notes]
========================================================================
```

---

## Bug Bounty Submission Format

```
TITLE
  [Vuln Type] in [endpoint/feature] allows [attacker action]

SUMMARY
  [2-3 sentences: what, where, why it matters]

STEPS TO REPRODUCE
  1. [exact URL/method/role/cookie]
  2. ...
  N. ...

IMPACT
  [Concrete attack scenario. "An attacker could..." with real data.]

SUPPORTING MATERIAL
  - curl commands (in code blocks)
  - HTTP request/response pairs
  - Screenshot/video (if needed)

REMEDIATION (optional)
  [Specific fix, not generic advice]
```

**Pre-submit checklist:**
- [ ] Can the steps be reproduced using only what's written?
- [ ] Is the impact proven, not just claimed?
- [ ] Did you check the program's hacktivity for duplicates?
- [ ] Is the target in-scope? Did you read exclusions?
- [ ] Are HTTP requests inside code blocks?
- [ ] Did you use the program-required email/header?
