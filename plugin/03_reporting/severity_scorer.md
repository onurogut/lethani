# Playbook: Severity Scorer (Bug Bounty Oriented)

## Purpose
Score a finding's severity in terms bug bounty platforms actually reward,
not raw CVSS. Factors in real-world exploitability, business impact,
program-specific context, and payout precedent.
Input: finding description + target context.

---

## Step 1 — Gather Context

Before scoring, answer these:

```
1. What does the target company do? (fintech, healthcare, e-commerce, SaaS...)
2. What type of data is exposed/affected? (PII, financial, auth credentials, internal...)
3. Is authentication required to exploit? (none / low-priv user / admin only)
4. Does exploit require victim interaction? (self-triggered / needs victim click)
5. How many users are affected? (one / many / all)
6. Is the asset in scope? (main app / subdomain / third-party)
7. What platform? (HackerOne / Bugcrowd / Intigriti / private)
```

---

## Step 2 — Base Severity Classification

### Critical (P1)
Requirements: all of the following
- No authentication OR low-privilege authentication
- No victim interaction required (self-exploitable)
- High impact to data confidentiality, integrity, OR availability
- Affects large number of users or core functionality

Examples:
- RCE on production server
- SQLi with data extraction (users table, PII, credentials)
- SSRF reaching AWS metadata → credential exposure
- Authentication bypass → admin access
- Account takeover without victim interaction
- Stored XSS on admin panel or high-traffic page with auto-execution

### High (P2)
One of:
- Critical conditions but requires some user interaction
- Significant data exposure (PII, financial) requiring low-priv auth
- IDOR exposing sensitive data of other users at scale
- Authentication bypass (partial or requiring some bruteforce)
- Stored XSS on authenticated pages with session hijack potential

Examples:
- IDOR on /api/orders/{id} exposing full order history + PII
- Stored XSS in user profile viewed by admins
- Password reset with predictable token
- Broken access control → access other users' data
- Subdomain takeover on meaningful subdomain

### Medium (P3)
- Requires multiple conditions to exploit
- Limited data exposure (no PII, no credentials)
- Self-XSS (only affects own account)
- Reflected XSS with complex exploitation path
- CSRF on non-sensitive actions
- Information disclosure (version numbers, stack traces, paths)
- Low-severity IDOR (non-sensitive data)

### Low / Informational (P4/P5)
- No direct security impact
- Requires unlikely conditions
- Missing security headers (unless exploitable)
- SPF/DMARC/DKIM misconfig without demonstrated exploit
- Rate limiting issues on non-sensitive endpoints
- SSL/TLS minor issues

---

## Step 3 — Modifier Factors

Apply these to adjust the base classification:

### Severity Upgrades (+1 tier)
- Target is a financial institution, healthcare, or critical infrastructure
- Finding affects admin panel or core business functionality
- Data exposed includes credentials / auth tokens (direct account takeover)
- Finding is exploitable by unauthenticated users from internet
- Finding chains into a higher-severity issue
- Bug exists in a mobile app with millions of users

### Severity Downgrades (-1 tier)
- Requires attacker to already have admin access
- Only affects the attacker's own account
- Requires significant victim interaction (social engineering required)
- Asset is a subdomain with low traffic or low data sensitivity
- Finding is in a staging/dev environment
- Program has historically downgraded this type of issue (check Disclosure)
- Requires physical access or local network access
- Already behind multiple security layers

---

## Step 4 — Platform-Specific Notes

### HackerOne
- Uses their own severity scale (Critical/High/Medium/Low/None)
- CVSS score is displayed but triage team overrides based on context
- Signal/Noise ratio matters — don't over-inflate or you'll lose reputation
- Check the program's "Pentest-style" vs "Bug Bounty" distinction

### Bugcrowd
- Uses VRT (Vulnerability Rating Taxonomy) — match your finding to it
- P1-P5 scale, rewards often follow VRT baseline
- VRT URL: https://bugcrowd.com/vulnerability-rating-taxonomy

### Intigriti
- Similar P1-P5 but often more generous on context-adjusted ratings
- Impact-focused — document business impact clearly

---

## Step 5 — Score Output Template

```
FINDING       : [short title]
ASSET         : [URL/domain]
─────────────────────────────────────────────────
IMPACT
  Confidentiality : [None / Low / Medium / High]
  Integrity       : [None / Low / Medium / High]
  Availability    : [None / Low / Medium / High]
  Affected data   : [describe: PII / financial / credentials / none]
  Users affected  : [1 / many / all / unauthenticated]

EXPLOITABILITY
  Auth required   : [None / Low / High]
  User interaction: [None / Required]
  Attack vector   : [Network / Adjacent / Local]
  Complexity      : [Low / High]

BASE SEVERITY   : [Critical / High / Medium / Low]

MODIFIERS
  Upgrades        : [list if any]
  Downgrades      : [list if any]

FINAL SEVERITY  : [Critical / High / Medium / Low]
SUGGESTED PAYOUT: [$range based on program's page + comparable reports]

COMPARABLE REPORTS
  [HackerOne Disclosure URL of similar finding]
  [Bugcrowd Disclosure URL of similar finding]
─────────────────────────────────────────────────
RATIONALE
  [2-3 sentences explaining why this severity is correct,
   anticipating triage team's likely objections]
```

---

## Step 6 — Common Triage Objections & Responses

| Triage says | Your response |
|---|---|
| "Requires auth — downgrading to Medium" | "Any registered user can exploit this, registration is open/free — attack surface is all internet users" |
| "Limited to own account — Low" | "This IDOR exposes data of *other* users, not just the attacker's" |
| "We accept self-XSS" | "This XSS fires in context viewed by other users / admins" |
| "Informational — no real impact" | "Attacker can use this to [concrete next step] — chain described in report" |
| "Duplicate" | "Reference the similar report and explain what's different about yours" |
| "Out of scope" | "Asset is reachable from in-scope main domain via [path/link]" |
