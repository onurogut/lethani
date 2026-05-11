# Playbook: Program Rules Parser

## Purpose
Extract and structure the key rules, scope definitions, and constraints from
a bug bounty program's policy page. Prevents OOS submissions and wasted effort.
Input: program URL or pasted policy text.

---

## Step 1 — Fetch the Program Page

```bash
PROGRAM_URL="https://hackerone.com/programs/TARGET"

# Fetch the policy page
curl -sk "$PROGRAM_URL" | python3 -m html.parser 2>/dev/null

# Or for Bugcrowd
curl -sk "https://bugcrowd.com/TARGET" | grep -A 500 "scope"
```

---

## Step 2 — Extract and Structure These Fields

Read the program page and populate every field below.
If a field is not explicitly stated, mark as `NOT SPECIFIED`.

---

### Program Identity

```
Program name    :
Platform        : HackerOne / Bugcrowd / Intigriti / Private / Other
Program type    : Public / Private / Invite-only
Launch date     :
Response SLA    : First response [X days] / Triage [X days] / Resolution [X days]
Hall of Fame    : Yes / No / URL
```

---

### Scope — In Scope

List all explicitly in-scope assets:

```
ASSET TYPE      | ASSET                        | NOTES
─────────────────────────────────────────────────────────
Web application | https://app.target.com        |
API             | https://api.target.com        |
Subdomain wildcard | *.target.com              | Excludes staging.*
Mobile (iOS)    | com.target.app                | App Store ID: XXXXX
Mobile (Android)| com.target.android            |
Source code     | github.com/target/repo        |
```

---

### Scope — Out of Scope

Critical section. Test nothing on this list.

```
ASSET / BEHAVIOR                          | REASON GIVEN
──────────────────────────────────────────────────────────
*.staging.target.com                      |
Third-party services (Zendesk, Salesforce)|
Social engineering                        |
Physical attacks                          |
DoS / DDoS                                |
Spam / phishing                           |
Rate limiting without demonstrated impact |
Self-XSS                                  |
Missing security headers (standalone)     |
SSL/TLS issues without impact             |
```

---

### Bounty Table

```
SEVERITY     | PAYOUT RANGE    | NOTES
─────────────────────────────────────────────
Critical     | $X,000 – $X,000 |
High         | $X,000 – $X,000 |
Medium       | $XXX – $X,000   |
Low          | $XX – $XXX      |
Informational| $0              | No reward
```

---

### Special Rules

Extract any program-specific rules that differ from standard:

```
[ ] Safe harbor explicitly stated: Yes / No
[ ] Coordinated disclosure policy: X days embargo
[ ] Account creation allowed for testing: Yes / No
[ ] Automated scanning allowed: Yes / No / Limited
[ ] Social engineering testing allowed: Yes / No
[ ] Requires written permission for network testing: Yes / No
[ ] Chain exploits policy (are chains rewarded separately?):
[ ] Maximum severity cap for certain asset types:
[ ] Previous finding grace period (recently fixed → still eligible?):
[ ] Eligible countries (some programs exclude certain countries):
```

---

### Vulnerability Categories — Special Notes

```
CATEGORY          | IN SCOPE | NOTES / CONDITIONS
──────────────────────────────────────────────────
SQLi              |          |
XSS               |          | Stored only? Reflected too?
IDOR              |          |
SSRF              |          | Internal network / cloud metadata?
RCE               |          |
Auth bypass       |          |
File upload        |          |
CSRF              |          | Requires impact?
Open redirect     |          | Standalone or only if chained?
Clickjacking      |          | Requires demo?
XXE               |          |
Subdomain takeover|          |
Business logic    |          |
2FA bypass        |          |
Account takeover  |          |
```

---

### Testing Constraints

```
[ ] Do NOT test with real user data
[ ] Use only your own test accounts
[ ] Do NOT access data beyond proof of vulnerability
[ ] Do NOT modify or delete data
[ ] Do NOT exfiltrate more than 1 record to prove IDOR
[ ] Stop testing if you access production data unexpectedly
[ ] Report any unintended access immediately
[ ] Maximum request rate per second: NOT SPECIFIED / [X req/s]
```

---

### Pre-Testing Checklist

Before starting any testing on this program:

```
[ ] Read full policy page — not just the scope table
[ ] Confirmed target URL/app is on in-scope list
[ ] Checked if test accounts must be created via special process
[ ] Noted any previous reports visible on public hacktivity
[ ] Set up safe testing environment (no production credentials)
[ ] Noted program's average response time and queue length
[ ] Bookmarked program's VDP / changelog page for fixed issues
[ ] Confirmed payout ranges match effort vs expected finding type
```

---

## Step 3 — Output Summary

```
PROGRAM       : target.com on HackerOne
TYPE          : Public, launched 2021
─────────────────────────────────────────
IN SCOPE      : app.target.com, api.target.com, *.target.com (excl staging)
                iOS app (com.target.ios), Android app (com.target.android)

OUT OF SCOPE  : staging.*, third-party integrations, DoS, rate limits,
                self-XSS, missing headers, social engineering

BOUNTIES      : Critical $5k-$15k / High $1k-$5k / Medium $250-$1k / Low $50-$250

SPECIAL RULES :
  - Automated scanning allowed with rate limit (max 10 req/s)
  - No test accounts needed (register freely)
  - Chains rewarded as single finding at highest severity
  - 90-day disclosure embargo

RED FLAGS     :
  ⚠ No safe harbor explicitly stated — proceed carefully
  ⚠ "No impact, no bounty" policy — document impact thoroughly

RECOMMENDED   : Focus on api.target.com (API surface, higher bounties)
  STARTING      Start with 01_recon → httpx_triage → js_endpoint_extractor
  POINT         Then test IDOR on API endpoints (high payout, common finding)
```
