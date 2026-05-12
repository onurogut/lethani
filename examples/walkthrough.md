# Walkthrough — Fictional Engagement, Phase 0 → 5

A fabricated, anonymized end-to-end engagement showing how lethani's
artifacts actually look on disk. The "target" `acme-saas.example` is not a
real domain; the IPs, finding IDs, and bounty references are invented for
illustration. Nothing here was run against a live system.

Use this as a reference for what each phase should produce.

---

## Phase 0 — Scope

Operator opens Claude Code in `~/lethani` and types:

```
/new-target acme-saas.example
```

lethani scaffolds `engagements/acme-saas/` and writes `scope.md`:

```markdown
# Scope — acme-saas.example

target          : acme-saas.example
created         : 2026-05-12
in_scope        :
  - acme-saas.example
  - "*.acme-saas.example"
out_of_scope    :
  - status.acme-saas.example
  - blog.acme-saas.example
program         : bug bounty (Acme on HackerOne, EU researchers, $50–$10k)

aggressive_rate : false
brute_force     : false
oob_endpoint    :

notes           : |
  - Mandatory header: X-HackerOne-Researcher: <handle>
  - Exclusions: rate-limit reports, SPF/DKIM, missing security headers without impact
  - Test from EU IP (program geo-restricted)
```

Operator edits notes/exclusions; saves; types `/recon acme-saas`.

---

## Phase 1 — Reconnaissance (fan-out to 6 sub-agents)

lethani dispatches six parallel sub-agents. Wall-clock: ~9 minutes. The
agentic run log appears in the conversation:

```
AGENTIC RUN — 2026-05-12 10:14
SCOPE         : phase 1 / acme-saas
SUB-AGENTS DISPATCHED:
  A recon-dns         status: done    findings: 1   output: recon/subdomains.txt, recon/takeover_candidates.txt
  B recon-http        status: done    findings: 2   output: recon/alive.txt, recon/tech.txt, recon/js_endpoints.txt
  C recon-params      status: done    findings: 0   output: recon/params.txt, recon/cicd_findings.md
  D osint-network     status: done    findings: 0   output: recon/asn.txt, recon/services.txt
  E osint-people      status: done    findings: 1   output: recon/emails.txt, recon/breach_check.txt
  F osint-source      status: done    findings: 1   output: recon/github_leaks.txt
TOTAL ELAPSED : 8m 52s
NEXT          : /scan acme-saas (proposed, not started)
```

Files dropped into the engagement:

```
engagements/acme-saas/recon/
├── subdomains.txt              (412 subdomains, sorted+unique)
├── alive.txt                   (218 alive HTTP services)
├── tech.txt                    (rollup: nginx/Cloudflare/Next.js/PostgreSQL/...)
├── takeover_candidates.txt     (1 candidate: campaign.acme-saas.example → unclaimed Heroku app)
├── vhosts.txt                  (3 unique vhosts on the same IP)
├── js_endpoints.txt            (1,847 endpoints mined from 92 JS bundles)
├── secrets.txt                 (candidates — 4 entries, manual triage required)
├── urls.txt                    (8,902 historical URLs)
├── params.txt                  (1,233 unique params, top: id, redirect_uri, account, token)
├── cicd_findings.md            (public GH Actions exposing CI logs — info)
├── asn.txt                     (AS14618 Amazon — 11 CIDRs)
├── services.txt                (Shodan rollup: nginx, k8s api, elasticsearch on internal IP)
├── emails.txt                  (87 employee emails harvested)
├── breach_check.txt            (12 hits across LinkedIn 2021, Twitter 2022)
├── github_leaks.txt            (1 hit: stale .env in a forked dev repo, secrets rotated, INFO)
└── _summary.md
```

Recap surfaced to the operator (3–5 bullets):

> - 412 subdomains, 218 alive. Tech stack: nginx + Cloudflare front, Next.js app, PostgreSQL behind.
> - **P3 candidate**: `campaign.acme-saas.example` CNAME → unclaimed Heroku app (subdomain_takeover playbook).
> - JS mining returned 1,847 endpoints — 73 look API-shaped (`/api/v[0-9]+/…`).
> - OSINT: 12 employee breach hits, but none with plaintext passwords; logging only.
> - Phase 2 ready. `/scan acme-saas`.

---

## Phase 2 — Automated Scanning (3 parallel sub-agents)

```
/scan acme-saas
```

```
AGENTIC RUN — 2026-05-12 10:31
SCOPE         : phase 2 / acme-saas
SUB-AGENTS DISPATCHED:
  G cve-match         status: done    findings: 3   output: scans/cves.txt
  H nuclei            status: done    findings: 5   output: scans/nuclei.txt
  I fuzz              status: done    findings: 2   output: scans/ffuf.txt
TOTAL ELAPSED : 22m 11s
NEXT          : /manual-test acme-saas
```

Highlights:

- `cve-match` flagged the Next.js minor version against CVE-2026-XXXX
  (cache poisoning on the ISR pipeline — confirm manually).
- `nuclei` returned a `tech-detect/elasticsearch-internal` on a host that
  shouldn't have been internet-reachable — **flagged as P2-MED inline**
  immediately, did not wait for the phase recap.
- `ffuf` found `/admin-old/` (HTTP 403) and `/api/v2/internal/healthz`
  (HTTP 200, returns a JSON env block).

---

## Phase 3 — Manual Vulnerability Testing (bucketed sub-agents)

```
/manual-test acme-saas
```

Buckets dispatched (8 sub-agents, capped at 6 in-flight per `agentic_mode.md`):

| Bucket    | Endpoints in this bucket                                                | Findings |
|-----------|-------------------------------------------------------------------------|----------|
| auth      | /login, /register, /password/reset, /2fa/verify, /oauth/google/callback | 1        |
| api       | /api/v2/users, /api/v2/orders, /api/v2/billing, /api/v2/admin           | 3        |
| graphql   | /graphql                                                                | 1        |
| upload    | /profile/avatar, /docs/import                                           | 0        |
| redirect  | /login?return=, /oauth/.../redirect_uri                                  | 1        |
| search    | /search?q=, /api/v2/search                                              | 1        |
| webhook   | /integrations/webhook/test                                              | 1        |
| state     | POST /api/v2/orders, DELETE /api/v2/users/{id}                          | 1        |

`engagements/acme-saas/findings.md` is appended as each finding is confirmed.
P1/Critical surfaces inline.

Selected findings (excerpts):

```
[F-001] CRITICAL — IDOR on GraphQL `billingDocument` allows access to any tenant's invoices
ENDPOINT     : POST /graphql
PARAM        : variables.id (base64 GraphQL node ID)
REPRO        : decode → change tenant prefix → re-encode → fetch → arbitrary invoice PDF returned
IMPACT       : full cross-tenant data breach (PII + financial)
EVIDENCE     : engagements/acme-saas/poc/F-001.http
NEXT         : duplicate check (Phase 5.1) — likely H1 critical-tier
```

```
[F-005] HIGH — SSRF on /integrations/webhook/test, AWS metadata reachable via DNS rebinding
ENDPOINT     : POST /integrations/webhook/test
PARAM        : url
REPRO        : rbndr.us-rotated host → 169.254.169.254/latest/meta-data/iam/security-credentials/
IMPACT       : EC2 IAM role tokens exfiltrated (limited role — read-only S3, but production bucket)
EVIDENCE     : engagements/acme-saas/poc/F-005.py + interactsh log
```

Eight findings total: 1 CRITICAL, 2 HIGH, 3 MEDIUM, 2 LOW.

---

## Phase 4 — Vulnerability Chaining (single-threaded)

```
/chain acme-saas
```

lethani reads all eight findings and produces three combined-impact entries:

```
[F-009] CRITICAL — Subdomain takeover (campaign.) + cookie scope → ATO
INGREDIENTS  : F-002 (takeover candidate, P3), F-007 (cookie Domain=.acme-saas.example)
COMBINED     : Take over campaign.acme-saas.example via Heroku claim, host a script that
               reads the session cookie (parent-domain scope), forward to attacker. Any
               logged-in user who visits campaign.acme-saas.example loses their session.
SEVERITY     : CRITICAL (was P3 + P3)
```

```
[F-010] HIGH — Open redirect + OAuth state-bypass → token theft
INGREDIENTS  : F-004 (open_redirect on /login?return=), F-006 (state param not validated)
COMBINED     : Craft an OAuth flow that bounces through /login?return= to attacker domain,
               exfiltrates the authorization code, exchanges it for an access token.
SEVERITY     : HIGH (was LOW + MED)
```

```
[F-011] CRITICAL — Cache poison + stored XSS on /search at CDN scale
INGREDIENTS  : F-003 (cache key omits Origin), F-008 (reflected XSS on /search?q=)
COMBINED     : Poison the Cloudflare edge cache for /search with an XSS payload. Any user
               who hits the same cache region sees the payload. PayPal $20K-class pattern.
SEVERITY     : CRITICAL (was MED + LOW)
```

`findings.md` now contains 11 entries (8 raw + 3 chained).

---

## Phase 5 — Reporting

```
/report acme-saas
```

`duplicate_checker` runs against the Acme H1 hacktivity and dedupes one
finding (F-008 reflected XSS reported in 2024, drop from submission set).

`severity_scorer` recomputes CVSS for each remaining finding with
chain-aware impact.

`report_writer` produces:

- `engagements/acme-saas/report.md` — the comprehensive pentest report
- `engagements/acme-saas/submissions/F-001.md` — IDOR submission for H1
- `engagements/acme-saas/submissions/F-009.md` — chained ATO submission
- `engagements/acme-saas/submissions/F-010.md` — OAuth token theft submission
- `engagements/acme-saas/submissions/F-011.md` — cache-poison XSS submission

Each submission uses the bug-bounty format from `report_templates.md` with
`Tester : [redacted]`.

Final conversation recap:

> Engagement complete. 11 findings (3 CRITICAL via chaining, 2 HIGH, 3 MED,
> 2 LOW, 1 INFO). One duplicate dropped. Four submissions ready under
> `engagements/acme-saas/submissions/`. Suggested submission order by
> bounty tier: F-001 → F-011 → F-009 → F-010.

---

## What this walkthrough is *not*

- Not a real engagement. No live testing happened.
- Not a recommendation to test `acme-saas.example` — it's a placeholder.
- Not a guarantee these wall-clock numbers reproduce. Phase 1 wall time
  depends on subdomain count and Kali tooling responsiveness.

For the real safety model see [`plugin/00_infra/behavior_rules.md`](../plugin/00_infra/behavior_rules.md)
and the project [SETUP.md](../SETUP.md).
