# Learning Sources — Curated High-Signal Public Feeds (2024-2026)

Sources the assistant pulls from in `learning_mode.md`. Every entry is in
English, current as of 2026, and represents material that has produced
actionable techniques in the last 12-24 months. Pentester.land Weekly is
included only for archive value — the front page has lagged; use the GitHub
mirror noted below for fresher content.

Format: `name | URL | what to look for | cadence`.

---

## 1. Live Disclosed Reports (continuously updated)

These produce the freshest real-world vulns. Skim daily during active recon
on a target; mine weekly for general technique drift.

| Source | URL | Look for | Cadence |
|---|---|---|---|
| HackerOne Hacktivity | https://hackerone.com/hacktivity | New disclosed reports, filter by bounty range (>$1k), bug type, program | Daily |
| reddelexc/hackerone-reports | https://github.com/reddelexc/hackerone-reports | Auto-mirrored top H1 reports sorted by program / bug type / bounty | Weekly (cron-updated) |
| Bugcrowd CrowdStream | https://bugcrowd.com/crowdstream | Disclosed Bugcrowd submissions, full PoC for accepted bugs | Weekly |
| Intigriti researchers portal | https://www.intigriti.com/researchers | Top researchers, hall of fame, leaderboards, monthly bounties | Monthly |
| YesWeHack Dojo / blog | https://blog.yeswehack.com/ | EU-program disclosures, niche techniques | Weekly |

---

## 2. Top Research Blogs (deep technical writeups)

These are the highest-signal feeds. A single post here often invalidates an
existing playbook section or introduces an entirely new attack class.

| Source | URL | Look for | Cadence |
|---|---|---|---|
| PortSwigger Research | https://portswigger.net/research | James Kettle's research, Top 10 Web Hacking Techniques (annual, ~Feb), HTTP smuggling and request-handling work | Monthly, plus annual roundup |
| Assetnote Research | https://www.assetnote.io/resources/research | Pre-auth RCE chains in enterprise software, novel SSRF, n-day analysis | Monthly |
| watchTowr Labs | https://labs.watchtowr.com/ | Edge-device n-days, pre-auth RCE walkthroughs, perimeter product breaks | Weekly |
| Synacktiv Publications | https://www.synacktiv.com/en/publications | CTF and Pwn2Own writeups, browser and kernel exploits, hardware | Monthly |
| Bishop Fox Labs | https://bishopfox.com/blog | Tooling releases (Sliver, eyeballer), advisories, web/cloud research | Monthly |
| Google Project Zero | https://googleprojectzero.blogspot.com/ | 0day mechanics, sandbox escapes, exploit primitives | ~Monthly |
| Snyk Research | https://snyk.io/blog/category/research/ | npm/PyPI supply-chain, prototype pollution gadgets, dependency vulns | Bi-weekly |
| Trail of Bits Blog | https://blog.trailofbits.com/ | Cryptography, smart contracts, fuzzing, tooling deep dives | Weekly |
| NCC Group Research | https://www.nccgroup.com/us/research-blog/ | AD, cloud, mobile, hardware; published advisories | Bi-weekly |
| Doyensec | https://blog.doyensec.com/ | Electron, Node.js, prototype pollution, SAML, OAuth | Monthly |
| Include Security | https://blog.includesecurity.com/ | Mobile, IoT, web app deep dives | Monthly |

---

## 3. Reference Wikis (always-current consolidated knowledge)

Use these as the second stop after a research blog post — to confirm a
technique is generalized and to grab payloads.

| Source | URL | Look for | Cadence |
|---|---|---|---|
| HackTricks | https://book.hacktricks.wiki/en/index.html | Cross-referenced technique pages, payload variants, OS-level tricks (mirror: https://book.hacktricks.xyz) | Daily commits |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Payload bank organized by vuln class, useful for filter-bypass variants | Weekly commits |
| OWASP WSTG | https://owasp.org/www-project-web-security-testing-guide/ | Canonical test-case names, mapping to your playbook section IDs | Quarterly |
| PortSwigger Web Security Academy | https://portswigger.net/web-security | Free labs covering each technique, useful to validate a new bypass | Frequent new labs |
| OWASP API Security Top 10 | https://owasp.org/API-Security/editions/2023/en/0x00-header/ | 2023 edition still current; BOLA, BOPLA, BFLA reference | Annual |
| OWASP LLM Top 10 | https://genai.owasp.org/llm-top-10/ | Maps prompt injection, data leakage, tool abuse to canonical names | ~Annual revisions |

---

## 4. Newsletters / Weekly Digests

Curated by humans. Treat these as the "skip the noise" layer — if a post
appears here it has already passed one quality filter.

| Source | URL | Look for | Cadence |
|---|---|---|---|
| tl;dr sec (Clint Gibler) | https://tldrsec.com/ | Weekly curated infosec, strong on appsec/cloud/devsecops with technique highlights | Weekly (Tue) |
| Pentester Land Weekly (archive) | https://pentester.land/list-of-bug-bounty-writeups.html | Historical writeup index; current site lags, prefer the GitHub list | Stale — use as archive |
| KathanP19/HowToHunt | https://github.com/KathanP19/HowToHunt | Community-aggregated bug bounty methodology + writeup links | Weekly |
| Bug Bytes (Intigriti) | https://newsletter.intigriti.com/ | Community-picked writeups, new tooling, Intigriti-program intel | Weekly |
| hackingthe.cloud | https://hackingthe.cloud/ | Cloud-native offensive tactics (AWS heavy, some Azure/GCP) | Bi-weekly content + annual wrap-up |
| OffSec Blog | https://www.offsec.com/blog/ | OSCP-adjacent writeups, less bug-bounty focused but solid AD/Linux | Bi-weekly |
| Ph.News (Hacking Hub) / Reddit r/bugbounty | https://www.reddit.com/r/bugbounty/ | Triage chatter, program rumors, weekly writeup threads | Daily, low signal-to-noise |

---

## 5. Tooling Update Streams

When tooling moves, defaults change. Subscribe to commits/releases, not the
marketing blog.

| Source | URL | Look for | Cadence |
|---|---|---|---|
| nuclei-templates (commits) | https://github.com/projectdiscovery/nuclei-templates/commits/main | New CVE templates, exposure templates, dast modules | Daily |
| nuclei-templates (releases) | https://github.com/projectdiscovery/nuclei-templates/releases | Bundled template releases, summary of additions | ~Weekly |
| nuclei (engine releases) | https://github.com/projectdiscovery/nuclei/releases | New matchers, protocols, DAST features | Monthly |
| ProjectDiscovery Blog | https://blog.projectdiscovery.io/ | Methodology posts, feature announcements impacting recon flow | Monthly |
| reconftw releases | https://github.com/six2dez/reconftw/releases | Recon flow updates, new module integrations | Monthly |
| projectdiscovery/nuclei-templates (community PRs) | https://github.com/projectdiscovery/nuclei-templates/pulls | Open PRs for templates not yet upstream | Weekly |
| Burp Suite release notes | https://portswigger.net/burp/releases | New scanner checks, BCheck additions | Monthly |
| Caido changelog | https://github.com/caido/caido/releases | Workflow features, new plugins | Bi-weekly |
| ffuf releases | https://github.com/ffuf/ffuf/releases | New encoders, filters, output formats | Quarterly |

---

## 6. Individual Researchers (X/Twitter + personal blogs)

When something paid >$5k or broke an unexpected target, it usually appears on
one of these timelines within 48h.

| Researcher | Primary URL | Look for |
|---|---|---|
| James Kettle (albinowax) | https://skeletonscribe.net/ + https://x.com/albinowax | HTTP smuggling, request-handling, browser-powered desync |
| Orange Tsai | https://blog.orange.tw/ + https://x.com/orange_8361 | Enterprise pre-auth RCE chains, URL parser confusion |
| Sam Curry | https://samcurry.net/ + https://x.com/samwcyo | Automotive, fintech, OAuth, account takeover chains |
| Sam Sanoob (xelkomy) | https://x.com/xelkomy | Cache poisoning, edge-side includes, esoteric web |
| Frans Rosén | https://labs.detectify.com/author/frans/ + https://x.com/fransrosen | Cloud takeovers, OAuth, postMessage abuse |
| Inon Shkedy | https://inonst.medium.com/ + https://x.com/InonShkedy | API testing methodology, OWASP API Top 10 author |
| gregxsunday (Bug Bounty Reports Explained) | https://bbre.dev/ | Video breakdowns of disclosed reports |
| NahamSec | https://nahamsec.com/ + https://x.com/NahamSec | Recon methodology, content with practical workflow |
| jhaddix | https://x.com/Jhaddix + https://danielmiessler.com/ | Recon methodology, "The Bug Hunter's Methodology" decks |
| Brett Buerhaus (bbuerhaus) | https://buer.haus/ + https://x.com/bbuerhaus | Logic bugs, mass-assignment, novel HTTP behavior |
| 0xPatrik | https://0xpatrik.com/ + https://x.com/0xpatrik | Subdomain takeover, DNS-layer attacks |
| Orwa Atyat | https://x.com/GodfatherOrwa | OAuth/SSO bypass, account takeover chains |
| Justin Gardner (Rhynorater) | https://www.criticalthinkingpodcast.io/ + https://x.com/rhynorater | Critical Thinking podcast, weekly technique discussions |
| Joseph Thacker (rez0) | https://josephthacker.com/ + https://x.com/rez0__ | AI/LLM security, prompt injection chains |
| Johan Carlsson (joaxcar) | https://x.com/joaxcar | Browser/web platform edge cases |
| Frans Rosén / Detectify Labs | https://labs.detectify.com/ | Detectify research output |

---

## 7. CVE / Advisory Feeds

For tech-stack-aware playbook updates. Tie these into the
`04_automation/cve_target_matcher.md` workflow.

| Source | URL | Look for | Cadence |
|---|---|---|---|
| NVD (NIST) | https://nvd.nist.gov/vuln/search | Canonical CVE entries, CVSS, CPE matching | Continuous |
| trickest/cve | https://github.com/trickest/cve | Auto-mined PoCs per CVE, organized by year | Daily commits |
| CISA Known Exploited Vulnerabilities (KEV) | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Actively exploited CVEs — prioritize these against detected tech | Continuous |
| GitHub Security Advisories | https://github.com/advisories | Ecosystem advisories (npm, pip, maven, etc.) with PoC links | Continuous |
| ExploitDB | https://www.exploit-db.com/ | Public exploits cross-referenced to CVEs | Daily |
| nuclei-templates CVE folder | https://github.com/projectdiscovery/nuclei-templates/tree/main/http/cves | Detection templates per CVE — pull when matcher works | Daily |
| Zero Day Initiative advisories | https://www.zerodayinitiative.com/advisories/published/ | Pwn2Own and ZDI-coordinated disclosures | Weekly |

---

## Notes on Use

- Treat blogs in Section 2 and researchers in Section 6 as **techniques**;
  treat Sections 1, 5, and 7 as **inventory** (what's now testable).
- If a post does not include either a PoC or a clear filter-bypass, skip it.
- Pentester.land's front page is no longer fresh — use the GitHub-mirrored
  community lists in Section 4 instead.
- Section 3 wikis are for confirming generality, not for novelty.
