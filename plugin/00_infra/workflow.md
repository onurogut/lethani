# Engagement Workflow — Phase Details

When a target is provided, all phases run in order. No skipping; mark steps
N/A if not applicable. P1/Critical findings are flagged to the user immediately.

---

## Phase 0 — Scope & Rules

- Playbook: `03_reporting/program_rules_parser.md`
- Output: `engagements/<target>/scope.md` (in/out scope, bounty table, excluded vuln types, mandatory header/email, geo-restrictions)
- Phase 1 does not start until this document is approved by the user.

---

## Phase 1 — Reconnaissance

| Order | Playbook                                  | Output                               |
|-------|-------------------------------------------|--------------------------------------|
| 1.1   | `01_recon/dns_enumeration.md`             | subdomains.txt                       |
| 1.2   | `05_osint/asn_ip_mapper.md`               | asn.txt, cidr.txt                    |
| 1.3   | `01_recon/subdomain_takeover.md`          | takeover candidates                  |
| 1.4   | `01_recon/tech_fingerprint.md`            | tech.txt                             |
| 1.5   | `01_recon/vhost_discovery.md`             | vhost.txt                            |
| 1.6   | `01_recon/js_endpoint_extractor.md`       | js_endpoints.txt, secrets.txt        |
| 1.7   | `01_recon/wayback_triage.md`              | urls.txt                             |
| 1.8   | `01_recon/parameter_discovery.md`         | params.txt                           |
| 1.9   | `01_recon/cloud_asset_mapper.md`          | buckets.txt                          |
| 1.10  | `05_osint/shodan_censys_queries.md`       | services.txt                         |
| 1.11  | `05_osint/github_dorking.md`              | github_leaks.txt                     |
| 1.12  | `05_osint/email_harvesting.md`            | emails.txt                           |
| 1.13  | `05_osint/leaked_credentials.md`          | breach_check.txt                     |
| 1.14  | `01_recon/cicd_supply_chain.md`           | cicd_findings.md                     |

**Feeds:** subdomains → Phase 2 targets; tech.txt → CVE matching + nuclei templates; JS endpoints → SSRF/IDOR/API targets; params → injection points; emails → credential testing; cloud → bucket testing; CI/CD configs → workflow injection.

---

## Phase 2 — Automated Scanning

| Order | Playbook                                          | Purpose                              |
|-------|---------------------------------------------------|--------------------------------------|
| 2.1   | `04_automation/cve_target_matcher.md`             | tech version → known CVEs            |
| 2.2   | `04_automation/nuclei_template_selector.md`       | tech-based template selection + run  |
| 2.3   | `04_automation/ffuf_fuzzing.md`                   | dir/param/vhost fuzz                 |
| 2.4   | `04_automation/wordlist_builder.md`               | target-specific wordlist             |
| 2.5   | `04_automation/rate_limit_tester.md`              | login/API/OTP rate limit             |

---

## Phase 3 — Manual Vulnerability Testing

Every endpoint, parameter, and form discovered in Phase 1-2 is tested in the
order below. Order is by typical bounty value.

```
P1-CRIT  sqli_methodology       any DB-backed endpoint with user input
P1-CRIT  ssrf_playbook          URL param, webhook, import/export, PDF, image fetch
P1-CRIT  deserialization        Java/.NET/PHP/Python/Ruby/Node serialized data
P1-CRIT  path_traversal_lfi     file/include/template/doc/path/page params
P1-CRIT  ssti_playbook          template rendering, email templates, PDF gen
P1-CRIT  http_smuggling         behind reverse proxy/CDN (nginx+Apache, CF+origin)

P1-HIGH  auth_bypass_checklist  login, register, password reset, 2FA, session
P1-HIGH  oauth_sso_saml         OAuth2/OIDC/SAML/SSO detected
P1-HIGH  idor_framework         every object reference (URL/body/GraphQL ID)
P1-HIGH  file_upload_guide      file upload, avatar, multipart
P1-HIGH  api_security           REST/GraphQL/gRPC, Swagger/OpenAPI, /api/

P2-MED   xss_playbook           reflected/stored input, search, comments, profile
P2-MED   xxe_playbook           XML/SOAP/SVG/XLSX/RSS/SAML
P2-MED   graphql_attacks        /graphql, /gql, /query
P2-MED   prototype_pollution    Node.js Express, JSON deep-merge, PHP type juggle
P2-MED   csrf_playbook          state-changing operations
P2-MED   cors_misconfiguration  CORS headers + credentials
P2-MED   cache_poisoning        CDN/proxy (CF/CloudFront/Akamai/Varnish)
P2-MED   race_condition         financial, coupons, votes, inventory
P2-MED   business_logic         e-commerce, multi-step, pricing, approvals
P2-MED   llm_ai_security        AI chatbot, LLM features, RAG

P3-LOW   open_redirect          url=/next=/return=/redirect_uri=
P3-LOW   crlf_header_injection  params reflected in headers
P3-LOW   jwt_attack_playbook    JWT auth
P3-LOW   websocket_testing      /ws, /nw, /socket.io
P3-LOW   host_header_attacks    password reset, Host-dependent URL building
P3-LOW   mobile_thick_client    APK/IPA, Electron
```

Full per-endpoint checklist: `00_infra/endpoint_checklist.md`.
Tech-stack mandatory playbooks: `00_infra/tech_attack_matrix.md`.

---

## Phase 4 — Vulnerability Chaining

Combine low-impact findings to escalate severity:

```
Open redirect + OAuth          →  token theft               (LOW → CRITICAL)
SSRF + cloud metadata          →  AWS/GCP/Azure keys        (MED → CRITICAL)
XSS + CSRF                     →  account takeover          (MED → HIGH)
IDOR + PII fields              →  mass data breach          (MED → CRITICAL)
Cache poisoning + XSS          →  stored XSS at scale       (MED → HIGH)
LFI + log poisoning            →  RCE                       (MED → CRITICAL)
Prototype pollution + gadget   →  RCE                       (MED → CRITICAL)
HTTP smuggling + cache         →  persistent XSS            (MED → HIGH)
CRLF + cache                   →  persistent poisoning      (LOW → HIGH)
Race condition + business log  →  $$$ exploit               (MED → HIGH)
Subdomain takeover + cookie    →  ATO                       (MED → HIGH)
SAML XSW + NameID spoof        →  admin access              (MED → CRITICAL)
OAuth CSRF + account link      →  ATO                       (LOW → CRITICAL)
XXE + SSRF                     →  internal network scan     (MED → HIGH)
GraphQL batch + no rate limit  →  brute force               (LOW → MED)
Deserialization + gadget       →  RCE                       (HIGH → CRITICAL)
Host header + password reset   →  ATO                       (LOW → HIGH)
Prompt injection + tool call   →  SSRF/RCE                  (MED → CRITICAL)
CI/CD injection + secret exfil →  supply chain compromise   (MED → CRITICAL)
XS-Leak + CSRF token leak      →  state change              (LOW → HIGH)
DOM clobbering + script gadget →  XSS                       (LOW → MED)
```

After every finding, asking "what can I chain this with?" is mandatory.

---

## Phase 5 — Reporting

| Order | Playbook                              | Purpose                              |
|-------|---------------------------------------|--------------------------------------|
| 5.1   | `03_reporting/duplicate_checker.md`   | already-reported check               |
| 5.2   | `03_reporting/severity_scorer.md`     | impact-aware severity                |
| 5.3   | `03_reporting/report_writer.md`       | structured report + PoC              |

Format templates: `00_infra/report_templates.md`.
