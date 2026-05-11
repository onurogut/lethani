---
description: Run Phase 3 manual vulnerability testing, bucketed by endpoint behaviour
argument-hint: <target>
---

Run Phase 3 manual testing for `engagements/$1/`.

Pre-flight:
- Read `recon/urls.txt`, `recon/alive.txt`, `recon/params.txt`, `scans/_summary.md`.
- Read `00_infra/tech_attack_matrix.md` and pick mandatory playbooks based on
  detected tech in `recon/tech.txt`.

Endpoint bucketing — split discovered endpoints into behaviour groups, fan out
one sub-agent per group (`agentic_mode.md` §3):

| Bucket    | Endpoints                                                    | Playbooks |
|-----------|--------------------------------------------------------------|-----------|
| auth      | login / register / reset / 2FA / oauth / saml                | auth_bypass_checklist, oauth_sso_saml, jwt_attack_playbook |
| api       | /api/, swagger, openapi, rest                                | api_security, idor_framework, sqli_methodology |
| graphql   | /graphql, /gql, /query                                       | graphql_attacks, idor_framework |
| upload    | file upload, avatar, import                                  | file_upload_guide, xxe_playbook, path_traversal_lfi |
| redirect  | redirect_uri, next, return, url= params                      | open_redirect, ssrf_playbook |
| search    | search, filter, sort, q= params                              | xss_playbook, sqli_methodology, ssti_playbook |
| webhook   | webhook, callback, import-from-url                           | ssrf_playbook |
| state     | POST/PUT/DELETE endpoints with side-effects                  | csrf_playbook, race_condition, business_logic |

Each sub-agent:
- runs `00_infra/endpoint_checklist.md` for every endpoint in its bucket
- writes per-bucket findings to `engagements/$1/findings_<bucket>.md`
- flags P1/Critical findings inline (does not wait for end of bucket)

Concurrency: max 6 in-flight, max 2 with active scanners simultaneously
(see `agentic_mode.md` §4).

After fan-in: concatenate per-bucket files into `findings.md`, then propose
`/chain $1` for Phase 4.
