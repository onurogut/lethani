---
description: Run Phase 1 reconnaissance against a target, fanning out to 6 parallel sub-agents
argument-hint: <target>
---

Run Phase 1 reconnaissance for `engagements/$1/`.

Pre-flight (silent unless something is wrong):

1. Verify `engagements/$1/scope.md` exists. If missing, scaffold it (see
   `/new-target`) and proceed — do not block on confirmation.
2. Read `scope.md` into context: in_scope, out_of_scope, aggressive_rate,
   brute_force, oob_endpoint.
3. Make sure `/tmp/lethani/$1/` exists on Kali via `kali-ssh`.

Dispatch — fan out to 6 sub-agents per `00_infra/agentic_mode.md` §3:

| Sub-agent       | Playbooks                                                                     |
|-----------------|-------------------------------------------------------------------------------|
| recon-dns       | dns_enumeration + subdomain_takeover + cloud_asset_mapper                     |
| recon-http      | tech_fingerprint + vhost_discovery + js_endpoint_extractor + wayback_triage   |
| recon-params    | parameter_discovery + cicd_supply_chain                                       |
| osint-network   | asn_ip_mapper + shodan_censys_queries                                         |
| osint-people    | email_harvesting + leaked_credentials                                         |
| osint-source    | github_dorking                                                                |

Each sub-agent:
- writes output into `engagements/$1/recon/<file>`
- returns a < 200-word summary with finding counts
- does NOT re-confirm scope with the operator

Wait for all 6 to return, emit the agentic run log (see `agentic_mode.md` §6),
then produce a Phase 1 summary in `engagements/$1/recon/_summary.md` and a
3–5 bullet recap in the conversation.

Then propose Phase 2 (`/scan $1`) — but do not auto-start it.
