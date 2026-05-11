# Agentic Mode — Parallel Sub-Agent Dispatch

lethani's default execution model. When a task contains independent
sub-tasks, the assistant fans them out to sub-agents (via the `Agent` tool)
and merges results, instead of running serially in the main thread.

The goal: cut wall time on Phase 1/2 work, keep the main-thread context
small, and let each sub-agent focus on one bounded job.

This document is loaded automatically when the user issues a multi-step task
(new engagement, "run phase 1", "scan all subdomains", "review these 30
endpoints"). It is also loaded explicitly when the user says "agentic mode",
"parallel", "fan out", or "use sub-agents".

---

## 1. When to fan out (paralellize)

Fan out only when **all** of the following are true:

1. **Independence** — the sub-task's inputs do not require another
   in-flight sub-task's output.
2. **Bounded scope** — the sub-task has a single, clearly defined deliverable
   (a file written, a summary returned, a finding count).
3. **Time savings real** — sub-task takes long enough to make dispatch
   overhead worthwhile (rule of thumb: >30 seconds of expected work).
4. **No shared mutable state** — sub-agents do not write to the same file
   without coordination; if they must, give each one a distinct output path.
5. **Rate-limit safe** — for active scanning, the sum of sub-agent rates
   stays under the agreed-upon ceiling for the target.

### Always fan out

- Phase 1 recon — 14 sources are independent. Group into 5–6 sub-agents.
- Phase 1.10–1.13 OSINT — fully independent from active recon and from each
  other.
- Tech-stack-targeted nuclei runs against disjoint subdomain buckets.
- Endpoint-by-endpoint manual checklist across a list of >10 endpoints.
- Source-by-source ingest during Learning Mode.

### Never fan out

- Phase 0 scope confirmation — single decision, single thread.
- Phase 4 chaining analysis — requires the full set of findings already
  collected; chaining is synthesis, not parallelizable work.
- Final report composition (Phase 5.3) — single voice, single document.
- Any step where the user must approve a destructive action between
  sub-steps.
- Initial reconnaissance against a *single* host where rate limits matter
  more than wall time.

---

## 2. Sub-agent dispatch pattern

### Brief format (every sub-agent message starts with this block)

```
TASK         : <one-line task name>
ENGAGEMENT   : <target slug>          (e.g. acme)
SCOPE        : <in-scope domains>
KALI PATH    : /tmp/lethani/<target>/
INPUT FILES  : <list of files the agent should read, or "none">
TOOLING      : <Explore | general-purpose | other>
TIME LIMIT   : <minutes>               (sub-agent self-aborts past this)
DELIVERABLE  : <exact file path the agent must write>
REPORT BACK  : <max-N-line summary to return to main thread>
DO NOT       : <explicit anti-instructions, e.g. "do not run active scans">
```

### Tool choice per sub-agent type

| Job kind                                  | Recommended subagent_type    |
|-------------------------------------------|------------------------------|
| File search / "where is X defined"        | `Explore`                    |
| Multi-step Kali command pipeline          | `general-purpose`            |
| Reading 20+ files and summarizing         | `Explore`                    |
| Writing a new playbook patch              | `general-purpose`            |
| Code review of a PoC script               | `code-reviewer` (if present) |
| Web research for Learning Mode            | `general-purpose`            |

### Result merge

Each sub-agent's return value should be **<200 words** plus a list of files
it wrote. The main thread does not re-read those files in full — it reads
the summary, picks two or three files of interest, and skims them.

Findings always land in `engagements/<target>/findings.md` (append-only),
not in the sub-agent's prose. The prose is a TL;DR for the main thread.

---

## 3. Standard fan-out plans

### Phase 1 — Recon (six parallel sub-agents)

```
Sub-agent A (recon-dns)        dns_enumeration + subdomain_takeover + cloud_asset_mapper
Sub-agent B (recon-http)       tech_fingerprint + vhost_discovery + js_endpoint_extractor + wayback_triage
Sub-agent C (recon-params)     parameter_discovery + cicd_supply_chain
Sub-agent D (osint-network)    asn_ip_mapper + shodan_censys_queries
Sub-agent E (osint-people)     email_harvesting + leaked_credentials
Sub-agent F (osint-source)     github_dorking
```

All six write to `engagements/<target>/recon/<file>` and return a one-page
summary. Main thread fans them in to a single `recon_summary.md`.

### Phase 2 — Automated scanning (three parallel sub-agents)

```
Sub-agent G (cve-match)    cve_target_matcher against tech.txt from Phase 1
Sub-agent H (nuclei)       nuclei against alive.txt with severity critical,high (rate-limited)
Sub-agent I (fuzz)         ffuf against the top-50 alive hosts using wordlist_builder output
```

Main thread waits for all three, dedupes findings, and writes
`engagements/<target>/scans/scan_summary.md`.

### Phase 3 — Manual vuln testing (N parallel sub-agents, one per endpoint bucket)

Group endpoints by behaviour, not by URL:

```
Sub-agent J (auth)         all login/register/reset/2FA endpoints
Sub-agent K (api)          all /api/ endpoints
Sub-agent L (graphql)      all GraphQL endpoints
Sub-agent M (upload)       all file-upload endpoints
Sub-agent N (redirect)     all URL-redirect-accepting endpoints
Sub-agent O (search)       all search/filter/sort endpoints
```

Each gets `00_infra/endpoint_checklist.md` plus the relevant
`02_vuln_testing/<playbook>.md`. Each writes findings to a per-bucket file:
`engagements/<target>/findings_<bucket>.md`. Main thread concatenates to
the master `findings.md` at the end of Phase 3 and starts Phase 4 chaining.

### Learning Mode — source fetch (one sub-agent per source category)

When the user invokes Learning Mode (`00_infra/learning_mode.md` §2.3),
dispatch one sub-agent per category in `learning_sources.md`. Each one
returns a filtered list of novel items (one paragraph each). Main thread
runs the diff/propose loop synchronously because that step needs user
interaction.

---

## 4. Concurrency limits

- **Soft limit**: 6 sub-agents in flight at once. More than that creates
  context churn on result merge.
- **Hard limit on active scanners**: at most 2 sub-agents may have
  concurrent `mcp__kali-ssh__runRemoteCommand` calls touching the same
  target. If a sub-agent needs to run nuclei, others must be passive
  (file-reading, OSINT API, web research) until it returns.
- **Token budget**: each sub-agent's `prompt` field stays under 1500 tokens.
  Long context (e.g. a 50-page playbook) is referenced by path, not pasted.

---

## 5. Failure handling

- A sub-agent returning "blocked" or "no findings" is **fine** — record it
  in the run log and move on. Do not retry blindly.
- A sub-agent that times out (past TIME LIMIT) is killed; the main thread
  notes which sources/endpoints were not covered, surfaces this in the
  Phase summary, and lets the user decide whether to re-dispatch.
- If two sub-agents return contradictory data (e.g. one says CDN is
  Cloudflare, another says Akamai), the main thread does not silently pick
  one — it surfaces the conflict and asks the user.
- A sub-agent that needs user input mid-task is **doing it wrong** —
  re-brief it with the missing info baked in.

---

## 6. Run log format

Every fan-out emits a brief run log in the main thread, so the user can
trace what happened:

```
AGENTIC RUN — <YYYY-MM-DD HH:MM>
SCOPE         : <phase or task name>
SUB-AGENTS DISPATCHED:
  A recon-dns         status: done    findings: 3  output: recon/subdomains.txt
  B recon-http        status: done    findings: 1  output: recon/alive.txt, recon/tech.txt
  C recon-params      status: timeout findings: 0  partial: recon/params.txt
  D osint-network     status: done    findings: 0  output: recon/asn.txt
  E osint-people      status: done    findings: 2  output: recon/emails.txt
  F osint-source      status: blocked findings: 0  reason: gh api 403
TOTAL ELAPSED : <minutes>
NEXT          : <main-thread next step>
```

This block is the canonical "what just happened" summary and is kept in the
conversation so the user can ask follow-ups without re-reading individual
sub-agent transcripts.

---

## 7. Anti-patterns (do not do these)

- **Sub-agent calling sub-agent** — recursion explodes context.
- **One sub-agent per HTTP request** — too granular; group at the playbook
  level.
- **Fanning out before scope is approved** — Phase 0 always runs first, in
  the main thread.
- **Asking the user to approve mid-fan-out** — fan-out implies user has
  already approved the batch; if approval is needed, do it before
  dispatching.
- **Writing to the same file from two sub-agents** — use distinct paths and
  merge in the main thread.
- **Reading sub-agent transcripts directly** — read the summary only; the
  full transcript will overflow context.
