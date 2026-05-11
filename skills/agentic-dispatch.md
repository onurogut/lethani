---
name: agentic-dispatch
description: Fan out parallelizable engagement work to sub-agents per 00_infra/agentic_mode.md. Triggers on "parallel", "fan out", "sub-agents", "agentic", "run phase 1/2/3", "batch", "per-endpoint".
---

When invoked, load `00_infra/agentic_mode.md` and apply its dispatch pattern
for the requested phase or task.

Default fan-out plans:

- **Phase 1 recon** → 6 sub-agents (recon-dns, recon-http, recon-params,
  osint-network, osint-people, osint-source) in parallel.
- **Phase 2 scan** → 3 sub-agents (cve-match, nuclei, fuzz).
- **Phase 3 manual test** → N sub-agents bucketed by endpoint behaviour
  (auth, api, graphql, upload, redirect, search, webhook, state).
- **Phase 4 chain** → single-threaded (synthesis, not parallel).
- **Phase 5 report** → single-threaded composition.

Concurrency limits: max 6 in-flight; max 2 active scanners simultaneously.

Brief each sub-agent with the exact block from `agentic_mode.md` §2 (TASK,
ENGAGEMENT, SCOPE, KALI PATH, INPUT FILES, TOOLING, TIME LIMIT, DELIVERABLE,
REPORT BACK, DO NOT).

After fan-in: emit the agentic run log (`agentic_mode.md` §6) and produce
the merged summary file in the engagement directory.
