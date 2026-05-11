---
description: Run Phase 2 automated scanning against a target (parallel cve + nuclei + ffuf)
argument-hint: <target>
---

Run Phase 2 automated scanning for `engagements/$1/`.

Pre-flight:
- Phase 1 outputs (`recon/alive.txt`, `recon/tech.txt`, `recon/subdomains.txt`)
  must exist. If not, suggest `/recon $1` and stop.
- Read `scope.md`: `aggressive_rate` controls rate ceilings.

Dispatch — three parallel sub-agents per `agentic_mode.md` §3:

| Sub-agent | Job                                                              |
|-----------|------------------------------------------------------------------|
| cve-match | `cve_target_matcher` against `tech.txt`                          |
| nuclei    | `nuclei -severity critical,high` against `alive.txt` (rate-limited per scope) |
| fuzz      | `ffuf` against top-50 alive hosts with `wordlist_builder` output |

Each writes to `engagements/$1/scans/<file>` and returns counts.

After fan-in: dedupe findings, write `scans/_summary.md`, surface any
CRITICAL/HIGH findings immediately in the conversation. Propose `/manual-test
$1` next (do not auto-start).
