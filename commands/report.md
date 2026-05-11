---
description: Run Phase 5 reporting — duplicate check, severity scoring, structured report
argument-hint: <target>
---

Run Phase 5 reporting for `engagements/$1/`.

Procedure:

1. **Duplicate check** — for each finding, follow
   `03_reporting/duplicate_checker.md`. If the engagement is a bug bounty
   submission, also check the program's hacktivity.
2. **Severity scoring** — per `03_reporting/severity_scorer.md`, score every
   finding (single + chained).
3. **Report composition** — single-threaded. Compose
   `engagements/$1/report.md` using the template in
   `00_infra/report_templates.md`:
   - Executive summary (3 paragraphs)
   - Target information
   - Findings ordered by severity
   - Positive findings (controls that worked)
   - Priority matrix
   - Overall assessment
   - Notes (scope limits, methodology)

The report uses `Tester : [redacted]` (anonymization rule, behavior_rules §7).

For bug bounty submissions: also generate `engagements/$1/submissions/<n>.md`
per finding using the bug-bounty format in `report_templates.md`.

Print the final report path. Do not auto-submit anywhere.
