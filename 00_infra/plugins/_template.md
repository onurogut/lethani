---
name: <kebab-case-name>
description: <one sentence — what this plugin tests and when to load it>
triggers:
  - <trigger phrase 1>
  - <trigger phrase 2>
phase: <0|1|2|3|4|5>
playbook_kind: <recon|vuln|automation|osint|reporting>
status: <experimental|beta|stable>
---

# <Plugin Name>

One-paragraph description: what this plugin tests, in plain English.

## When to load

Concrete triggers, tech-stack overlap, endpoint patterns.

## Procedure

Numbered steps. Each step is testable on its own.

1. What to send (payload / curl in a code block).
2. What to look for in the response.
3. Pass / Fail / N-A criteria.

## Bypasses and variants

If applicable, one line per variant + sample payload.

## Evidence to capture

What goes into the finding record.

## False positives

What looks like a hit but isn't.

## References

3–5 links.
