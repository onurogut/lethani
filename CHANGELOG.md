# Changelog

All notable changes to lethani are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions use
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Drop-in plugin extension point under `00_infra/plugins/` for emerging
  vuln classes that don't yet warrant a full playbook slot.

## [0.1.0] — 2026-05-12

### Added
- Initial public release.
- 51 phase-aligned playbooks across `01_recon/`, `02_vuln_testing/`,
  `03_reporting/`, `04_automation/`, `05_osint/`.
- `CLAUDE.md` router (≈3.6K tokens) with phase-order, slash-routing table,
  tech matrix, and behaviour rules summary.
- `00_infra/` shared docs: workflow, behavior rules (authorization
  implicit), execution environment, tech attack matrix, endpoint
  checklist, report templates, bug bounty lessons, agentic mode, learning
  mode, learning sources.
- Claude Code plugin packaging: `.claude-plugin/plugin.json`, 8 slash
  commands, 6 sub-agents, 3 skills.
- Kali setup helpers: `setup-host.sh` (SSH/MCP wiring) and `setup-kali.sh`
  (tool inventory install).
- Host CLI: `bin/lethani new|status|backup|version`.
- Helper scripts: `oob.sh` (interactsh OOB endpoint), `update.sh`.
- Examples: anonymised end-to-end engagement walkthrough, asciinema demo
  script.
- Contribution and disclosure docs: `CONTRIBUTING.md`, `SECURITY.md`.
- CI: markdownlint + lychee linkcheck + shellcheck workflow.
- License: MIT.

### Notes
- Naming change: project renamed from `netfuckerz` to `lethani`.
  References to the old name have been removed; engagement artifacts and
  archive files retain their historical contents.

[Unreleased]: https://github.com/onurogut/lethani/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/onurogut/lethani/releases/tag/v0.1.0
