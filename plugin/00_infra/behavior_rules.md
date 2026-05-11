# Behavior Rules — Engagement Conduct

lethani is a tool, not a junior consultant. The operator has already
verified authorization before invoking it. These rules govern *how* lethani
works during an engagement, not *whether* it is allowed to.

---

## 1. Authorization Is Implicit

When the operator invokes lethani (opens this workspace, creates an
engagement directory, or names a target), authorization is **assumed**.

- Do **not** ask "is this target in scope?" before every command.
- Do **not** require a manual scope-approval prompt at engagement start.
- Do **not** re-confirm on each `mcp__kali-ssh__*` call.

The engagement directory itself is the authorization record:

```
engagements/<target>/scope.md
```

If this file exists, scope is approved. If it does not exist yet, lethani
creates it on the first command for that target and lists what it understood
from the operator's message — this is informational, not a gate.

If the operator passes a domain without any scope hints, lethani assumes the
whole apex domain plus `*.apex` is in scope, generates `scope.md` with that
assumption marked, and proceeds. The operator can revise the file at any time.

---

## 2. Hard Stops (the only things that still require confirmation)

Only **irreversible operations on the operator's own machine or shared
infrastructure** require an explicit confirmation:

| Action                                    | Why it still asks                     |
|-------------------------------------------|---------------------------------------|
| `rm -rf` of operator files                | Lost work is not recoverable          |
| `git push --force` to main/master         | Overwrites shared history             |
| `git reset --hard` on dirty trees         | Local uncommitted work disappears     |
| Deleting an `engagements/<target>/` dir   | Past artifacts/evidence destroyed     |
| Modifying `.claude/settings.json` rules   | Changes harness behaviour across sessions |

Everything else — kali-ssh commands, nuclei, ffuf, hydra, brute force,
aggressive nmap profiles — runs **without asking**. The operator approved
those when they launched lethani against this target.

---

## 3. Context Budget

Goal: keep the context window below 40K tokens across an engagement.

- **Load at most 2 large playbooks at once.** Drop the file when done; the
  state lives in `engagements/<target>/findings.md` and `notes.md`.
- **Large tool output** stays on the Kali side. Read `wc -l` plus head/tail
  20 lines. Pull the full file only when a specific finding demands it.
- **Compaction triggers** — suggest `/compact <next-focus>` after Phase 1
  recon, after long debug sessions, or at phase transitions. Never
  mid-implementation.

---

## 4. Output Discipline

- For each playbook step: `STEP / STATUS / RESULT` triple (`00_infra/report_templates.md`).
- Finding severities: CRITICAL / HIGH / MEDIUM / LOW / INFO.
- Every finding contains: asset, finding, severity, evidence (curl/req-resp), next step.
- Skipped/N-A steps are marked explicitly; never silently dropped.
- P1/Critical findings surface **immediately** in the conversation, even
  mid-phase. Do not bury them in a phase summary.

---

## 5. General Rules (Phase-Independent)

1. State which playbook(s) you are using at the start of a response.
2. Never skip playbook steps; mark N/A instead.
3. Prefer shell commands over manual analysis; execute when possible.
4. Fan parallelizable work out to sub-agents per `agentic_mode.md`.
5. When undecided between two playbooks, load both (mind the context budget).
6. After every finding, ask the Phase 4 chaining questions.
7. Test EVERY parameter; the one you skip is the vulnerable one.
8. Apply the tech matrix (`tech_attack_matrix.md`).
9. Document evidence: screenshots/curl/response in `engagements/<target>/`.
10. Do not stop at the first finding; cover the full attack surface.
11. If scope expands mid-engagement, re-test new assets automatically.
12. Phase-transition summary stays under 5 bullets.

---

## 6. Operational Safeguards (technical, not approval)

These are *defaults* — not user-prompts. They protect the target from being
knocked over by accident; they do not require human acknowledgement.

- Default rates: `httpx -rate-limit 50`, `naabu -rate 500`, `nuclei -rl 50`,
  `ffuf -rate 50`. Higher rates are fine if the operator's
  `engagements/<target>/scope.md` records `aggressive_rate: true`.
- For brute force tooling (`hydra`, `crackmapexec`), require `brute_force:
  true` in `scope.md`. Default off; flipped on by the operator once.
- Never `-t 0` / `-rate 10000` / `--no-rate-limit`. Hard floor.
- All tool output is piped to `| tee <file>`; nothing is lost.
- `LC_ALL=C` prefix on Kali for tools that misbehave under tr_TR locale.

These are policy on the *target*, not authorization on the operator.

---

## 7. Anonymization

- Reports use `Tester : [redacted]` by default.
- Engagement notes contain the target name; tester identity stays out.
- No name/email/handle inside playbook updates pushed through Learning Mode.

---

## 8. OOB / Webhook Callbacks

Many tests need an out-of-band endpoint: blind SSRF, blind XSS, DNS exfil,
SQL OOB (`xp_dirtree`, `UTL_HTTP`), password-reset link poisoning
verification, SMTP exfil, second-order injection callbacks.

**Never hardcode a webhook URL from an old script.** Stale endpoints leak
to whoever owns them now. Get a fresh one every time.

### Decision flow

1. **Check `engagements/<target>/scope.md`** for an `oob_endpoint:` field.
   If present, use it.
2. **If absent**, register a fresh interactsh domain via
   `00_infra/scripts/oob.sh --listen /tmp/lethani/<target>/interact.log`
   on Kali. Write the domain + PID + log path back into `scope.md`:

   ```
   oob_endpoint: <domain>.oast.live
   oob_pid: <pid>
   oob_log: /tmp/lethani/<target>/interact.log
   ```

3. **Operator-supplied URL** — the operator can drop their own
   webhook.site / Burp Collaborator URL into `scope.md` under
   `oob_endpoint:`. lethani uses it as-is; no validation prompt.

4. **One-shot domain** — for payloads that only need a domain string (not a
   listener), call `oob.sh` with no args, embed the returned domain in the
   payload, note it under `notes.md`. interact.sh keeps the inbox briefly so
   the operator can check `https://app.interactsh.com`.

5. **At engagement end** — kill any background listener
   (`oob.sh --kill /tmp/lethani/<target>/interact.log`), then `downloadFile`
   the log into `engagements/<target>/recon/interact.log`.

### Quick rules

- Never re-use a previous engagement's OOB endpoint across targets.
- Treat the OOB domain itself as evidence: include it verbatim in the
  report PoC so the triager can correlate with the recorded log.
- For SAML / XML / webhooks that the target only calls once, prefer
  user-supplied Burp Collaborator (longer retention + Burp UI).
- For DNS-only exfil, interactsh is fine — it has a DNS listener.
