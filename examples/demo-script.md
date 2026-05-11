# asciinema Demo Script

Target length: **~90 seconds**.

```bash
# record
asciinema rec --idle-time-limit 2 --title "lethani — every move, deliberate" \
              examples/demo.cast

# stop with Ctrl-D when the Phase 1 recap shows up

# upload (asks for asciinema.org auth on first use)
asciinema upload examples/demo.cast

# optional: render a GIF
# (install once: cargo install --git https://github.com/asciinema/agg)
agg examples/demo.cast examples/demo.gif
```

Embed in README:

```markdown
[![asciicast](https://asciinema.org/a/REC_ID.svg)](https://asciinema.org/a/REC_ID)
```

Or the GIF directly:

```markdown
![demo](examples/demo.gif)
```

---

## Scene plan

### 0:00 — Cold open (5s)

```bash
cd ~/lethani
clear
echo "lethani — every move, deliberate"
```

### 0:05 — Launch Claude Code (5s)

```bash
claude
```

Wait for the prompt. The SessionStart hook prints one short reminder line.

### 0:10 — Scaffold a target (20s)

In Claude Code:

```
/new-target acme-saas.example
```

The agent confirms the engagement directory and shows the scope.md
template. **Do not edit anything mid-demo** — the default scope is fine
for a 90s clip.

Cut to: `ls engagements/acme-saas/` in a second pane (or have the agent
print the tree).

### 0:30 — Phase 1 fan-out (40s)

```
/recon acme-saas
```

The agent prints the dispatch table for the six sub-agents and waits.
Sub-agents run on Kali via kali-ssh; their output is summarized line by
line as each returns. The viewer sees the run log fill in.

**Key visual**: highlight `recon-dns` returning a subdomain takeover
candidate as a P1 surface. The agent flags it inline:

> ⚠ P3 candidate: campaign.acme-saas.example → unclaimed Heroku app.

(If recording against a live target, sanitize the name in post — or
record against a CTF target that explicitly permits it.)

### 1:10 — Findings + closing recap (15s)

The agent prints the 3–5 bullet recap. Pan over to show:

```bash
cat engagements/acme-saas/recon/_summary.md
```

End with:

```
Phase 1 complete. /scan acme-saas next.
```

### 1:25 — Outro (5s)

Stop recording (`Ctrl-D` in the recording terminal).

---

## Recording tips

- Use a 100×30 terminal at minimum (asciinema scales down nicely).
- Solarized Dark or a black/gold theme matches the README aesthetic.
- Speak nothing aloud — the cast is silent. All narration goes into a
  caption track in post (asciinema supports markers but most viewers
  rely on the visible terminal).
- Run `asciinema upload examples/demo.cast` to publish; replace
  `REC_ID` in the README badge with the returned ID.

## Don't

- Don't record against a live in-scope target without that program's
  explicit permission to broadcast traffic. Bug bounty programs
  generally **prohibit** publishing PoCs of unpatched vulns. Use a CTF
  range, your own deliberately-vulnerable host, or a wholly fictional
  recording where the "Kali output" is pre-recorded text.
- Don't show real API keys, real customer data, or real IPs even if
  technically in-scope. Sanitize.
