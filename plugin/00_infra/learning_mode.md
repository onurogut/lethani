# Learning Mode — Procedure for Ingesting New Offensive Research

This document tells the assistant how to learn from the public sources in
`00_infra/learning_sources.md` and propose targeted updates to playbooks in
`01_recon/`, `02_vuln_testing/`, `03_reporting/`, `04_automation/`, and
`05_osint/`.

The output of Learning Mode is **proposed patches** — never silent edits.
Every change is confirmed by the user before any file is written.

---

## 1. Trigger Phrases

When the user message contains any of the following, switch to Learning Mode
and load this document plus `learning_sources.md`:

- "learn mode"
- "learning mode"
- "update playbooks"
- "what's new"
- "what is new in <vuln class>"
- "scrape sources"
- "ingest research"
- "refresh playbooks"
- "check for new techniques"
- "weekly update" / "monthly update"
- "diff playbooks against research"

If the user names a specific category (e.g. "learn mode for SSRF"), restrict
fetching to sources relevant to that category and to the matching playbook
file.

---

## 2. Workflow

Numbered steps. Do not skip. Stop and ask the user at each decision point
where the spec says "ask".

### Step 1 — Scope the run

Ask the user (single message, multiple bullets):

- Category focus (all / recon / specific vuln class / automation / OSINT / reporting)
- Cadence (weekly / monthly / ad-hoc — see Section 5)
- Time bound (last 7 days / last 30 days / last 90 days)
- Max sources to fetch (default: 10)

If the user says "just go", default to: weekly cadence, last 14 days, all
categories, max 10 sources.

### Step 2 — Pick sources

From `learning_sources.md`, select sources by category and cadence:

- Weekly run: Section 2 (top 5 blogs), Section 4 (tl;dr sec + Bug Bytes), Section 1 (top 10 from HackerOne hacktivity + reddelexc mirror).
- Monthly run: add Section 5 (nuclei-templates diff) and Section 7 (CISA KEV diff).
- Category-restricted run: pick only sources whose "Look for" column matches the user's category.

Output the chosen list to the user as a numbered table before fetching.

### Step 3 — Fetch with WebFetch

For each chosen source:

1. Call `WebFetch` with a prompt of the form:
   `"List items from the last <N> days. For each item return: title, URL, vuln class, 3-line technique summary, whether a PoC is included."`
2. If the source is a GitHub repo (reddelexc, trickest, nuclei-templates),
   use `gh api` via the Bash tool to list recent commits instead — faster
   and authenticated.
3. Collect raw results into an in-memory list. Do NOT write to disk yet.

If a source returns nothing or 404s, log it and continue. Never block the
whole run on one dead source.

### Step 4 — Filter for novelty

For each fetched item, drop it unless it meets ALL of the following (this is
the **quality bar** from Section 4):

- (a) Demonstrated with a working PoC, video, or step-by-step reproduction.
- (b) Not already covered by an existing playbook section.
- (c) Generalizable beyond one target (technique, not a single-vendor bug
  unless the vendor is widely deployed — e.g. Atlassian, Cloudflare,
  Microsoft 365).
- (d) Published within the user's time bound.

For each item that survives, record:

- `source_url`
- `vuln_class` (map to playbook filename)
- `technique_summary` (max 2 lines)
- `delta_type` (NEW_BYPASS / NEW_CHAIN / NEW_PRIMITIVE / NEW_DETECTION / TOOL_UPDATE / CVE_PATTERN)

### Step 5 — Diff against existing playbooks

For each surviving item:

1. Read the target playbook (`02_vuln_testing/<file>.md` etc.).
2. Search it for keywords from the technique summary.
3. Classify:
   - **DUPLICATE** — already present, drop.
   - **REFINEMENT** — existing section, but technique adds a variant /
     bypass / new payload.
   - **NEW SECTION** — playbook has no coverage of this technique.

### Step 6 — Propose patches

Present a batch of proposed patches to the user using the **diff format** in
Section 3. One patch per surviving novel technique. Number them sequentially.

End the message with:

> Reply with the numbers you want to apply (e.g. "apply 1,3,5"), "apply all",
> or "skip". Reply "edit N" with notes to revise patch N before applying.

### Step 7 — On approval, write the edits

Only after the user approves:

1. Use the `Edit` tool to insert each approved patch into its target playbook
   at the section indicated. Preserve surrounding formatting and heading
   levels.
2. Append a one-line entry per approved patch to `00_infra/_changelog.md`
   (create the file if missing). Format:

   ```
   YYYY-MM-DD | <playbook> | <delta_type> | <one-line summary> | <source_url>
   ```

3. After writing, report back: "Applied N patches. Updated M playbooks.
   Changelog updated."

### Step 8 — Verify

Re-read the modified playbook sections (use `Read`) to confirm no formatting
breakage. If a sanity check fails, revert that edit and flag the issue to
the user.

---

## 3. Diff Format (for each proposed patch)

```
─────────────────────────────────────────────────────────
PATCH #N
SOURCE       : <full URL>
PUBLISHED    : <YYYY-MM-DD>
VULN CLASS   : <e.g. SSRF, prototype pollution, OAuth>
DELTA TYPE   : <NEW_BYPASS | NEW_CHAIN | NEW_PRIMITIVE | NEW_DETECTION | TOOL_UPDATE | CVE_PATTERN>

TECHNIQUE SUMMARY (2 lines max)
  Line 1: what the technique does.
  Line 2: what makes it new vs. current playbook coverage.

TARGET PLAYBOOK : <relative path, e.g. 02_vuln_testing/ssrf_playbook.md>
TARGET SECTION  : <heading text the patch lands under, or "NEW SECTION: <name>">
INSERT MODE     : <APPEND | REPLACE_LINES <start>-<end> | NEW_SUBSECTION_AFTER "<heading>">

PROPOSED TEXT BLOCK
```text
<exact markdown to insert, ready to drop into the playbook>
```

NOTES
  <Optional: prerequisites, false-positive risk, related playbooks to also update>
─────────────────────────────────────────────────────────
```

Rules for the proposed text block:

- Use the same heading depth as the surrounding playbook section.
- No emojis. No "Sources:" footer (the changelog tracks that).
- Keep technical density similar to the rest of the playbook — a
  one-paragraph technique with a payload or curl example is the right size.
- If the playbook uses tables, match the table format. If it uses
  numbered checklists, match that.

---

## 4. Quality Bar (hard filter — never override)

A technique passes Learning Mode only if **every** condition is true:

1. **Demonstrated**: a public PoC exists (link, video, curl, payload, repo).
2. **Not duplicated**: no playbook already contains the same primitive,
   bypass, or payload.
3. **Generalizable**: applies to a technique class, not a one-off bug in
   one product (exception: very widely deployed products — top 50 SaaS,
   top 10 CDN/edge, top 10 auth/IdP).
4. **Actionable**: changes what a tester would do — a new param to check,
   a new payload to send, a new chain to attempt, a new tool flag to use.
   Pure "interesting" reads without testing impact are **dropped**.
5. **Recent**: within the user's time bound (default 14 days).

If a candidate fails any of these, do not present it as a patch. Log it in
the run summary as "filtered out, reason: <which clause>" so the user sees
the rejection rate.

---

## 5. Cadence Suggestions

| Cadence | Sources to pull | Typical runtime | Trigger |
|---|---|---|---|
| **Weekly** | Sections 1, 2 (top 5), 4 (tl;dr sec, Bug Bytes), 6 (X timelines of top 5 researchers if accessible) | 10-20 min | Manual: user says "weekly update". |
| **Monthly** | Weekly set + Section 5 (nuclei-templates diff for last 30 days), Section 7 (CISA KEV diff, NVD high-severity for detected stacks) | 30-60 min | Manual: user says "monthly update". |
| **Ad-hoc, category-restricted** | Only sources tagged with the named category (e.g. SSRF → Section 2 PortSwigger + Assetnote + watchTowr posts tagged SSRF, plus reddelexc filtered for SSRF reports) | 5-15 min | User says "learn mode for <X>". |
| **On-target** (during an active engagement) | Section 7 (KEV + trickest/cve) filtered by detected tech from Phase 1 recon; Section 5 nuclei-templates filtered by tech tag | 5-10 min | User says "anything new for <tech>". |

The assistant must not run Learning Mode automatically. It is always
user-initiated.

---

## 6. Don't Pollute Rule

Learning Mode exists to keep playbooks **actionable**, not encyclopedic.
Reject everything that does not change tester behavior, even if it is
interesting.

Specifically:

- Do **not** add "further reading" links, "see also" sections, or curated
  blog rolls into playbooks. Those live in `learning_sources.md`.
- Do **not** add speculative attack chains that have never been demonstrated.
- Do **not** add CVEs without a corresponding detection method or payload.
- Do **not** rewrite existing sections for style — only for new content.
- Do **not** import an entire blog post; extract the testable nugget and
  cite the URL via the changelog.
- If two patches collide on the same playbook section, present them as a
  single combined patch with both source URLs.
- If you are unsure whether a technique is novel vs. an existing playbook
  section, default to **REFINEMENT** under the existing section rather than
  creating a new section.

When in doubt, drop the patch. A playbook that is slightly stale is fine.
A playbook bloated with low-signal content is not.

---

## 7. Run Summary Format

At the end of every Learning Mode run, output:

```
LEARNING MODE RUN — <YYYY-MM-DD>
─────────────────────────────────────────
SCOPE         : <category> / <cadence> / <time bound>
SOURCES TRIED : <N>   (failed: <M>)
ITEMS FETCHED : <N>
PASSED FILTER : <N>
PATCHES PROPOSED : <N>
PATCHES APPLIED  : <N>
PLAYBOOKS TOUCHED: <list>
CHANGELOG ENTRIES ADDED: <N>
─────────────────────────────────────────
REJECTED ITEMS (reason)
  - <title> — filtered: <clause that failed>
  - ...
─────────────────────────────────────────
NEXT SUGGESTED RUN: <weekly / monthly / on-target with <tech>>
```

This summary is the only thing that should be retained in conversation
context after the run — the rest (raw fetched items, filtered candidates)
can be discarded.
