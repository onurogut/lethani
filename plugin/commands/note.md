---
description: Append a timestamped note to an engagement's notes.md, or show the last 10 lines if no text is given
argument-hint: <target> [free-form note text]
---

Append a single note to `engagements/$1/notes.md` with the format:

```
[YYYY-MM-DD HH:MM] <rest of the arguments after $1>
```

Behavior by arguments:

### `/note <target>` (no body)

- If `engagements/<target>/notes.md` exists: print the last 10 lines.
- If it does not exist: tell the operator the engagement does not exist
  yet and suggest `/new-target <target>`.

### `/note <target> <text...>`

- Validate that `engagements/<target>/` exists. If not, refuse with:
  > Engagement `<target>` not found. Run `/new-target <target>` first.
- Use the `Edit` tool to append `[YYYY-MM-DD HH:MM] <text>\n` to
  `engagements/<target>/notes.md`. Append; never overwrite.
- Confirm with a single line:
  > Noted at HH:MM for `<target>`.

### Rules

- Notes are append-only. Never delete or modify existing lines from this
  command — that is what `notes.md` open-in-editor is for.
- Do not scaffold a missing engagement — be explicit, refuse, suggest
  `/new-target` instead. Quick `/note` is meant to be a one-keystroke
  flow during active work, not a setup path.
- Time format: `YYYY-MM-DD HH:MM` (local time). Use the system clock.
- If the operator's text contains backticks or markdown that breaks
  rendering, escape minimally; do not rewrite their wording.

### Example

```
/note acme stored XSS confirmed on /profile/about, payload survives sanitizer
```

Appends:

```
[2026-05-12 18:42] stored XSS confirmed on /profile/about, payload survives sanitizer
```

to `engagements/acme/notes.md` and replies "Noted at 18:42 for `acme`."
