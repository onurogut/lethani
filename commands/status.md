---
description: Show status across engagements or for one target — phase progress, findings, next step
argument-hint: [target-or-empty]
---

If `$1` is empty: list every directory under `engagements/`, for each one
print:

```
<target>  Phase: <highest-completed>  Findings: <n CRITICAL / n HIGH / n MED / n LOW>  Next: <suggested next command>
```

Phase detection rules:
- `scope.md` exists → Phase 0 done
- `recon/_summary.md` exists → Phase 1 done
- `scans/_summary.md` exists → Phase 2 done
- `findings.md` non-empty → Phase 3 in progress / done
- `chain:` entries in `findings.md` → Phase 4 done
- `report.md` exists → Phase 5 done

If `$1` is a target name: print the same row plus a recent activity log —
the last 10 lines of `notes.md` and any P1/Critical findings inline.

Do not start any work. This is read-only.
