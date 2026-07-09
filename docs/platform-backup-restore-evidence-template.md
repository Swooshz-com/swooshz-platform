# Platform Backup/Restore Evidence Template

Production readiness is not approved. This template is not backup evidence, restore evidence, hosted smoke evidence, or launch approval. It exists so future operator evidence can be recorded in a sanitized, evidence-based shape after an approved restore test.

Do not commit backup exports, database URLs, provider console screenshots, private storage paths, table dumps, private identities, product runtime data, cookies, tokens, secrets, or exact hosted endpoints.

## Evidence Record Template

Fill real operational details outside this repo. If a sanitized copy is later committed, keep placeholders or opaque evidence ids only.

| Field | Sanitized value |
| --- | --- |
| Evidence id | `<evidence-id>` |
| Environment category | `<internal-alpha-or-production-candidate>` |
| Backup owner role | `<backup-owner-role>` |
| Restore approver role | `<restore-approver-role>` |
| Restore operator role | `<restore-operator-role>` |
| Backup artifact reference | `<opaque-backup-artifact-reference>` |
| Backup retention class | `<retention-class>` |
| Restore target category | `<isolated-restore-target-category>` |
| Restore command category | `<provider-approved-restore-command-category>` |
| Migration state category before restore | `<ready-or-schema-not-ready-or-not-checked>` |
| Migration state category after restore | `<ready-or-schema-not-ready-or-not-checked>` |
| Application health category after restore | `<health-pass-or-health-fail-or-not-run>` |
| Auth/admin smoke category after restore | `<pass-or-fail-or-not-run>` |
| Swooshz Quote Auto Generator handoff category | `<manual-or-approved-handoff-pass-or-not-run>` |
| Restore result | `<pass-or-fail>` |
| Reviewer role | `<reviewer-role>` |
| Follow-up decision | `<fix-forward-or-restore-or-no-action>` |

## Required Checks Before Evidence Can Count

- Backup owner and restore owner are approved.
- Restore target is isolated from the production runtime.
- Backup artifact reference is opaque and contains no connection details.
- Restore process is provider-approved.
- Platform DB readiness is checked after restore when a database target is involved.
- `/healthz` is checked only as adapter reachability, not full launch proof.
- Auth/admin smoke is run only after hosted smoke is separately approved.
- Swooshz Quote Auto Generator remains separate; Platform evidence cannot prove product runtime readiness.
- Evidence is reviewed for secrets, table data, provider payloads, raw IDs, private paths, private domains, private IPs, cookies, tokens, screenshots, and backup exports before any sanitized note is committed.

## What This Template Must Not Become

- It must not become fake backup evidence.
- It must not include fake timestamps, fake providers, fake owners, fake test results, fake domains, fake IPs, fake emails, fake table counts, or fake restore logs.
- It must not approve hosted deployment.
- It must not approve production readiness.
- It must not replace the final go/no-go checklist.

Backup/restore execution remains unchecked until real sanitized restore evidence exists.
