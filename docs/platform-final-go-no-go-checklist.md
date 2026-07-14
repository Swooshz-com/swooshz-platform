# Platform Final Go/No-Go Checklist

Production readiness is not approved. This checklist is owner and evidence planning only. It does not deploy, configure DNS/TLS/OAuth, add secrets, run hosted smoke, approve legal/compliance, or approve production launch.

The checklist must remain unchecked until every launch-critical gate has evidence. Fill actual owners, providers, domains, identities, secrets, and approval records outside this repo. Sanitized repo updates may reference only placeholder roles, evidence ids, route names, status categories, and non-secret env names.

## Required Owner Placeholders

| Area | Required placeholder |
| --- | --- |
| Final launch approver | `<final-launch-approver-role>` |
| Platform technical owner | `<platform-technical-owner-role>` |
| Shared Hostinger/Coolify owner | `<shared-hosting-owner-role>` |
| DNS/TLS owner | `<dns-tls-owner-role>` |
| OAuth/provider owner | `<oauth-provider-owner-role>` |
| Secret rotation owner | `<secret-rotation-owner-role>` |
| Backup/restore owner | `<backup-restore-owner-role>` |
| Monitoring/logging owner | `<monitoring-logging-owner-role>` |
| Incident owner | `<incident-owner-role>` |
| Legal/compliance reviewer | `<legal-compliance-reviewer-role>` |
| Swooshz Quote Auto Generator handoff reviewer | `<sqag-handoff-reviewer-role>` |
| SKR hosting-readiness reviewer | `<skr-hosting-reviewer-role>` |

## Go/No-Go Gates

- [ ] PR-reviewed Platform code and docs are merged into `main`.
- [ ] Shared Hostinger/Coolify foundation exists and is confirmed shared across Platform, Swooshz Quote Auto Generator, and SKR.
- [ ] DNS/TLS baseline is approved outside repo.
- [ ] Hosted Platform app is created in the reviewed hosting environment.
- [ ] Hosted env and secret names are present in the approved secret store without values in repo notes.
- [ ] Hosted OAuth/provider configuration is completed outside repo.
- [ ] Hosted env readiness check passes with sanitized categories only.
- [ ] Hosted DB readiness check returns `ready` with sanitized categories only.
- [ ] Manual migration procedure is approved, and no automatic build/start/deploy/restart/health migrations are configured.
- [ ] CSRF success and denial smoke is complete with route names and status categories only.
- [ ] Session cookie, logout, expiry, and membership-removal revocation smoke is complete without cookie/session values.
- [ ] Rate limiting or explicit short-term risk acceptance is reviewed for hosted launch.
- [ ] Hosted security-header review is complete after proxy/app configuration.
- [ ] Dependency/security audit cadence and first result are recorded without secret output.
- [ ] Secret rotation owner, routine rotation plan, and emergency revoke plan are approved.
- [ ] Backup owner, restore owner, restore target, and restore/fix-forward decision are approved.
- [ ] Sanitized backup/restore test evidence exists.
- [ ] Monitoring/logging owner, log retention, alert destination, and incident escalation path are approved.
- [ ] Secret-safe hosted log review is complete.
- [ ] Legal/compliance placeholders are replaced by approved privacy, terms or usage rules, retention, removal, and vendor/subprocessor decisions.
- [ ] Swooshz Quote Auto Generator remains a separate launched app, and Platform does not own product workflow/runtime data.
- [ ] Hosted Platform-to-Swooshz Quote Auto Generator launch handoff remains manual or has approved cross-host session/cookie strategy and smoke evidence.
- [ ] SKR remains separate from Platform and has its own hosting-readiness evidence.
- [ ] SEO/GEO/Seozilla remains absent from customer-facing Platform surfaces unless separately approved under a future product contract.
- [ ] No billing, payment, upgrade, plan, or credits flow is introduced before approval.
- [ ] Final launch decision is recorded by the final launch approver outside repo.

## Non-Go Conditions

Any one of these keeps the decision at no-go:

- Hosted deployment does not exist or is not reviewed.
- DNS/TLS is not approved.
- Hosted OAuth/provider setup is missing.
- Hosted smoke is missing.
- Backup/restore evidence is missing or fake.
- Monitoring/logging/incident owner is missing.
- Legal/compliance approval is missing.
- Secrets, cookies, tokens, provider material, database URLs, private paths, private identities, table data, backup exports, or product runtime data appear in repo notes or screenshots.
- Platform stores or embeds Swooshz Quote Auto Generator product workflow/runtime data.
- Shared Hostinger/Coolify foundation becomes Platform-only.
- Final go/no-go owner is not approved.

## Recommended Next Move

If SQAG and SKR are both hosting-ready, proceed to shared Hostinger/Coolify foundation planning.

Otherwise continue only non-hosted Platform governance work or return to the app that still blocks shared hosting.
