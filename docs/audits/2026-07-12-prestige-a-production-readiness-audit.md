# Prestige A public site production-readiness audit

Status: implementation and local production-readiness validation complete.
The public-site PR is ready for review. Production launch remains subject to
the pre-existing security and deployment limitations recorded below.

## Scope

- Repository: `Swooshz-com/swooshz-platform`
- Branch: `sol/prestige-a-public-site`
- Base SHA: `567fa25003be840198bea1edc663b46aede11b2f`
- App type: framework-free server-rendered TypeScript/Node full-stack service
- Public routes: `/`, `/solutions`, `/resources`,
  `/resources/platform-launch-boundaries`, `/about`, `/contact`,
  `/request-access`, and `/login`
- Regression scope: `/app` and `/app/admin`
- Security scan: standard repository scan complete (single pass, not deep)
- Live/deployment/private-data work: excluded

## Instruction and requirement sources

- Root `AGENTS.md`
- `docs/agent-playbooks/INDEX.md`
- Baseline, safety-gate, Windows command, Git completion, local docs, and project
  completion playbooks routed by the index
- User production implementation brief in the task
- Approved `prestige-a-final-share` design contract, screenshots, QA summary,
  interaction script, and recording contact sheets
- Current `spacekonceptrental` `PublicSectionScrollAssist.tsx`
- Current `swooshz-quote-auto-generator` product-family tokens
- `docs/frontend-design-readiness.md`
- `docs/frontend-readiness-audit.md`
- `docs/internal-alpha-platform-contract.md`
- `docs/sqag-integration-contract.md`
- `docs/auth-session-security-contract.md`

## Implementation state

- Public routes use `src/http/public-site.ts` and public-only assets.
- `/app` and `/app/admin` retain the existing `platform-shell.ts` renderer.
- Public CSS and JavaScript are not referenced by authenticated shell HTML.
- Homepage scenes use responsive minimum block sizes and expand with content.
- Scroll settling uses native `y proximity` snap as progressive enhancement.
- No wheel interception, `preventDefault` wheel handler, or programmatic
  section-scrolling loop is used.
- Mobile, touch-first, reduced-motion, short viewport, zoom, increased root
  text size, deep-link, focus, selection, and tall-scene states disable settling.
- Approved AVIF/WebP/PNG candidates and local OFL fonts are documented in
  `docs/public-site-asset-provenance.md`.

## SKR comparison

The inspected SKR implementation uses a client-side wheel listener across many
public sections, calls `preventDefault`, chooses one adjacent target, jumps with
`window.scrollTo`, and applies a 780 ms lock. It enables above 900px, disables
for reduced motion and text entry, respects nested scroll containers, and clears
the lock for touch and keyboard input.

The Platform implementation reproduces the one-scene cinematic feel with native
proximity snapping on homepage narrative scenes only. This preserves normal
wheel/trackpad, scrollbar, keyboard, focus, anchor, and touch behavior and avoids
copying SKR's input interception.

## Validation ledger

| Check | Current result |
| --- | --- |
| `npm ci` | PASS |
| `npm run typecheck` | PASS |
| `npm run build` | PASS; public assets copied to `dist/http/public-assets` |
| Focused frontend and adapter tests | PASS, 98/98 |
| Full `npm test` | PASS, 727/727 |
| JavaScript syntax checks | PASS |
| `docker build -t swooshz-platform-prestige-a-qa .` | PASS; production image audit reports 0 vulnerabilities |
| `npm audit --omit=dev` | PASS; 0 vulnerabilities |
| Full `npm audit` | 4 moderate development-only advisories through `drizzle-kit` and older `esbuild`; absent from the pruned runtime image |
| `npm run platform:sqag-smoke-readiness` | PASS; synthetic readiness correctly reports `production_ready=false` without live services |
| Browser screenshot/video matrix | PASS; all required viewport, menu, focus, motion, and authenticated-regression evidence reviewed |
| `/app` and `/app/admin` visual regression | PASS; existing signed-out shells retained on desktop and mobile |
| Standard Codex Security scan | COMPLETE; 83/83 source-like files reviewed, 16 reconciled candidates, 3 reportable availability findings |
| `git diff --check` | PASS before audit closure; rerun as a final gate |

## Browser and interaction evidence

Evidence root: `C:\tmp\swooshz-prestige-evidence`

- Required route screenshots: `screenshots/1440x900/` and
  `screenshots/390x844/`.
- Additional homepage, narrow, short-landscape, menu-open, keyboard-focus,
  reduced-motion, and authenticated-regression captures are under
  `screenshots/`.
- Reviewed videos: `videos/initial-homepage-load.webm`,
  `videos/scroll-down-all-scenes-repaired.webm`,
  `videos/scroll-back-up.webm`,
  `videos/rapid-trackpad-like-scroll-repaired.webm`,
  `videos/keyboard-section-navigation-screencast.webm`,
  `videos/reduced-motion-scroll-repaired.webm`,
  `videos/mobile-free-touch-scroll.webm`, and
  `videos/mobile-menu-interaction.webm`.
- Representative start/25/50/75/end frames and contact strips are under
  `video-frames/`.

Automated browser measurements covered ten routes across eight viewport sizes.
They found no horizontal overflow, empty CTA labels, missing H1s, public-script
leakage into authenticated routes, public-route console errors, or failed public
network requests. Native proximity settling moved at most one scene per tested
gesture, reversed immediately, and bypassed deep-link and focus navigation.

### Visual-defects checklist

- [x] No hero-label, CTA, or artwork collision at required widths.
- [x] No clipped content on short or enlarged compositions.
- [x] No broken intermediate reveal frame in reviewed video samples.
- [x] Mobile menu focus lifecycle is correct.
- [x] Reduced-motion content starts visible and scrolls freely.
- [x] Mobile remains ordinary touch scrolling with no scene settling.
- [x] Sticky-header offsets preserve anchored and focused targets.
- [x] `/app` and `/app/admin` retain their prior visual shell.
- [x] No confirmed major visual defect remains.

The in-app Browser connection timed out twice during setup. The approved
Playwright fallback was used for the production-like browser matrix and all
resulting evidence was manually reviewed.

## Security result

Readable standard-scan report:

`C:\Users\xPass\AppData\Local\Temp\codex-security-scans\swooshz-platform\567fa25003be840198bea1edc663b46aede11b2f_20260711T223036Z\report.md`

No reportable issue was introduced by the Prestige A public-site diff. Three
pre-existing availability/resource findings survived repository-wide gates:

| Priority | Finding | Boundary |
| --- | --- | --- |
| P2 / medium | Anonymous auth start can create unbounded persistent `auth_states` rows | Pre-existing authentication/backend path |
| P3 / low | Pre-routing mutation-body reads rely on lower-layer timing defaults | Pre-existing Node HTTP adapter/server path |
| P3 / low | Authenticated CSRF issuance can create unbounded persistent token rows | Pre-existing session/backend path |

Thirteen additional candidates were rejected or marked not applicable with
counterevidence preserved in canonical coverage. These findings were not fixed
because this implementation explicitly excludes changes to OIDC, sessions,
CSRF, database behavior, and API contracts. They remain production-launch
limitations requiring separately scoped backend work.

## Production-boundary review

- Public rendering and assets are isolated in public-only helpers and modules.
- Authenticated portal/admin renderer and browser JavaScript are unchanged.
- No OIDC, session, cookie, CSRF, workspace, membership, role, entitlement,
  launch-token, product-proxy, database, admin-action, or API-contract behavior
  was intentionally modified.
- No prototype directory, evidence capture, or scan bundle is intended for
  commit.

## Findings and limitations

| Severity | Finding | Status |
| --- | --- | --- |
| P2 | Pre-existing anonymous auth-state resource allocation | Open for separately scoped backend remediation; blocks an unconditional production-launch claim, not review of this visual-only PR. |
| P3 | Pre-existing slow request-body timing policy | Open for separately scoped server-hardening work. |
| P3 | Pre-existing authenticated CSRF row allocation | Open for separately scoped backend remediation. |
| P3 | Four moderate development-only advisories under `drizzle-kit`/older `esbuild` | Runtime/pruned image is unaffected; track through a compatible tooling upgrade. |
| Informational | In-app Browser connection unavailable | Closed through the documented Playwright fallback and manual evidence review. |

## Release gates

The public-site branch is PR-ready once final diff review, repeated closing
checks, commit, push, and CI verification complete. There is no unresolved P0
or P1 finding, and no reportable finding was introduced by Prestige A. This
audit does not represent production-launch approval while the three explicitly
recorded pre-existing findings and deployment controls remain unresolved.
