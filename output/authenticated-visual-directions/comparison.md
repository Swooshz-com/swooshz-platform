# Authenticated Visual Directions Comparison

Status: local-only design-study evaluation. This document does not approve a production port.

Package note: this tracked package retains the selected Direction B prototype and its contact sheets. The complete multi-direction raw evidence remains local-only and is not part of this package.

## Scope And Evidence

- Inspected `origin/main`: `699c04d26585a52bde1ad0d2a157fe266a950ceb` (`Port Prestige A to the Swooshz public website`).
- Reviewed the current `/app` and `/app/admin` renderers, browser scripts, responsive CSS, route contracts, session-context service, workspace-admin service, HTTP tests, and admin-route test fixtures.
- Reviewed merged Prestige A source extracted from `origin/main` only into this ignored study directory: `src/http/public-site.ts`, `src/http/public-assets/public-site.css`, and `src/http/public-assets/public-site.js`.
- Current-renderer baseline snapshots were captured using the compiled renderer with local `.example` API fixtures only: `evidence/current-renderer/app-renderer-shell.png` and `evidence/current-renderer/admin-renderer-shell.png`.
- Prototype evidence is local file-based Playwright Chromium output. It makes no network request to a provider, database, production service, or external API.

## Shared Product Truth

All directions reflect the implemented product boundary, not label-inferred functionality:

- `/app` is an authenticated workspace launcher. It exposes safe signed-in identity, active workspace membership, app summaries/access, launch, logout, loading, unavailable access, no-workspace, no-app, and unauthenticated states.
- `Swooshz Quote Auto Generator` is the customer-facing app name. No SQAG, SAQG, KQAG, AutoQuote, or SKR product claim is present.
- `SEO / GEO / Seozilla` remains unavailable with a vendor-pending state. It has no launch control.
- `/app/admin` is owner/admin-only and is limited to member management, pending access approvals, SQAG entitlement enable/disable, and bounded safe audit browsing.
- The studies do not add billing, invitations/email delivery, owner transfer, bulk actions, password resets, editable audit history, new roles, product workflow data, or account/security administration.

## State Coverage

The local prototype supports these URL-addressable study states and interactive transitions:

| Surface | Covered states |
| --- | --- |
| Launcher | Session loading, unauthenticated, signed-in owner, signed-in member, one workspace, multiple workspaces, workspace switch, available launch, launch loading, launch failure/retry, unavailable entitlement, vendor pending, no workspace, no registered apps, logout. |
| Administration | Loading, permission denied, workspace summary, members, long members, owner protection, empty members, pending approvals, approval revocation confirmation, app access, entitlement confirmation, bounded audit browsing with functional Older/Newer pagination, action menu, add-member modal, destructive confirmation, busy action, safe local success feedback, generic local failure feedback. |
| Accessibility | Landmarks, skip link, visible focus, keyboard navigation, Escape close, modal focus entry/restoration and Tab containment, action-menu Escape close, aria-expanded state, live status region, colour-plus-text status labels, reduced-motion CSS, and mobile touch-sized controls. |

## Direction Evaluation

Scores are comparative study ratings on a five-point scale, not production readiness claims.

| Criterion | A - Editorial Operations | B - Precision Workspace | C - Product Gallery Workspace |
| --- | --- | --- | --- |
| Brand continuity with Prestige A | 5 | 4 | 4 |
| Distinctiveness | 4 | 4 | 5 |
| Launcher clarity | 4 | 4 | 5 |
| Admin usability | 3 | 5 | 4 |
| Information hierarchy | 5 | 4 | 4 |
| Operational density | 2 | 5 | 3 |
| Long-session comfort | 5 | 4 | 3 |
| Mobile quality | 4 | 4 | 4 |
| Accessibility and state clarity | 4 | 4 | 4 |
| Interaction quality | 4 | 4 | 4 |
| Scalability to future applications | 3 | 5 | 4 |
| Production implementation complexity | 3 | 4 | 3 |
| Risk of generic SaaS UI | Low | Medium | Medium |

## Direction A - Editorial Operations

### Strongest Qualities

- Treats the workspace as an editorial context before presenting actions. The warm paper rail, wide canvas, engraved rules, and deliberately large functional rows feel related to Prestige A without copying its cinematic scenes.
- The application rows read as a calm operational ledger rather than as a generic card wall.
- The admin treatment gives identity, workspace scope, and owner protection generous breathing room, which should help infrequent or high-consequence actions.

### Weakest Qualities

- The generous vertical cadence reduces the number of members and activity rows visible at once.
- It is the least efficient option for an administrator who spends many consecutive hours scanning long lists.

### Production Risks

- Requires careful responsive tuning to preserve its hierarchy without wasting critical mobile viewport height.
- Serif emphasis must remain limited to section hierarchy; applying it to dense data would reduce scanning speed.

## Direction B - Precision Workspace

### Strongest Qualities

- Has the clearest repeated-admin workflow: compact persistent rail, strict horizontal alignment, table-forward density, compact tabs, and restrained status treatment.
- The dark navy control rail creates a strong operational anchor while paper surfaces preserve long-session comfort.
- It scales cleanly as more registered applications or activity entries are added, without inventing navigation destinations.

### Weakest Qualities

- The launcher is clearly functional but emotionally quieter than Direction C.
- The visual discipline can drift into familiar SaaS territory if future work adds rounded cards, broad shadows, or generic dashboard widgets.

### Production Risks

- Its density needs a real-data pass with the longest member names, translated strings if relevant, and several pages of audit rows.
- The navy rail and compact controls need contrast and focus regression tests in the production shell rather than visual-only acceptance.

## Direction C - Product Gallery Workspace

### Strongest Qualities

- Makes the app launcher unmistakable: Swooshz Quote Auto Generator is a focused product object, its separate-launch boundary is clear, and the unavailable vendor product is visibly non-actionable.
- The product-led launcher gives the authenticated experience a stronger identity while retaining a compact, usable admin mode.
- It is the clearest choice if more approved applications eventually need distinct, truthful identities rather than uniform tiles.

### Weakest Qualities

- The featured product panel consumes more vertical space than A or B, particularly on short screens.
- The gallery emphasis must not lead to marketing-card proliferation as product count grows.

### Production Risks

- Needs explicit layout rules for three or more available applications before adoption; the current single-primary-product composition should not automatically repeat into a grid.
- Product-specific visual treatment needs a real app registry contract, not arbitrary illustrations or availability claims.

## Known Defects And Deliberate Limits

- These are local static studies with synthetic state. They do not call existing APIs, issue CSRF tokens, launch products, or persist admin actions.
- Generic local errors are intentionally not coupled to server event references because no server action occurs. A production port must preserve the existing safe error contract and logging correlation requirements.
- The study uses the approved Manrope/Fraunces relationship through local/system font declarations but does not copy production font files. A real port must consume the approved local public font assets only after the existing provenance/licensing process.
- Contact sheets are visual review artifacts, not a substitute for a real authenticated UAT run against a safe non-production environment.
- The workspace switcher is a local context demonstration. Production selection must continue to use the existing session-context and admin-slug behavior without changing authorization or persistence semantics.

## Responsive And Accessibility Review

- Captured and reviewed at 1440 x 900, 1366 x 768, 1024 x 768, 768 x 1024, 390 x 844, 320 x 844, and 844 x 390 across all directions.
- `evidence/evidence-summary.json` records no horizontal overflow in the captured states, including long content and 320px action-menu transformations.
- Mobile member, approval, and audit tables transform into labelled row stacks. The only deliberately scrollable mobile control is the compact contextual admin tab strip where labels remain visible.
- Automated local browser checks passed for mobile navigation open/Escape focus restoration, add-member modal focus entry/Escape restoration, member action-menu Escape close, and bounded audit paging.
- Reduced-motion screenshots exist for desktop and mobile per direction. All functional content remains present with animation effectively disabled.

## Packaged Evidence

- Direction B desktop contact sheet: `evidence/direction-b-desktop-contact-sheet.png`.
- Direction B mobile contact sheet: `evidence/direction-b-mobile-contact-sheet.png`.
- The complete screenshots, recordings, recording-frame sheet, and browser-validation JSON remain local-only and are intentionally excluded from this lean package.

## Advisory Recommendation

Recommend **Direction B - Precision Workspace** for a future implementation decision. It makes the existing admin surface materially easier to scan and operate over long sessions, scales to future registered applications without creating unfinished navigation, and retains Prestige A through paper, navy, teal, fine rules, and controlled typography.

This is advisory only. Do not combine it with Direction A or Direction C, and do not port it into the production renderer without a separately approved implementation scope.
