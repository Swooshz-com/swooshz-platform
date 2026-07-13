# Swooshz Platform Prestige A design contract

Status: selected visual reference. This contract guides a future production port; it does not authorize production integration.

## Brand character

Prestige A is bright, editorial, calm, and assured. It should feel broader and more brand-led than an operational product UI while remaining clearly related to SQAG. Quality comes from scale, typography, material depth, disciplined spacing, and a small number of strong scenes.

The voice is concise and customer-facing: one trusted entry, an approved workspace, and focused Swooshz applications launched separately.

## Typography roles

- Functional sans: Manrope. Use for navigation, body copy, labels, controls, and most display text.
- Editorial accent: Fraunces italic. Restrict to one phrase in a hero or major transition. Never use for body copy, navigation, or dense interface text.
- Display hierarchy: large, tightly tracked, controlled line lengths. Mobile may wrap into more lines but must preserve readable phrases.
- Body copy: minimum 15px on mobile and 16px on desktop, with generous line height.
- Production use of both local prototype fonts requires owner approval and a fresh licensing/provenance check.

## Colour roles

- Cool paper canvas: #f5f6f2.
- Warm paper depth: #ece9e1.
- Primary ink: #09253d.
- Deep navy stage: #061a31.
- Functional teal: #0f766e. Use for connections, selected emphasis, and short labels.
- Muted text: #5e6e76.
- Keyboard focus: #e3a92d.
- White is a light surface and dark-stage text colour, not a default card fill.

Keep teal precise and navy concentrated. Do not spread equal amounts of colour across every section.

## Surface and material language

The core material is precision paper and ink: cool and warm paper variation, fine grain, engraved lines, soft directional light, and restrained depth. The dark scene should feel like rich ink, not cyber-security software.

Use overlap and cropping before shadows. Avoid generic glass cards, glossy gradients, floating dashboard panels, and flat blue-grey bands.

## Layout and spacing

- Prefer full-bleed or near-full-bleed visual fields.
- Use asymmetry, negative space, and deliberate crop rather than a stack of centred containers.
- Keep sections few and substantial. A scene should have one dominant idea.
- Preserve clear foreground, midground, and background.
- Align important text and controls to a stable editorial grid.
- Avoid repeated eyebrow + heading + three-card patterns.

## Signature visual rules

The folded paper monument represents entry, context, and forward focus. It must remain a dominant first-viewport object, not a small illustration beside the headline.

- Preserve its paper, navy, and teal relationship.
- Crop it intentionally per viewport.
- Do not add fake UI, product data, dashboards, logos, or text inside the asset.
- Decorative index labels may appear on desktop but must disappear when they interfere with mobile or landscape composition.
- Supporting pages may use close crops, edge details, or related paper planes; do not repeat the full hero monument everywhere.

## Motion principles

- Motion clarifies hierarchy and continuity; it is not a visibility gate.
- Initial order: eyebrow, headline lines, support copy and CTA, then the monument resolves.
- Essential content remains readable in the first frame.
- Use transform, opacity, clip-path, and CSS custom properties.
- Pointer response is fine-pointer only, limited to a few pixels, and resets on pointer leave, cancellation, blur, page hide, and tab return.
- Scroll-linked progress must work in both directions and tolerate rapid reversal.
- Avoid generic fade-up animation on every section.

## Reduced motion

With `prefers-reduced-motion: reduce`:

- All essential content is immediately visible.
- Decorative parallax and animated cues stop.
- Hero progress remains 0 at the top and is not forced to a later scroll state.
- The bridge and downstream scenes remain complete as static compositions.
- Navigation and focus behavior remain unchanged.

## Navigation behaviour

Use semantic site navigation and a disclosure button on viewports up to 900px.

- Closed mobile navigation is `inert`, `aria-hidden="true"`, visually hidden, and excluded from Tab order.
- Opening sets `aria-expanded="true"`, removes hidden/inert state, locks background scrolling, and moves focus to the first navigation link.
- Escape closes and restores focus to the trigger.
- Activating a navigation link closes without stealing destination focus.
- Outside pointer activation may close and restore focus.
- Resizing to desktop clears stale open state and restores normal navigation semantics.
- Orientation changes close and unlock the disclosure.
- Do not add application-menu roles or modal focus trapping.

## Desktop and mobile composition

Desktop:

- The first viewport balances a monumental text block with the large paper monument.
- The primary CTA must remain fully visible at 1440 x 900 and 1920 x 900.
- The index ledger may remain as a quiet secondary layer.

Mobile:

- Recompose, do not simply stack.
- Keep the headline, support copy, CTA, handoff link, and recognisable monument in the first 390 x 844 viewport.
- At 320px, preserve the CTA and artwork even when the headline gains lines.
- Hide the index ledger at 720px and below.
- At landscape mobile, tighten typography and spacing, keep the CTA fully visible, and introduce the artwork at the lower edge.
- Use the disclosure navigation through tablet widths.

## Route extension

| Route | Direction |
| --- | --- |
| Home | Full monument hero, account -> workspace -> product story, restrained dark platform scene. |
| Solutions | Editorial product chapters with one dominant application visual per chapter; SQAG primary, planning-only products secondary. |
| Resources | Bright reading-led index with strong titles and restrained material thumbnails; avoid a uniform card wall. |
| Resource article | Calm editorial column, generous type, useful in-page navigation, minimal decorative motion. |
| About | Brand narrative using material details and larger editorial transitions rather than corporate metric blocks. |
| Contact | Short, reassuring route with one clear contact path and minimal visual interruption. |
| Request Access | Focused form scene with explicit workspace/access expectations; no public-signup language. |
| Login | Quiet trusted-entry composition with the monument or paper edge as supporting context, never a security dashboard. |

## Anti-patterns

Do not reintroduce generic SaaS cards, equal three-column grids, dark cyber styling, terracotta, purple gradients, tiny dashboard panels, excessive glassmorphism, generic fade-up sequences, fake screenshots, fake metrics, fake customers, pricing, billing, public signup, or unavailable-product purchase cues.

## Production-port constraints

- Port the visual and interaction contract, not the temporary file structure.
- Do not import prototype CSS wholesale or replace the server-rendered shell without a separate approved implementation task.
- Preserve existing route, authentication, API, and product boundaries.
- Platform launches SQAG separately; quote workflow and runtime data remain in SQAG.
- SEO / GEO / Seozilla remains unavailable and vendor-pending.
- Keep assets and fonts local to the production build only after approval and provenance review.
- Add production tests for menu focus, inert state, Escape, scroll lock, breakpoint cleanup, reduced motion, overflow, and critical viewport composition.
- No external runtime dependency is required for this direction.