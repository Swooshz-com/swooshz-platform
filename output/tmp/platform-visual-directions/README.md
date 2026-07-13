# Swooshz Platform visual directions

Temporary, tracked homepage exploration. This package is intentionally outside the production frontend and does not import the server-rendered shell, call Platform APIs, or change route contracts.

## Required cleanup after a direction is chosen

This package exists only to preserve the comparison across devices. Do not ship its files wholesale.

1. Record the selected direction and rationale in the production implementation task or pull request.
2. Reimplement only approved changes in the production source locations.
3. Retain only evidence or provenance required for that implementation.
4. Delete this entire `output/tmp/platform-visual-directions/` folder in a dedicated cleanup commit.

The supplied reference images, recordings, and `prestige-a-final-share.zip` archive remain here only for review portability and must be removed with the temporary package.

## Open locally

- `index.html` - comparison index
- `direction-a/index.html` - editorial product platform
- `direction-b/index.html` - connected workspace ecosystem
- `direction-c/index.html` - bold product-led direction

Each direction is self-contained with its own `styles.css` and `script.js`. The only JavaScript is the responsive navigation menu.

## Direction notes

### A / Editorial product platform

Calm, spacious, asymmetrical, and typographic. It uses a warm paper canvas, navy ink, and restrained teal to tell the Platform story through a paper-stack hero and fewer, stronger sections. This route feels the most premium and brand-led.

### B / Connected workspace ecosystem

The workspace network is the hero anchor. Account, workspace, membership context, and approved applications become visible nodes with directional movement. It is the clearest explanation of the Platform model and has the strongest interaction affordance without becoming a security-monitoring interface.

### C / Bold product company

The most expressive route. High-contrast navy, cream, and teal bands frame a large document-inspired form, giving Swooshz Quote Auto Generator a clear presence without inventing product UI. It is memorable and product-led, with the highest art-direction risk.

## Evaluation

| Criterion | A / Editorial | B / Ecosystem | C / Bold product |
| --- | --- | --- | --- |
| First impression | Calm, premium, confident | Clear, active, connected | Memorable, dramatic |
| Brand distinctiveness | High through typography and paper geometry | High through node language and signal paths | Highest through document/signal signature |
| Relationship to SQAG | Strong cool near-white, navy, teal family | Strongest functional relationship to product access | Strong color family, more art-directed |
| Customer clarity | Very clear after the hero | Clearest overall explanation | Clear but more narrative |
| Visual polish | High and restrained | High with more visible motion | High but depends on disciplined art direction |
| Responsive behavior | Editorial composition compresses well | Network needs careful mobile balance | Document remains a strong mobile anchor |
| Accessibility | Strong contrast and plain-language hierarchy | Good contrast; motion should respect reduced-motion | Strong contrast; oversized type needs viewport testing |
| Maintainability | Straightforward CSS composition | More custom geometry and interaction states | Straightforward but more art-directed CSS |
| Production implementation | Easiest | Moderate | Moderate |
| Remaining-page suitability | Strong for public and portal surfaces | Strong for workspace/admin surfaces | Strong for a campaign or product-led entry surface |
| Future admin branding | Calm foundation with room for dense surfaces | Natural extension into workspace/admin | Needs a calmer companion system for admin |

## Recommendation

Direction A is the strongest overall starting point for production exploration. It is the best balance of customer clarity, premium brand feeling, maintainability, and a believable bridge to the existing SQAG visual family. Direction B is the strongest alternate if the primary goal is to make the account-to-workspace-to-app relationship immediately legible. Direction C is the most distinctive campaign-like route, but it carries the largest risk of making the Platform feel like a visual statement before it feels like a reliable shared starting point.

This recommendation is only for the prototype comparison. No production integration is included.

## Typography and licensing

The original three directions use the system UI stack: `Inter`, `ui-sans-serif`, `system-ui`, `-apple-system`, `BlinkMacSystemFont`, and `"Segoe UI"`. The later Prestige A study includes local Manrope and Fraunces assets with their OFL license texts under `prestige-a-final-share/prototype/assets/fonts/`. Those assets are temporary study material, not a production font decision. Any production font choice requires an explicit license and performance review.

## Generated reference boards

Generated reference boards informed these directions but are not linked by the browser prototypes.

## Evidence package

The intended evidence paths are documented in `evidence/README.md`. Screenshots and contact sheets in this package are temporary review artifacts and must be removed when the selected direction is implemented.
