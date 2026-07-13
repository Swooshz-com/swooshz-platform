# Product identity decision

## Existing assets inspected

The asset search was read-only and excluded dependencies, build output, generated caches, and test-only synthetic images.

Platform asset inspected:

- `src/http/public-assets/swooshz-mark.png`
- SHA-256: `5A272D5BD2EF8AD68252E7AB9CB24864391A6946A75F6B6977DC36C119037B82`

SQAG asset inspected:

- `webapp/static/assets/swooshz-mark.png`
- SHA-256: `5A272D5BD2EF8AD68252E7AB9CB24864391A6946A75F6B6977DC36C119037B82`
- Local repository worktree inspected read-only on `codex/amend-pr-112-db-verifier` at `1d5379e21340b2e22ebf04df70f693de6ae79bbb`; no SQAG file was changed.

Both repositories contain the same first-party Swooshz brand mark. Neither repository contains a separate approved product icon, quotation-document mark, or product-specific logo in the searched raster/vector asset set. The only other matching SQAG image was a synthetic pricing-catalog fixture and was unrelated.

## Provenance and licensing conclusion

The Swooshz mark has clear first-party repository provenance and identical bytes across Platform and SQAG, but it is a company/platform identity mark rather than a distinct product mark. No separate asset-specific licence or approval record for a product icon was found in the inspected sources.

The final product symbol therefore uses no copied external artwork and no unrelated repository logo. It is a new local-study-only inline SVG authored for this prototype.

## Final mark decision

Decision: **study-only inline SVG quotation sheet**.

The symbol combines:

- A folded document edge.
- Three structured line-item rules.
- A precise calculation column.
- A heavier teal total rule.
- Deep navy outline with controlled teal detail.

It appears at 52px inside a 76px desktop identity surface and at 34px without a decorative stage on mobile. It supports recognition but remains subordinate to `Swooshz Quote Auto Generator`.

The actual Swooshz mark remains in the application bar where it correctly identifies the Platform.

## Approval status

- Swooshz brand mark: existing first-party asset, reused only for Platform identity.
- Quotation-sheet product symbol: not an approved production asset; study-only pending product/brand-owner review.
- External assets or downloaded icon libraries: none.

## Accessibility and small-size behaviour

- The product symbol is decorative because the full product name is adjacent; each inline SVG uses `aria-hidden="true"` through its container.
- Product recognition and state never rely on the symbol alone.
- Navy and teal line geometry remains distinguishable on the light material at 34px and 52px.
- The mobile version removes the outer icon stage and keeps the product name/description at full content width.
- The icon does not carry status colour; access state remains explicit text with a separate status dot.
- The total rule and calculation column remain visible at the captured mobile size, as shown in `evidence/comparisons/product-icon-detail-sheet.png`.

## Rejected alternatives

- Reusing the Swooshz mark as the product icon: rejected because it conflates company/platform identity with product identity.
- A generic file outline: rejected because it does not distinguish quotation work.
- A large letterform: rejected because it would dominate the operational surface and read as a decorative monogram.
- AI sparkles: rejected because the interface does not need a generic AI visual claim.
- Coins, carts, invoice stamps, or ecommerce imagery: rejected because they imply unsupported billing, retail, or accounting workflows.
- A detailed illustration: rejected because it would weaken small-size clarity and move the launcher toward marketing composition.
