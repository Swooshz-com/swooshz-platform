# Swooshz Platform authenticated operational UI polish

This package contains the final local polish pass for the approved authenticated operational UI study. It is a portable visual reference, not production source. The approved shell, launcher, administration structure, responsive behaviour, typography scale, and interaction contracts remain recognisable.

## Review order

1. Open `evidence/comparisons/final-four-screen-contact-sheet.png` for the final core set.
2. Review the four baseline comparisons in `evidence/comparisons/`.
3. Read `polish-review-v1.md`, then `polish-review-v2.md` for the mandatory refinement record.
4. Read `copy-map.md`, `product-identity.md`, and `polish-rationale.md` for decisions and provenance.
5. Read `manual-review.md` and `evidence-summary.json` for responsive, interaction, accessibility, and repository-safety evidence.
6. Inspect the individual final screens in `evidence/core-v2/` and `evidence/supporting/` at full size.

`evidence/core-v1/` is retained only to show the first polished pass. `evidence/core-v2/` is the final decision set.

## Inspect the prototype

From this directory, serve the files over localhost:

```powershell
python -m http.server 4173
```

Then open:

- Launcher: `http://127.0.0.1:4173/?view=launcher`
- Members: `http://127.0.0.1:4173/?view=members`
- Pending approvals: `http://127.0.0.1:4173/?view=pending`
- Product access: `http://127.0.0.1:4173/?view=access`
- Audit activity: `http://127.0.0.1:4173/?view=audit`
- Launch unavailable: `http://127.0.0.1:4173/?view=launcher&state=unavailable`
- Add-member modal: `http://127.0.0.1:4173/?view=members&modal=add`
- Member action menu: `http://127.0.0.1:4173/?view=members&menu=member`
- Launch keyboard focus: `http://127.0.0.1:4173/?view=launcher&focus=launch`

Stop the local server with `Ctrl+C` when review is complete.

## Source and fixtures

- `index.html`, `styles.css`, and `app.js` are the polished standalone prototype.
- `fixtures/synthetic-fixtures.json` contains local synthetic data only.
- `assets/swooshz-mark.png` is the existing Platform brand mark.
- The product symbol is a study-only inline SVG in `index.html`; its decision record is in `product-identity.md`.
- The local Inter font is bundled under `assets/fonts/`.

No production source copy, hosted product source, dependency directory, browser cache, secret, environment file, cookie, token, real personal data, or Git metadata is included.

## Evidence generation

The checked-in capture scripts expect the repository's already-declared Playwright dependency and an installed Google Chrome browser:

```powershell
node capture-core.cjs v2
node capture-support.cjs
python make-comparison-sheets.py
```

The Browser plugin was attempted first after reinstall but timed out before acquiring a page. The final evidence therefore used Playwright with installed Google Chrome. See `manual-review.md` for the exact limitation and validation findings.

## Package boundaries

- This study remains local and ignored by the Platform repository.
- The approved baseline source is preserved outside this package under `../approved-baseline/`.
- Only the four required before-and-after baseline renders are represented here, inside the comparison sheets.
- No production port, commit, push, pull-request action, or live-system action was performed.
