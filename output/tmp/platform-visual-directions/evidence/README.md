# Browser evidence checklist

Use consistent viewport sizes for comparison:

- Desktop full page: 1440 x 900
- Desktop first viewport: 1440 x 900, captured at scroll position 0
- Mobile full page: 390 x 844
- Mobile first viewport: 390 x 844, captured at scroll position 0
- Mobile menu open: 390 x 844 after activating the menu button
- Spot checks: 320px mobile, 768px tablet, and 1920px desktop

Expected screenshot names:

```text
evidence/screenshots/direction-a-desktop-full.png
evidence/screenshots/direction-a-desktop-first.png
evidence/screenshots/direction-a-mobile-full.png
evidence/screenshots/direction-a-mobile-first.png
evidence/screenshots/direction-a-mobile-menu.png
evidence/screenshots/direction-b-desktop-full.png
evidence/screenshots/direction-b-desktop-first.png
evidence/screenshots/direction-b-mobile-full.png
evidence/screenshots/direction-b-mobile-first.png
evidence/screenshots/direction-b-mobile-menu.png
evidence/screenshots/direction-c-desktop-full.png
evidence/screenshots/direction-c-desktop-first.png
evidence/screenshots/direction-c-mobile-full.png
evidence/screenshots/direction-c-mobile-first.png
evidence/screenshots/direction-c-mobile-menu.png
```

Expected comparison sheets:

```text
evidence/contact-sheet-desktop.png
evidence/contact-sheet-mobile.png
```

The pages themselves are dependency-free static HTML. Browser capture can use an already-installed local browser automation runtime; no browser runtime is imported by the prototypes.

QA checklist:

- Full page renders without horizontal overflow at 1440, 1920, 768, 390, and 320px widths.
- Each mobile menu opens, exposes all primary links, and closes after a link is selected.
- Menu button exposes `aria-expanded` and `aria-controls`.
- Keyboard focus is visible for links and the menu button.
- No primary CTA is blank or decorative-only.
- `prefers-reduced-motion` disables decorative animation/transitions.
- Product copy keeps Swooshz Quote Auto Generator as a separate application.
- SEO / GEO / Seozilla are described only as planning-only, not available or purchasable.
