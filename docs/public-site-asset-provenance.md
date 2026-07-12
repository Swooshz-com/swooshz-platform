# Public site asset provenance

This record covers the local assets added for the Prestige A public-site port.
The approved visual package remains the design source of truth; prototype and
evidence folders are not production inputs at runtime and are not committed.

## Approved source

- Package: `prestige-a-final-share`
- Local handoff root: `_tmp/platform-visual-directions/prestige-a-final-share/`
- Design contract: `documentation/prestige-a-design-contract.md`
- Approved hero source: `prototype/assets/hero-editorial-monument.png`
- Source dimensions: 1672 x 941 RGB
- Source SHA-256: `BA7337CC9E22CD132BD833C44C38DF876CCCB935F93CC08825E8CE5153ACD0F0`
- Swooshz mark SHA-256: `5A272D5BD2EF8AD68252E7AB9CB24864391A6946A75F6B6977DC36C119037B82`

The approved artwork was manually reviewed in the handoff screenshots and
recording contact sheets. It contains no embedded words, fake user interface,
customer data, customer marks, or third-party marks. The mark and monument are
used decoratively; rendered HTML gives them empty alternative text.

## Production image variants

The 1,857,342-byte source PNG is not shipped. Production candidates are encoded
locally with Pillow 12.2.0 from the approved source only:

| Width | AVIF | WebP | PNG fallback |
| --- | ---: | ---: | ---: |
| 640 | 8,883 bytes | 10,734 bytes | 263,851 bytes |
| 960 | 16,980 bytes | 20,094 bytes | - |
| 1280 | 28,304 bytes | 32,250 bytes | 1,080,594 bytes |
| 1672 | 46,140 bytes | 50,928 bytes | - |

All listed candidates are referenced by the homepage `picture` element and its
responsive `srcset`/`sizes`. The homepage has one AVIF image preload. Other
routes do not preload the monument. The image declares its intrinsic 1672 x 941
dimensions to prevent layout shift. No third-party image service is used.

## Fonts and licensing

Only the two approved Latin variable fonts are included:

| Font | Production file | SHA-256 | License notice |
| --- | --- | --- | --- |
| Manrope | `fonts/manrope-latin-variable.woff2` | `A30DDCD349703AFF7464C34BEF3FFFDFF405EE50C113440D7C8693C02D210972` | `fonts/OFL-Manrope.txt` |
| Fraunces italic | `fonts/fraunces-italic-latin-variable.woff2` | `066710CE7ED235A339D3D6CDCC8B55C0BEA5632232662D83AACEA25852108271` | `fonts/OFL-Fraunces.txt` |

The supplied notices are SIL Open Font License 1.1 text. Notice SHA-256 values:

- Manrope OFL: `517DC2E6AE4A4EF4D9FD9D7375A001171AC2264D70DE24092178165699855D3F`
- Fraunces OFL: `7BA6D8841DF783BBC00AF75A375A60326ED8072727FC77FF401903CCFD1E2DEF`

Fonts are served locally with `font-display: swap`. No remote font request or
unrelated font file is included.

## Cache and content-versioning strategy

Every browser-rendered public asset URL contains the first 16 hexadecimal
characters of that asset's SHA-256 digest. The generated manifest is derived
from the bytes served in production; changing those bytes changes the URL. CSS
is hashed after its font references are rewritten to the fonts' own hashed
paths, so the stylesheet URL also changes when a referenced font changes.

The production build regenerates `src/http/public-asset-manifest.ts`, removes
stale generated output under `dist/http/public-assets`, and materializes both
the content-addressed files referenced by HTML/CSS and revalidating logical
aliases. Content-addressed paths receive one-year `immutable` caching. Logical
unversioned aliases receive `public, max-age=0, must-revalidate` and are retained
only as safe compatibility paths. The typecheck command fails when the committed
generated manifest no longer matches source asset bytes.
