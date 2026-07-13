from pathlib import Path
from textwrap import wrap

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
BASELINE = ROOT.parent / "approved-baseline" / "evidence" / "core"
FINAL = ROOT / "evidence" / "core-v2"
SUPPORT = ROOT / "evidence" / "supporting"
OUT = ROOT / "evidence" / "comparisons"
OUT.mkdir(parents=True, exist_ok=True)

PAPER = "#fffefa"
PAGE = "#f0f1ed"
INK = "#0f1a2a"
SECONDARY = "#364b63"
MUTED = "#637184"
LINE = "#ccd5d4"
TEAL = "#0b756d"
TEAL_SOFT = "#e0f1ec"
FONT_PATH = ROOT / "assets" / "fonts" / "inter-latin-wght-normal.woff2"


def font(size):
    return ImageFont.truetype(str(FONT_PATH), size=size, layout_engine=ImageFont.Layout.BASIC)


TITLE = font(34)
SUBTITLE = font(17)
LABEL = font(22)
BODY = font(17)
SMALL = font(15)


def open_rgb(path):
    return Image.open(path).convert("RGB")


def page_heading(canvas, title, subtitle):
    draw = ImageDraw.Draw(canvas)
    draw.text((48, 28), title, fill=INK, font=TITLE)
    draw.text((49, 74), subtitle, fill=SECONDARY, font=SUBTITLE)
    draw.line((48, 108, canvas.width - 48, 108), fill=TEAL, width=3)


def fit(image, size):
    copy = image.copy()
    copy.thumbnail(size, Image.Resampling.LANCZOS)
    return copy


def place(canvas, image, box, fill=PAPER):
    x, y, width, height = box
    tile = Image.new("RGB", (width, height), fill)
    fitted = fit(image, (width, height))
    tile.paste(fitted, ((width - fitted.width) // 2, (height - fitted.height) // 2))
    canvas.paste(tile, (x, y))


def labelled_tile(canvas, image, label, box):
    x, y, width, height = box
    draw = ImageDraw.Draw(canvas)
    draw.text((x, y), label, fill=INK, font=LABEL)
    draw.rounded_rectangle((x, y + 36, x + width, y + height), radius=10, fill=PAPER, outline=LINE, width=1)
    place(canvas, image, (x + 2, y + 38, width - 4, height - 40))


def desktop_before_after(name, title, filename):
    canvas = Image.new("RGB", (2200, 980), PAGE)
    page_heading(canvas, title, "Approved baseline versus polished version 2")
    labelled_tile(canvas, open_rgb(BASELINE / name), "Approved baseline", (48, 140, 1028, 790))
    labelled_tile(canvas, open_rgb(FINAL / name), "Polished", (1124, 140, 1028, 790))
    canvas.save(OUT / filename, quality=96)


def mobile_before_after(name, title, filename):
    canvas = Image.new("RGB", (1400, 1110), PAGE)
    page_heading(canvas, title, "Approved baseline versus polished version 2 at 390 x 844")
    labelled_tile(canvas, open_rgb(BASELINE / name), "Approved baseline", (48, 140, 620, 920))
    labelled_tile(canvas, open_rgb(FINAL / name), "Polished", (732, 140, 620, 920))
    canvas.save(OUT / filename, quality=96)


def final_four_screen_sheet():
    canvas = Image.new("RGB", (2200, 1720), PAGE)
    page_heading(canvas, "Final four-screen review", "Authenticated operational UI polish - version 2")
    tiles = [
        (FINAL / "desktop-launcher.png", "Desktop launcher - 1440 x 900"),
        (FINAL / "desktop-members.png", "Desktop Members - 1440 x 900"),
        (FINAL / "mobile-launcher-390.png", "Mobile launcher - 390 x 844"),
        (FINAL / "mobile-members-390.png", "Mobile Members - 390 x 844"),
    ]
    positions = [(48, 138, 1028, 710), (1124, 138, 1028, 710), (48, 884, 1028, 786), (1124, 884, 1028, 786)]
    for (path, label), box in zip(tiles, positions):
        labelled_tile(canvas, open_rgb(path), label, box)
    canvas.save(OUT / "final-four-screen-contact-sheet.png", quality=96)


def final_mobile_sheet():
    canvas = Image.new("RGB", (1800, 1810), PAGE)
    page_heading(canvas, "Final mobile comparison", "Core 390px screens and required 320px preservation")
    tiles = [
        (FINAL / "mobile-launcher-390.png", "Launcher - 390px"),
        (FINAL / "mobile-members-390.png", "Members - 390px"),
        (SUPPORT / "launcher-320.png", "Launcher - 320px"),
        (SUPPORT / "members-320.png", "Members - 320px"),
    ]
    positions = [(48, 138, 820, 790), (932, 138, 820, 790), (48, 964, 820, 796), (932, 964, 820, 796)]
    for (path, label), box in zip(tiles, positions):
        labelled_tile(canvas, open_rgb(path), label, box)
    canvas.save(OUT / "final-mobile-comparison-sheet.png", quality=96)


def icon_detail_sheet():
    baseline = open_rgb(BASELINE / "desktop-launcher.png")
    final = open_rgb(FINAL / "desktop-launcher.png")
    mobile = open_rgb(FINAL / "mobile-launcher-390.png")
    before_crop = baseline.crop((148, 258, 262, 372)).resize((456, 456), Image.Resampling.NEAREST)
    after_crop = final.crop((202, 402, 320, 520)).resize((472, 472), Image.Resampling.NEAREST)
    mobile_crop = mobile.crop((28, 238, 210, 292)).resize((728, 216), Image.Resampling.NEAREST)

    canvas = Image.new("RGB", (1800, 1050), PAGE)
    page_heading(canvas, "Product-icon detail", "Brand mark removed from product identity; study-only quote-sheet symbol introduced")
    labelled_tile(canvas, before_crop, "Before - Swooshz brand mark", (48, 146, 520, 600))
    labelled_tile(canvas, after_crop, "Final - desktop quote sheet", (640, 146, 520, 600))
    labelled_tile(canvas, mobile_crop, "Final - mobile quote sheet", (1232, 146, 520, 600))
    draw = ImageDraw.Draw(canvas)
    notes = [
        "Folded document edge",
        "Three line-item rules",
        "Calculation column",
        "Controlled teal total rule",
        "No letter Q or AI sparkle motif",
    ]
    x = 48
    y = 800
    for note in notes:
        draw.ellipse((x, y + 7, x + 8, y + 15), fill=TEAL)
        draw.text((x + 18, y), note, fill=SECONDARY, font=BODY)
        x += 340
    canvas.save(OUT / "product-icon-detail-sheet.png", quality=96)


def draw_wrapped(draw, xy, text, width_chars, fill, text_font, line_height):
    x, y = xy
    lines = []
    for paragraph in text.split("\n"):
        lines.extend(wrap(paragraph, width=width_chars) or [""])
    for line in lines:
        draw.text((x, y), line, fill=fill, font=text_font)
        y += line_height
    return y


def copy_sheet():
    rows = [
        ("Operational access / App launcher", "Your product"),
        ("Workspace product", "Quotations"),
        ("Create accurate, branded quotations from your approved products, pricing rules and commercial terms.", "Create professional quotations using your approved workspace."),
        ("Access: Active / Session: Ready", "Product status: Ready to launch"),
        ("Launch quote generator", "Launch product"),
        ("Secure workspace handoff. Opens the quote workspace with your current access and workspace context.", "Ready when you are. Your workspace and role stay the same when the product opens."),
        ("Entitlement", "Product access"),
        ("Launch could not complete. Your session is safe. Check your connection and try again.", "We could not open the product. Try again."),
        ("Product access is unavailable. Ask a workspace administrator to check the current entitlement.", "Product access unavailable. Your workspace does not currently have access to this product."),
    ]
    canvas = Image.new("RGB", (1900, 1500), PAGE)
    page_heading(canvas, "Customer copy - before and after", "Technical and prototype language replaced with direct customer wording")
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle((48, 142, 1852, 1448), radius=10, fill=PAPER, outline=LINE, width=1)
    draw.rectangle((48, 142, 1852, 208), fill=TEAL_SOFT)
    draw.text((84, 164), "Approved baseline", fill=INK, font=LABEL)
    draw.text((978, 164), "Polished", fill=INK, font=LABEL)
    y = 208
    row_height = 136
    for before, after in rows:
        draw.line((48, y, 1852, y), fill=LINE, width=1)
        draw.line((950, y, 950, y + row_height), fill=LINE, width=1)
        draw_wrapped(draw, (84, y + 20), before, 66, MUTED, BODY, 24)
        draw_wrapped(draw, (978, y + 20), after, 66, INK, BODY, 24)
        y += row_height
    canvas.save(OUT / "copy-before-and-after-sheet.png", quality=96)


if __name__ == "__main__":
    desktop_before_after("desktop-launcher.png", "Launcher comparison", "baseline-vs-polished-launcher.png")
    desktop_before_after("desktop-members.png", "Members comparison", "baseline-vs-polished-members.png")
    mobile_before_after("mobile-launcher-390.png", "Mobile launcher comparison", "baseline-vs-polished-mobile-launcher.png")
    mobile_before_after("mobile-members-390.png", "Mobile Members comparison", "baseline-vs-polished-mobile-members.png")
    final_four_screen_sheet()
    final_mobile_sheet()
    icon_detail_sheet()
    copy_sheet()
    for path in sorted(OUT.glob("*.png")):
        print(f"{path.name}: {path.stat().st_size} bytes")
