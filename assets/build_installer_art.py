#!/usr/bin/env python3
"""Build NSIS installer sidebar/header bitmaps for TRACE Desktop, using the
real TRACE brand palette and real copy captured from the live tracems.com
homepage on 2026-09-09. No fabricated testimonials -- only TRACE's own
published product copy is used."""
import textwrap
from PIL import Image, ImageDraw, ImageFont, ImageOps

BG = (10, 16, 14)          # near-black TRACE background
PANEL = (16, 26, 22)       # slightly lighter panel
ACCENT = (200, 244, 94)    # TRACE lime-green accent
WHITE = (240, 246, 240)
MUTED = (150, 168, 156)

FONT_DIR = "/usr/share/fonts/truetype/dejavu/"
def font(name, size):
    return ImageFont.truetype(FONT_DIR + name, size)

F_WORDMARK = font("DejaVuSans-Bold.ttf", 20)
F_QUOTE = font("DejaVuSans-Bold.ttf", 15)
F_SMALL = font("DejaVuSans.ttf", 11)
F_TAG = font("DejaVuSans-Bold.ttf", 9)

def wrap_draw(draw, text, xy, f, fill, max_width, line_h, anchor_top=True):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if draw.textlength(trial, font=f) <= max_width:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    x, y = xy
    for line in lines:
        draw.text((x, y), line, font=f, fill=fill)
        y += line_h
    return y

def sidebar(path, quote, tag, screenshot_inset=None):
    W, H = 164, 314
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # accent rule at top
    d.rectangle([0, 0, W, 4], fill=ACCENT)
    # wordmark
    d.text((16, 20), "TRACE", font=F_WORDMARK, fill=WHITE)
    d.text((16, 44), "MS", font=F_TAG, fill=ACCENT)
    d.line([(16, 62), (W - 16, 62)], fill=(40, 54, 46), width=1)

    y = 78
    y = wrap_draw(d, tag.upper(), (16, y), F_TAG, ACCENT, W - 32, 13)
    y += 10
    y = wrap_draw(d, quote, (16, y), F_QUOTE, WHITE, W - 32, 20)
    y += 8

    if screenshot_inset:
        thumb = Image.open(screenshot_inset).convert("RGB")
        tw = W - 32
        th = int(tw * thumb.height / thumb.width)
        th = min(th, 92)
        thumb = ImageOps.fit(thumb, (tw, th), method=Image.LANCZOS)
        frame = Image.new("RGB", (tw + 4, th + 4), (60, 78, 66))
        frame.paste(thumb, (2, 2))
        img.paste(frame, (16, H - th - 44))
        d.text((16, H - 30), "app.tracems.com", font=F_SMALL, fill=MUTED)
    else:
        d.text((16, H - 30), "app.tracems.com", font=F_SMALL, fill=MUTED)

    img.save(path, "BMP")

def header(path):
    W, H = 150, 57
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, H - 3, W, H], fill=ACCENT)
    d.text((14, 17), "TRACE", font=font("DejaVuSans-Bold.ttf", 18), fill=WHITE)
    img.save(path, "BMP")

sidebar(
    "/home/claude/trace-desktop/build/installer-sidebar-welcome.bmp",
    "Every plan. Every detail. Connected.",
    "Construction management + project AI",
    screenshot_inset="/home/claude/trace-desktop/assets/trace-risk-gauge-crop.jpg",
)

sidebar(
    "/home/claude/trace-desktop/build/installer-sidebar-finish.bmp",
    "See risk, schedule and compliance at a glance.",
    "Work in the real platform",
    screenshot_inset="/home/claude/trace-desktop/assets/trace-dashboard-crop.jpg",
)

header("/home/claude/trace-desktop/build/installer-header.bmp")
print("done")
