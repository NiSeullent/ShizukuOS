# SPDX-License-Identifier: GPL-2.0-only
"""Draw host evidence panels. These are not guest framebuffer captures."""
from __future__ import annotations
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

FONT = "/usr/share/fonts/google-droid-sans-fonts/DroidSans.ttf"
FONT_BOLD = "/usr/share/fonts/google-droid-sans-fonts/DroidSans-Bold.ttf"


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_BOLD if bold else FONT, size)


def panel(path: Path, title: str, lines: list[str], *, banner: tuple[int, int, int] = (0, 0, 128),
          width: int = 960, line_height: int = 28) -> Path:
    height = 86 + line_height * (len(lines) + 1)
    image = Image.new("RGB", (width, height), (192, 192, 192))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, width - 1, height - 1), outline=(0, 0, 0))
    draw.rectangle((3, 3, width - 4, 32), fill=banner)
    draw.text((12, 8), title, fill=(255, 255, 255), font=_font(16, True))
    y = 48
    face = _font(15)
    for line in lines:
        draw.text((16, y), line, fill=(0, 0, 0), font=face)
        y += line_height
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, "PNG")
    return path


def byte_rows(path: Path, title: str, rows: list[tuple[str, bytes]]) -> Path:
    width, row_h = 960, 36
    height = 70 + row_h * len(rows)
    image = Image.new("RGB", (width, height), (0, 128, 128))
    draw = ImageDraw.Draw(image)
    draw.rectangle((8, 8, width - 9, height - 9), fill=(192, 192, 192), outline=(255, 255, 255))
    draw.rectangle((12, 12, width - 13, 40), fill=(0, 0, 128))
    draw.text((20, 16), title, fill=(255, 255, 255), font=_font(16, True))
    y = 52
    for label, blob in rows:
        draw.text((20, y), label, fill=(0, 0, 80), font=_font(14, True))
        draw.text((220, y), blob.hex(), fill=(0, 0, 0), font=_font(14))
        y += row_h
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, "PNG")
    return path
