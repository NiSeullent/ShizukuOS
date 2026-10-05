#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate an OFL Korean bitmap face; never install or alter the source font."""
import argparse
import hashlib
import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont, __version__ as pillow_version
from fontTools.ttLib import TTFont

WIDTH, HEIGHT, BASELINE = 16, 22, 17
CODEPOINTS = list(range(0x20, 0x7f)) + list(range(0x1100, 0x1200)) + list(range(0x3131, 0x318f)) + list(range(0xac00, 0xd7a4))
BLANK_FILLERS = {0x20, 0x115f, 0x1160, 0x3164}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--font', type=Path, required=True)
    parser.add_argument('--license', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    font_path, license_path, out = args.font.resolve(), args.license.resolve(), args.out.resolve()
    if out.exists():
        raise SystemExit('Output must be a new directory')
    before = {'font': digest(font_path), 'license': digest(license_path)}
    license_text = license_path.read_text()
    if 'SIL OPEN FONT LICENSE Version 1.1' not in license_text:
        raise SystemExit('Expected complete SIL OFL 1.1 license')
    table = TTFont(str(font_path), fontNumber=1, lazy=True)
    copyright_text = next(n.toUnicode() for n in table['name'].names if n.nameID == 0)
    cmap = table.getBestCmap()
    missing = [c for c in CODEPOINTS if c not in cmap]
    if missing:
        raise SystemExit('Source lacks requested glyphs: ' + str(missing[:8]))
    font = ImageFont.truetype(str(font_path), 16, index=1)
    if font.getname()[0] != 'Noto Sans CJK KR':
        raise SystemExit('Collection face 1 is not Korean Noto Sans CJK')
    font.set_variation_by_axes([500])
    rows = []
    empty = []
    for codepoint in CODEPOINTS:
        text = chr(codepoint)
        bounds = font.getbbox(text, anchor='ls')
        shift_x = -min(0, bounds[0])
        if bounds[2] + shift_x > WIDTH or bounds[1] + BASELINE < 0 or bounds[3] + BASELINE > HEIGHT:
            raise SystemExit(f'Clipped glyph U+{codepoint:04X}: {bounds}')
        image = Image.new('L', (WIDTH, HEIGHT))
        ImageDraw.Draw(image).text((shift_x, BASELINE), text, font=font, fill=255, anchor='ls')
        glyph = [sum((1 << (WIDTH - 1 - x)) for x in range(WIDTH) if image.getpixel((x, y)) >= 96) for y in range(HEIGHT)]
        if not any(glyph) and codepoint not in BLANK_FILLERS:
            empty.append(codepoint)
        rows.append(glyph)
    if empty:
        raise SystemExit('Unexpected blank glyphs: ' + str(empty[:8]))
    if before != {'font': digest(font_path), 'license': digest(license_path)}:
        raise SystemExit('Inputs changed during generation')
    out.mkdir(parents=True)
    notice = 'ShizukuKRBitmap: modified bitmap face derived from Noto Sans CJK KR.\n' + copyright_text + '\n'
    (out / 'OFL.txt').write_text(notice + '\n' + license_text)
    header = ['/* SPDX-License-Identifier: OFL-1.1', ' * ' + notice.replace('\n', '\n * ').rstrip(' * '), ' * See OFL.txt. Generated; do not edit. */', '#ifndef SHZ_KR_GLYPHS_H', '#define SHZ_KR_GLYPHS_H', '#include <stdint.h>', f'#define SHZ_KR_GLYPH_HEIGHT {HEIGHT}', f'#define SHZ_KR_GLYPH_COUNT {len(rows)}', f'static const uint16_t shz_kr_rows[{len(rows)}][{HEIGHT}] = {{']
    for glyph in rows:
        header.append('{' + ','.join(f'0x{row:04x}' for row in glyph) + '},')
    header.extend(['};', '#endif', ''])
    header_path = out / 'glyphs.h'
    header_path.write_text('\n'.join(header))
    receipt = {'face_name': 'ShizukuKRBitmap', 'source_family': font.getname()[0], 'source_face_index': 1, 'source_copyright': copyright_text, 'source_sha256': before, 'source_stable': True, 'pillow_version': pillow_version, 'pixel_size': 16, 'weight': 500, 'threshold': 96, 'cell': [WIDTH, HEIGHT], 'baseline': BASELINE, 'ranges': [[0x20, 0x7e], [0x1100, 0x11ff], [0x3131, 0x318e], [0xac00, 0xd7a3]], 'glyph_count': len(rows), 'glyphs_sha256': digest(header_path), 'license_sha256': digest(out / 'OFL.txt'), 'runtime_execution': False, 'general_font_engine': False}
    (out / 'generation.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
