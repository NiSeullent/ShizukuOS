#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Export real Noto outlines; keep the original fonts and legacy atlas untouched."""
import argparse
import hashlib
import json
from pathlib import Path

from fontTools import subset, __version__ as fonttools_version
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def family(font):
    return font['name'].getDebugName(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--latin', type=Path, required=True)
    parser.add_argument('--kr', type=Path, required=True)
    parser.add_argument('--latin-license', type=Path, required=True)
    parser.add_argument('--kr-license', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    paths = [args.latin, args.kr, args.latin_license, args.kr_license]
    before = {str(p): digest(p) for p in paths}
    if args.out.exists():
        raise SystemExit('Output must be a new directory')
    for p in paths[2:]:
        if 'SIL OPEN FONT LICENSE Version 1.1' not in p.read_text():
            raise SystemExit('Missing original OFL license')
    latin = TTFont(args.latin, lazy=True)
    if family(latin) != 'Noto Sans':
        raise SystemExit('Expected proportional Noto Sans Latin')
    latin.close()
    kr = TTFont(args.kr, fontNumber=1)
    if family(kr) != 'Noto Sans CJK KR':
        raise SystemExit('Expected Korean Noto collection face 1')
    ranges = [(0x20, 0x7e), (0x1100, 0x11ff), (0x3131, 0x318e), (0xac00, 0xd7a3),
              (0x2000, 0x206f), (0x20a0, 0x20cf), (0x2190, 0x21ff), (0x25a0, 0x25ff),
              (0xa960, 0xa97f), (0xd7b0, 0xd7ff), (0xfffd, 0xfffd)]
    requested = {cp for lo, hi in ranges for cp in range(lo, hi + 1)}
    mandatory = {cp for lo, hi in ranges[:4] for cp in range(lo, hi + 1)}
    if mandatory - kr.getBestCmap().keys():
        raise SystemExit('Original Korean face lacks required coverage')
    copyright_text = kr['name'].getDebugName(0)
    options = subset.Options()
    options.name_IDs = ['*']
    options.name_languages = ['*']
    options.name_legacy = True
    options.recalc_timestamp = False
    worker = subset.Subsetter(options=options)
    worker.populate(unicodes=requested)
    worker.subset(kr)
    kr = instantiateVariableFont(kr, {'wght': 400}, inplace=True, updateFontNames=True)
    if 'fvar' in kr or mandatory - kr.getBestCmap().keys():
        raise SystemExit('Static instance or Korean coverage invalid')
    args.out.mkdir()
    target = args.out / 'NotoSansKR.otf'
    kr.save(target)
    kr.close()
    if target.stat().st_size > 8 << 20:
        raise SystemExit('Korean font exceeds asset budget')
    (args.out / 'NotoSans.ttf').write_bytes(args.latin.read_bytes())
    (args.out / 'OFL-Latin.txt').write_bytes(args.latin_license.read_bytes())
    (args.out / 'OFL-KR.txt').write_bytes(args.kr_license.read_bytes())
    check = TTFont(target)
    if family(check) != 'Noto Sans CJK KR' or mandatory - check.getBestCmap().keys():
        raise SystemExit('Written outline font failed readback')
    coverage = sorted(check.getBestCmap())
    check.close()
    if before != {str(p): digest(p) for p in paths}:
        raise SystemExit('Inputs changed during export')
    files = []
    for name in ('NotoSans.ttf', 'NotoSansKR.otf', 'OFL-Latin.txt', 'OFL-KR.txt'):
        path = args.out / name
        files.append({'path': name, 'media_target': '\\SHZ\\FONTS\\' + name,
                      'bytes': path.stat().st_size, 'sha256': digest(path)})
    receipt = {'status': 'PASS_OUTLINE_ASSET_EXPORT_ONLY', 'files': files,
               'input_sha256': before, 'source_stable': True,
               'recipe_sha256': digest(Path(__file__)), 'fonttools_version': fonttools_version,
               'kr_source_face': 1, 'kr_runtime_face': 0, 'kr_weight': 400,
               'kr_family': 'Noto Sans CJK KR', 'kr_copyright': copyright_text,
               'kr_modification': 'subset of Unicode ranges and static weight 400; genuine outlines retained',
               'kr_requested_ranges': ranges, 'kr_exported_codepoints': len(coverage),
               'required_hangul_syllables': 11172, 'complete_required_coverage': True,
               'shaping_verified': False, 'guest_verified': False}
    (args.out / 'font-assets.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'files': files}))


if __name__ == '__main__':
    main()
