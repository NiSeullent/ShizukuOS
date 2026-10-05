#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Export genuine Noto 13px FreeType gray glyphs to an OFL caption cache.

Run on NAS through nas-run; source assets remain read-only. No kernel build,
media, VM, font installation or code modification. Output must be new.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
LATIN = '8b23d6341a12454e68e35c2c0917f0504104ded6aa3024d18e9d462da06fadd3'
KR = '6c6af05d3e4ac479f830647fef083fa7014731e5a4f1e825df38c511bc33c57b'
LICENSES = {'OFL-Latin.txt': 'cee9892f9f0cc8fe882c9e9537ee6a89621d86ee7ceaf70b02e2b2b1c25c061a',
            'OFL-KR.txt': '6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2'}
CAP = 2 * 1024 * 1024
# Actual 13px glyph extents are [-11, +4); baseline 12 leaves one pixel
# above and below their 15px union inside the unchanged 17px caption clip.
EM, BASELINE, LINE = 13, 12, 17
CPS = list(range(0x20, 0x7f)) + list(range(0x1100, 0x1200)) + list(range(0x3131, 0x318f)) + list(range(0xac00, 0xd7a4)) + [0xfffd]
BLANK = {0x20, 0x115f, 0x1160, 0x3164}

# Public FreeType structs through the fields consumed here (LP64 NAS ABI).
class Generic(C.Structure):
    _fields_ = [('data', C.c_void_p), ('finalizer', C.c_void_p)]
class Vector(C.Structure):
    _fields_ = [('x', C.c_long), ('y', C.c_long)]
class Bitmap(C.Structure):
    _fields_ = [('rows', C.c_uint), ('width', C.c_uint), ('pitch', C.c_int), ('buffer', C.c_void_p),
                ('num_grays', C.c_ushort), ('pixel_mode', C.c_ubyte), ('palette_mode', C.c_ubyte), ('palette', C.c_void_p)]
class Slot(C.Structure):
    _fields_ = [('library', C.c_void_p), ('face', C.c_void_p), ('next', C.c_void_p), ('glyph_index', C.c_uint),
                ('generic', Generic), ('metrics', C.c_long * 8), ('linearHoriAdvance', C.c_long), ('linearVertAdvance', C.c_long),
                ('advance', Vector), ('format', C.c_uint32), ('bitmap', Bitmap), ('bitmap_left', C.c_int), ('bitmap_top', C.c_int)]
class Face(C.Structure):
    _fields_ = [('num_faces', C.c_long), ('face_index', C.c_long), ('face_flags', C.c_long), ('style_flags', C.c_long),
                ('num_glyphs', C.c_long), ('family_name', C.c_char_p), ('style_name', C.c_char_p),
                ('num_fixed_sizes', C.c_int), ('available_sizes', C.c_void_p), ('num_charmaps', C.c_int), ('charmaps', C.c_void_p),
                ('generic', Generic), ('bbox', C.c_long * 4), ('units_per_EM', C.c_ushort), ('ascender', C.c_short),
                ('descender', C.c_short), ('height', C.c_short), ('max_advance_width', C.c_short), ('max_advance_height', C.c_short),
                ('underline_position', C.c_short), ('underline_thickness', C.c_short), ('glyph', C.POINTER(Slot)),
                ('size', C.c_void_p), ('charmap', C.c_void_p)]
FacePtr = C.POINTER(Face)
class SfntName(C.Structure):
    _fields_ = [('platform_id', C.c_ushort), ('encoding_id', C.c_ushort), ('language_id', C.c_ushort),
                ('name_id', C.c_ushort), ('string', C.c_void_p), ('string_len', C.c_uint)]
def copyright_statements(ft, face):
    # Public FT_SfntName records carry the actual pinned font's name ID 0.
    # Bitmap derivatives lack a name table, so retain these notices separately.
    count = ft.FT_Get_Sfnt_Name_Count(face)
    if count > 4096:
        raise RuntimeError('bounded SFNT name table required')
    texts = []
    for i in range(count):
        name = SfntName()
        call(ft, 'FT_Get_Sfnt_Name', face, i, C.byref(name))
        if name.name_id != 0:
            continue
        if not name.string or not 0 < name.string_len <= 8192:
            raise RuntimeError('bounded copyright name record required')
        raw = C.string_at(name.string, name.string_len)
        if name.platform_id in (0, 3):
            text = raw.decode('utf-16-be')
        elif name.platform_id == 1:
            text = raw.decode('mac_roman')
        else:
            continue
        if text not in texts:
            texts.append(text)
            if sum(len(value.encode('utf-8')) for value in texts) > 16384:
                raise RuntimeError('copyright notice text cap')
    if not texts or not any('Copyright' in text or '\u00a9' in text for text in texts):
        raise RuntimeError('actual source copyright statement required')
    return texts
def make_notice(copyrights):
    text = ('ShizukuCaptionCache: antialiased bitmap cache derived from Noto Sans and Noto Sans CJK KR.\n'
            'Original source copyright notices copied from the pinned fonts, SFNT name ID 0:\n')
    for name in ('NotoSans.ttf', 'NotoSansKR.otf'):
        text += '\n' + name + '\n' + '\n'.join(copyrights[name]) + '\n'
    return text + ('\nComplete source OFL-1.1 texts are in OFL-Latin.txt and OFL-KR.txt.\n'
                   'The derivative cache name is ShizukuCaptionCache; reserved source font names are not used.\n')

def sha(p):
    h = hashlib.sha256()
    with Path(p).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()
def call(ft, name, *a):
    error = getattr(ft, name)(*a)
    if error:
        raise RuntimeError(name + ' FreeType error ' + str(error))
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--assets', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--freetype', type=Path, default=Path('/usr/lib/libfreetype.so.6'))
    ap.add_argument('--nas-root', type=Path, default=Path('/volume2/homes/sharhene777/wub-data-20261003/root'))
    args = ap.parse_args()
    native_root = Path('/volume2/homes/sharhene777/wub-data-20261003/root')
    mounted_root = Path('/root/_drive/0001/volume2/homes/sharhene777/wub-data-20261003/root')
    if args.nas_root not in (native_root, mounted_root):
        raise RuntimeError('declared NAS root required')
    root = args.nas_root.resolve()
    execution = 'NAS native Python/FreeType'
    if args.nas_root == mounted_root:
        mount = subprocess.run(['findmnt', '-n', '-o', 'FSTYPE,SOURCE', '-T', str(root)],
                               check=True, capture_output=True, text=True, timeout=10).stdout.strip()
        if mount != 'fuse.sshfs sharhene777@100.99.23.27:/volume2':
            raise RuntimeError('actual NAS mount required; no local storage fallback')
        execution = 'local native Python/FreeType, actual mounted NAS storage'
    assets, out, library_path = args.assets.resolve(), args.out.resolve(), args.freetype.resolve()
    if root not in out.parents or out.exists():
        raise RuntimeError('new owned NAS output under declared root required')
    if shutil.disk_usage(root).free < 17 * 1024**3 + CAP:
        raise RuntimeError('NAS disk reserve')
    pins = {'NotoSans.ttf': LATIN, 'NotoSansKR.otf': KR, **LICENSES}
    before = {n: sha(assets / n) for n in pins}
    if before != pins:
        raise RuntimeError('font/OFL inputs differ from compiled source pins')
    licenses = {n: (assets / n).read_bytes() for n in LICENSES}
    if any(b'SIL OPEN FONT LICENSE Version 1.1' not in data for data in licenses.values()):
        raise RuntimeError('complete source OFL license required')
    library_before = sha(library_path)
    ft = C.CDLL(str(library_path)); lib = C.c_void_p(); faces = []
    ft.FT_Init_FreeType.argtypes = [C.POINTER(C.c_void_p)]
    ft.FT_New_Face.argtypes = [C.c_void_p, C.c_char_p, C.c_long, C.POINTER(FacePtr)]
    ft.FT_Get_Sfnt_Name_Count.argtypes = [FacePtr]; ft.FT_Get_Sfnt_Name_Count.restype = C.c_uint
    ft.FT_Get_Sfnt_Name.argtypes = [FacePtr, C.c_uint, C.POINTER(SfntName)]
    ft.FT_Select_Charmap.argtypes = [FacePtr, C.c_uint32]
    ft.FT_Set_Pixel_Sizes.argtypes = [FacePtr, C.c_uint, C.c_uint]
    ft.FT_Get_Char_Index.argtypes = [FacePtr, C.c_ulong]; ft.FT_Get_Char_Index.restype = C.c_uint
    ft.FT_Load_Char.argtypes = [FacePtr, C.c_ulong, C.c_int32]
    ft.FT_Done_Face.argtypes = [FacePtr]; ft.FT_Done_FreeType.argtypes = [C.c_void_p]
    ft.FT_Library_Version.argtypes = [C.c_void_p, C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(C.c_int)]
    call(ft, 'FT_Init_FreeType', C.byref(lib))
    records = bytearray(); pixels = bytearray(); intermediate = 0; advances = {}; family = []; copyrights = {}
    version = [C.c_int() for _ in range(3)]
    try:
        ft.FT_Library_Version(lib, *[C.byref(v) for v in version])
        for name in ('NotoSans.ttf', 'NotoSansKR.otf'):
            face = FacePtr(); call(ft, 'FT_New_Face', lib, os.fsencode(assets / name), 0, C.byref(face)); faces.append(face)
            family.append(face.contents.family_name.decode('utf-8'))
            copyrights[name] = copyright_statements(ft, face)
            call(ft, 'FT_Select_Charmap', face, 0x756e6963)
            call(ft, 'FT_Set_Pixel_Sizes', face, 0, EM)
        if family != ['Noto Sans', 'Noto Sans CJK KR']:
            raise RuntimeError('unexpected source families ' + str(family))
        for cp in CPS:
            face = faces[0 if cp < 0x80 or cp == 0xfffd else 1]
            if not ft.FT_Get_Char_Index(face, cp):
                raise RuntimeError('source glyph absent U+%04X' % cp)
            # FT_LOAD_RENDER | FT_LOAD_NO_HINTING | FT_LOAD_NO_AUTOHINT,
            # normal grayscale, actual fractional horizontal advance.
            call(ft, 'FT_Load_Char', face, cp, 4 | 2 | 32768)
            g = face.contents.glyph.contents; bm = g.bitmap
            w, h, left, top, advance = bm.width, bm.rows, g.bitmap_left, g.bitmap_top, g.advance.x
            if w > 32 or h > 32 or bool(w) != bool(h) or not 0 < advance <= 32 * 64 or not -32 <= left <= 32 or not -32 <= top <= 32:
                raise RuntimeError('glyph metrics outside bounds U+%04X' % cp)
            if BASELINE - top < 0 or BASELINE - top + h > LINE:
                raise RuntimeError('caption height would clip glyph U+%04X' % cp)
            if w and (bm.pixel_mode != 2 or bm.num_grays != 256 or bm.pitch < w or not bm.buffer):
                raise RuntimeError('expected genuine FreeType gray bitmap')
            coverage = []
            for y in range(h):
                row = C.string_at(bm.buffer + y * bm.pitch, w)
                coverage += [(a * 15 + 127) // 255 for a in row]
            if not any(coverage) and cp not in BLANK:
                raise RuntimeError('unexpected blank source glyph U+%04X' % cp)
            intermediate += sum(0 < a < 15 for a in coverage)
            offset = 128 + len(CPS) * 24 + len(pixels)
            records += struct.pack('<IIihhHHI', cp, offset, advance, left, top, w, h, 0)
            for i in range(0, len(coverage), 2):
                pixels.append((coverage[i] << 4) | (coverage[i + 1] if i + 1 < len(coverage) else 0))
            if cp in (ord('i'), ord('W')):
                advances[chr(cp)] = advance
            if 128 + len(records) + len(pixels) > CAP:
                raise RuntimeError('cache exceeds 2MiB bound')
        header = struct.pack('<8s10I', b'SHZCAP01', 1, 128 + len(records) + len(pixels), len(CPS), 24, 128,
                             128 + len(records), EM, BASELINE, LINE, 0)
        blob = header + bytes.fromhex(LATIN) + bytes.fromhex(KR) + b'\0' * 16 + records + pixels
        if len(blob) > CAP or not intermediate or advances['i'] == advances['W']:
            raise RuntimeError('cache lacks bounded antialias/proportional evidence')
        after = {n: sha(assets / n) for n in pins}
        if after != before:
            raise RuntimeError('source changed during generation')
        if sha(library_path) != library_before:
            raise RuntimeError('FreeType library changed during generation')
        out.mkdir()
        p = out / 'NOTOCAP.BIN'
        with p.open('xb') as f:
            f.write(blob); f.flush(); os.fsync(f.fileno())
        digest = sha(p)
        if digest != hashlib.sha256(blob).hexdigest():
            raise RuntimeError('written cache readback mismatch')
        for name, data in licenses.items():
            (out / name).write_bytes(data)
        (out / 'NOTICE.txt').write_text(make_notice(copyrights), encoding='utf-8')
        receipt = {'status': 'PASS_NOTO_CAPTION_CACHE_GENERATION', 'source_stable': True, 'source_before': before, 'source_after': after,
                   'producer_sha256': sha(__file__), 'execution': execution, 'source_families': family, 'pixel_size': EM, 'baseline': BASELINE, 'line_height': LINE,
                   'coverage': {'glyphs': len(CPS), 'printable_ascii': 95, 'conjoining_jamo': 256, 'compatibility_jamo': 94,
                                'hangul_syllables': 11172, 'replacement': 1, 'intermediate_4bit_pixels': intermediate},
                   'advance26_6_sample': advances, 'freetype': {'path': str(library_path), 'sha256': sha(library_path), 'version': [v.value for v in version]},
                   'recipe': {'argv': sys.argv, 'load_flags': 4 | 2 | 32768, 'pixel_mode': 'normal gray', 'coverage': 'nearest 4bit, high nibble first'},
                   'copyright_sfnt_name0': copyrights,
                   'notice': {'path': 'NOTICE.txt', 'media_target': '\\SHZ\\FONTS\\NOTICE.TXT',
                              'bytes': (out / 'NOTICE.txt').stat().st_size, 'sha256': sha(out / 'NOTICE.txt')},
                   'files': [{'path': 'NOTOCAP.BIN', 'media_target': '\\SHZ\\FONTS\\NOTOCAP.BIN', 'bytes': len(blob), 'sha256': digest}],
                   'guest_verified': False, 'kernel_embedded': False}
        (out / 'caption-manifest.json').write_text(json.dumps(receipt, indent=2) + '\n')
        for path in out.iterdir():
            path.chmod(0o444)
        print(json.dumps(receipt))
    finally:
        for face in faces:
            call(ft, 'FT_Done_Face', face)
        call(ft, 'FT_Done_FreeType', lib)
if __name__ == '__main__':
    main()
