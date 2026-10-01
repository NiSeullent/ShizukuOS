#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile exact compositor/resize/present bodies with bounded host contracts.

No guest execution or app-rendering result is inferred. --before supplies an
immutable old gfx_wm.c to reproduce the actual transparent overlay regression.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
NAMES = ('client_w', 'client_h', 'wm_lookup', 'wm_is_visible', 'abs_origin',
         'wm_client_origin', 'wm_screen_rect', 'tgt_backbuffer', 'tgt_at',
         'fillc', 'blit_surface', 'blit_written_surface', 'is_layered',
         'has_transparent_client', 'blend_layer', 'compose_win', 'compose_plain',
         'covers_opaquely', 'wm_damage', 'win_apply_size', 'layer_free',
         'free_window_memory', 'gfx_syscall_present', 'winop_print')


def function(text, name):
    match = re.search(r'^[^\n;{}]*\b'+re.escape(name)+r'\([^;{}]*\)\s*\{', text, re.M)
    if not match:
        raise ValueError('missing production body: '+name)
    start, at = match.start(), match.end()-1
    depth, quote = 0, None
    while at < len(text):
        char = text[at]
        if quote:
            if char == '\\': at += 2; continue
            if char == quote: quote = None
        elif text.startswith('/*', at):
            at = text.index('*/', at+2)+2; continue
        elif text.startswith('//', at):
            at = text.index('\n', at+2); continue
        elif char in ('"', "'"): quote = char
        elif char == '{': depth += 1
        elif char == '}':
            depth -= 1
            if not depth: return text[start:at+1]
        at += 1
    raise ValueError('unterminated production body: '+name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--before', type=Path)
    args = parser.parse_args()
    out = args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    source = args.before or ROOT/'shizukudos/kernel64/gfx_wm.c'
    text = source.read_text()
    names = [name for name in NAMES if not args.before or name not in
             ('blit_written_surface', 'has_transparent_client')]
    bodies = {name:function(text,name) for name in names}
    geometry = (ROOT/'shizukudos/kernel64/gfx.h').read_text()
    declarations = 'static void compose_plain(gwin_t *,int,int,const shz_rect_t *);\n'
    declarations += 'static uint32_t *tgt_px; static uint32_t tgt_w,tgt_h; static uint32_t *g_under;\n'
    extracted = declarations+function(geometry,'rc_empty')+'\n'+function(geometry,'rc_isect')+'\n'+('\n\n'.join(bodies.values()))+'\n'
    (out/'written_coverage_production.inc').write_text(extracted)
    fixture = ROOT/'shizukudos/kernel64/tests/test_written_coverage_host.c'
    proof = {'source':str(source.resolve()),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
             'production_functions':{n:hashlib.sha256(b.encode()).hexdigest() for n,b in bodies.items()},
             'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),'counterfactual':bool(args.before),'runs':[]}
    for cc,sanitize in [('gcc',False),('clang',True)]:
        exe = out/('coverage_'+cc)
        command = [cc,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-I',str(out)]
        if sanitize:command += ['-fsanitize=address,undefined','-fno-omit-frame-pointer']
        if args.before:command += ['-DSHZ_COVERAGE_BEFORE']
        command += [str(fixture),'-o',str(exe)]
        built = subprocess.run(command,capture_output=True,text=True)
        row = {'command':command,'build_returncode':built.returncode,'build_output':built.stdout+built.stderr}
        if not built.returncode:
            ran = subprocess.run([str(exe)],capture_output=True,text=True,timeout=30)
            row.update(returncode=ran.returncode,output=ran.stdout+ran.stderr)
        proof['runs'].append(row)
    (out/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof['runs'],indent=2))
    return 0 if all(not row['build_returncode'] and not row.get('returncode',1) for row in proof['runs']) else 1


if __name__=='__main__':raise SystemExit(main())
