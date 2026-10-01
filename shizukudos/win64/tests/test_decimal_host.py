#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile exact additive DECIMAL sources with independent Python rational oracles.

Only isolated host compilers/tests run. No Windows image or target application runs.
"""
import argparse
import hashlib
import json
import random
import subprocess
import tempfile
from fractions import Fraction
from pathlib import Path


ORDINALS = dict(zip([
    'VarDecAdd','VarDecDiv','VarDecMul','VarDecSub','VarDecNeg','VarDecFromUI1','VarDecFromI2',
    'VarDecFromI4','VarDecFromR4','VarDecFromR8','VarDecFromStr','VarDecCmp','VarI2FromDec',
    'VarI4FromDec','VarR4FromDec','VarR8FromDec','VarBstrFromDec','VarUI1FromDec','VarDecFromUI2',
    'VarDecFromUI4','VarUI2FromDec','VarUI4FromStr','VarUI4FromDec','VarI8FromDec','VarDecFromI8',
    'VarDecFromUI8','VarUI8FromDec'],
    [177,178,179,181,189,190,191,192,193,194,197,204,208,212,216,220,232,240,242,243,269,277,282,345,374,375,441]))


def cdec(magnitude, scale=0, negative=False):
    return '{.wReserved=0,.scale=%d,.sign=%d,.Hi32=%du,.Lo64=%dULL}' % (
        scale,128 if negative else 0,magnitude >> 64,magnitude & ((1 << 64)-1))


def vectors():
    rng = random.Random(0x01a0f3d0cb43)
    ints = []
    boundaries = [0,1,2,5,15,25,35,45,125,135,(1<<31)-1,1<<31,
                  (1<<63)-1,1<<63,(1<<64)-1,1<<64,(1<<96)-1]
    inputs = [(n,scale,neg) for n in boundaries for scale in (0,1,2,27,28) for neg in (False,True)]
    # Values beyond double's exact integer range and ties on both sides of signed/unsigned limits.
    inputs += [(((1<<63)-1)*10+tail,1,neg) for tail in (0,4,5,6,9) for neg in (False,True)]
    inputs += [(((1<<64)-1)*10+tail,1,neg) for tail in (0,4,5,6,9) for neg in (False,True)]
    inputs += [(rng.getrandbits(96),rng.randrange(29),bool(rng.randrange(2))) for _ in range(2000)]
    for n,scale,neg in inputs:
        rounded = round(Fraction(-n if neg else n,10**scale))
        signed = -(1<<63) <= rounded < (1<<63)
        unsigned = 0 <= rounded < (1<<64)
        ints.append('{%s,%s,(LONG64)%dULL,%s,%dULL}' % (
            cdec(n,scale,neg),'S_OK' if signed else 'DISP_E_OVERFLOW',
            rounded & ((1<<64)-1) if signed else 0,'S_OK' if unsigned else 'DISP_E_OVERFLOW',rounded if unsigned else 0))
    math = []
    def append(op,am,ascl,an,bm,bscl,bn,value):
        scale=0
        # These generated exact arithmetic cases terminate within DECIMAL scale/range.
        while (value*10**scale).denominator != 1:
            scale += 1
            assert scale <= 28
        mag=abs(int(value*10**scale))
        assert mag < (1<<96)
        math.append('{%d,%s,%s,%s,S_OK}' % (op,cdec(am,ascl,an),cdec(bm,bscl,bn),cdec(mag,scale,value<0)))
    for _ in range(1000):
        am,bm=rng.getrandbits(38),rng.getrandbits(38)
        asc,bsc=rng.randrange(7),rng.randrange(7)
        an,bn=bool(rng.randrange(2)),bool(rng.randrange(2))
        a,b=Fraction(-am if an else am,10**asc),Fraction(-bm if bn else bm,10**bsc)
        for op,v in ((0,a+b),(1,a-b),(2,a*b)):
            append(op,am,asc,an,bm,bsc,bn,v)
    for _ in range(500):
        am=rng.getrandbits(48); bm=2**rng.randrange(8)*5**rng.randrange(8)
        asc,bsc=rng.randrange(5),rng.randrange(5); an,bn=bool(rng.randrange(2)),bool(rng.randrange(2))
        v=Fraction(-am if an else am,10**asc)/Fraction(-bm if bn else bm,10**bsc)
        append(3,am,asc,an,bm,bsc,bn,v)
    # Published Wine native regression values, with exact integer results across limb boundaries.
    append(0,(1<<64)-1,0,False,1,0,False,Fraction(1<<64))
    append(1,1<<64,0,False,1,0,False,Fraction((1<<64)-1))
    append(2,(1<<64)-1,0,False,2,0,False,Fraction(2*((1<<64)-1)))
    # A scale reduction whose rounding crosses a whole 32-bit limb. The original
    # DWORD+1 expression lost its carry before being assigned to ULONGLONG.
    rounded=(1<<93)|0xffffffff
    left=(1<<96)-1
    right=10*rounded+5-left
    append(0,left,1,False,right,1,False,Fraction(rounded+1))
    strings=[]
    for _ in range(600):
        magnitude=rng.getrandbits(rng.randrange(1,150))
        original_scale=rng.randrange(60)
        neg=bool(rng.randrange(2))
        value=Fraction(-magnitude if neg else magnitude,10**original_scale)
        chosen=None
        for scale in range(min(original_scale,28),-1,-1):
            rounded=round(value*10**scale)
            if abs(rounded)<(1<<96):
                chosen=(abs(rounded),scale,rounded<0)
                break
        source=('-' if neg else '')+str(magnitude)+'e-'+str(original_scale)
        strings.append('{(const WCHAR *)L"%s",%s,%s}' % (source,
                       cdec(*chosen) if chosen else cdec(0),'S_OK' if chosen else 'DISP_E_OVERFLOW'))
    result = ('struct int_vector { DECIMAL input; HRESULT signed_hr; LONG64 signed_value; HRESULT unsigned_hr; ULONG64 unsigned_value; };\n'
              'static const struct int_vector int_vectors[] = {\n'+',\n'.join(ints)+'\n};\n'
              'struct math_vector { unsigned op; DECIMAL a,b,expected; HRESULT hr; };\n'
              'static const struct math_vector math_vectors[] = {\n'+',\n'.join(math)+'\n};\n'
              'struct string_vector { const WCHAR *source; DECIMAL expected; HRESULT hr; };\n'
              'static const struct string_vector string_vectors[] = {\n'+',\n'.join(strings)+'\n};\n')
    return result, {'integer_vectors':len(ints),'exact_rational_math_vectors':len(math),'exact_rational_parse_vectors':len(strings),'seed':'01a0f3d0cb43',
                    'oracle':'Python Fraction + round(Fraction) half-even; no production body called to generate expected values'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output-dir',type=Path)
    args=ap.parse_args()
    w64=Path(__file__).resolve().parents[1]
    owned=[w64/'dlls/oleaut32'/name for name in ('decimal_wine.c','decimal_wine_int.h','decimal_string_wine.c','module.json')]
    owned += [w64/'tests'/name for name in ('decimal_host_contract.h','test_decimal_host.c','test_decimal_host.py')]
    readonly=[w64/'dlls/oleaut32'/name for name in ('bstr.c','variant.c','safearray.c')]
    inputs={p:p.read_bytes() for p in owned+readonly}
    config=json.loads(inputs[owned[3]])
    assert 'ucrtbase' in config['libs']
    assert all(config['ordinals'][n]==o for n,o in ORDINALS.items())
    assert len(set(config['ordinals'].values()))==len(config['ordinals'])
    text,oracle=vectors()
    records=[]
    with tempfile.TemporaryDirectory(prefix='win98-decimal-') as folder:
        tmp=Path(folder)
        for p,data in inputs.items():
            dest=tmp/p.relative_to(w64); dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(data)
        (tmp/'tests/oracle_vectors.inc').write_text(text)
        for cc,flags,label in [('gcc',['-O2'],'gcc'),('clang',['-O1','-g','-fsanitize=address,undefined',
                         '-fno-sanitize-recover=all','-fno-omit-frame-pointer'],'clang-san')]:
            exe=tmp/(label+'-contract')
            cmd=[cc,'-std=c11','-fshort-wchar','-Wall','-Wextra','-Werror','-Wno-unused-function',
                 '-Wno-unused-parameter',*flags,'-pthread',str(tmp/'tests/test_decimal_host.c'),'-lm','-o',str(exe)]
            built=subprocess.run(cmd,text=True,capture_output=True,timeout=180)
            if built.returncode: raise SystemExit(built.stdout+built.stderr)
            run=subprocess.run([str(exe)],text=True,capture_output=True,timeout=120)
            if run.returncode: raise SystemExit(run.stdout+run.stderr)
            records.append({'compiler':label,'build_command':cmd,'stdout':run.stdout,'exit_code':run.returncode,
                            'binary_sha256':hashlib.sha256(exe.read_bytes()).hexdigest()})
        if args.output_dir:
            args.output_dir.mkdir(parents=True,exist_ok=True)
            (args.output_dir/'oracle_vectors.inc').write_text(text)
    assert all(p.read_bytes()==data for p,data in inputs.items()), 'Consumed source changed during test'
    receipt={'status':'HOST_GCC_AND_CLANG_SAN_PASS','source_sha256':{str(p):hashlib.sha256(data).hexdigest() for p,data in inputs.items()},
             'oracle':oracle,'oracle_sha256':hashlib.sha256(text.encode()).hexdigest(),'runs':records,
             'claims':{'guest_run':False,'target_app_run':False,'all_27_fixed_ordinals_checked':True,
                       'host_nls_and_bstr_adapters':True,'existing_oleaut_production_C_unchanged':True}}
    if args.output_dir: (args.output_dir/'host-result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))


if __name__=='__main__': main()
