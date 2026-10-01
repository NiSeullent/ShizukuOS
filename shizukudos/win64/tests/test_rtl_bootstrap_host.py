#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exact additive RTL sources, independent Python oracles, explicit host providers."""
import argparse
import hashlib
import json
import random
import subprocess
import tempfile
import unicodedata
from pathlib import Path

SOURCES=['rtl_bootstrap_strings.c','rtl_bootstrap_utf8.h','rtl_bootstrap_case.c','rtl_bootstrap_once.c','rtl_bootstrap_perf.c']
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();args.output_dir.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[1]
    owned=[root/'ntdll'/n for n in SOURCES]+[root/'tests'/n for n in ['test_rtl_bootstrap_host.c','test_rtl_bootstrap_host.py','rtl_bootstrap_host_contract.h']]
    readonly=[root/'kernel32/unidata.h']
    data={p:p.read_bytes() for p in owned+readonly}
    rng=random.Random(0x01a0f3d0cb43)
    valid=['','ASCII','\0','x\0y','한글','😀','éöΩя','\U0010ffff','\uffff','\ud7ff\ue000']
    for _ in range(3000):
        words=[]
        for _ in range(rng.randrange(40)):
            value=rng.randrange(0x110000)
            if 0xd800<=value<=0xdfff:value=0xfffd
            words.append(chr(value))
        valid.append(''.join(words))
    vectors=[];bytes_flat=[];words_flat=[]
    for value in valid:
        encoded=value.encode('utf-8');wide=value.encode('utf-16le')
        words=[wide[i]|wide[i+1]<<8 for i in range(0,len(wide),2)]
        vectors.append((len(bytes_flat),len(encoded),len(words_flat),len(words)))
        bytes_flat.extend(encoded);words_flat.extend(words)
    # Explicit pinned Wine malformed-subsequence contract, including truncation.
    malformed=[(b'\xc0\xaf',[0xfffd,0xfffd]),(b'\xed\xa0\x80',[0xfffd,0xfffd]),
               (b'\xe2\x82',[0xfffd]),(b'\xe2A',[0xfffd]),(b'\x80Z',[0xfffd,ord('Z')]),
               (b'\xf4\x90\x80\x80',[0xfffd,0xfffd,0xfffd])]
    for encoded,words in malformed:
        vectors.append((len(bytes_flat),len(encoded),len(words_flat),len(words)))
        bytes_flat.extend(encoded);words_flat.extend(words)
    upper=[]
    for value in range(65536):
        mapped=chr(value).upper()
        upper.append(ord(mapped) if len(mapped)==1 and ord(mapped)<=0xffff else value)
    oracle=('static const WCHAR uppercase_expected[]={'+','.join(map(str,upper))+'};\n'
            +'static const unsigned char utf8_bytes[]={'+','.join(map(str,bytes_flat))+'};\n'
            +'static const WCHAR utf16_words[]={'+','.join(map(str,words_flat))+'};\n'
            +'struct utf8_vector {unsigned byte_offset,bytes,word_offset,units;};\n'
            +'static const struct utf8_vector utf8_vectors[]={'+','.join('{'+','.join(map(str,row))+'}' for row in vectors)+'};\n'
            +'static const unsigned utf8_vector_count='+str(len(vectors))+';\n')
    (args.output_dir/'rtl_bootstrap_vectors.inc').write_text(oracle)
    runs=[]
    with tempfile.TemporaryDirectory(prefix='win98-rtl-bootstrap-') as temporary:
        stage=Path(temporary)
        for source,content in data.items():
            target=stage/source.relative_to(root);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(content)
        (stage/'tests/rtl_bootstrap_vectors.inc').write_text(oracle)
        for compiler,flags,label in [('gcc',['-O2'],'gcc'),('clang',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'],'clang-san')]:
            binary=stage/label
            command=[compiler,'-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter',*flags,'-pthread','-DSHZ_RTL_BOOTSTRAP_HOST','-I',str(stage/'tests'),*[str(stage/'ntdll'/n) for n in SOURCES if n.endswith('.c')],str(stage/'tests/test_rtl_bootstrap_host.c'),'-o',str(binary)]
            result=subprocess.run(command,capture_output=True,text=True,timeout=120)
            row={'compiler':label,'command':command,'compile_exit':result.returncode,'compile_stdout':result.stdout,'compile_stderr':result.stderr}
            if not result.returncode:
                executed=subprocess.run([str(binary)],capture_output=True,text=True,timeout=60)
                row.update({'exit_code':executed.returncode,'stdout':executed.stdout,'stderr':executed.stderr,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
            runs.append(row)
            if result.returncode or row.get('exit_code'):
                (args.output_dir/'failed-result.json').write_text(json.dumps({'status':'PRESERVED_FIRST_FAILURE','runs':runs},indent=2)+'\n')
                raise SystemExit(result.stdout+result.stderr+row.get('stdout','')+row.get('stderr',''))
    assert all(p.read_bytes()==content for p,content in data.items()),'Consumed source changed'
    receipt={'status':'HOST_GCC_AND_CLANG_SAN_PASS','runs':runs,'source_sha256':{str(p):hashlib.sha256(content).hexdigest() for p,content in data.items()},'oracle_sha256':hashlib.sha256(oracle.encode()).hexdigest(),'case_oracle':'Python upper with single BMP code-unit result; existing immutable provider Unicode14, independently checked against Python '+unicodedata.unidata_version,'valid_utf8_python_vectors':len(valid),'pinned_Wine_malformed_vectors':len(malformed),'claims':{'host_pthread_contention':96,'actual_Windows_NT_execution':False,'application_execution':False}}
    (args.output_dir/'host-result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'status':receipt['status'],'runs':[{k:row[k] for k in ['compiler','stdout']} for row in runs]},indent=2))
if __name__=='__main__':main()
