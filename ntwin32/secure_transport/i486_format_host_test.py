#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real formatter C against an independent libc oracle and a legacy CRT model."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

DRIVER = r'''
#include "i486_format.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
static unsigned checks, failures, calls;
static int broken;
#define CHECK(c) do { ++checks; if (!(c)) { ++failures; fprintf(stderr,"FAIL line %d\n",__LINE__); } } while (0)
int ntwst_test_legacy_vsnprintf(char *out,size_t cap,const char *fmt,va_list args) {
 char normalized[20000];size_t i=0,n=0;int result;
 ++calls;
 if (broken) return -1;
 /* Linux model of the OEM's I64 integer spelling and negative truncation.
  * It supplies no evidence about execution of a Windows runtime. */
 while(fmt[i]) {
  if(!strncmp(fmt+i,"I64",3)){normalized[n++]='l';normalized[n++]='l';i+=3;}
  else normalized[n++]=fmt[i++];
 }
 normalized[n]=0;
 result=vsnprintf(out,cap,normalized,args);
 if(result>=0 && (size_t)result>=cap){memset(out,'!',cap);return -1;}
 return result;
}
#define SAME(f,...) do { \
 char expect[9010],actual[9010];size_t caps[]={0,1,2,5,16,127,128,129,512,9000}; \
 unsigned j;int size=snprintf(expect,sizeof expect,f,__VA_ARGS__); \
 for(j=0;j<sizeof caps/sizeof caps[0];++j) { \
  size_t cap=caps[j],n;memset(actual,0x5a,sizeof actual); \
  CHECK(ntwst_i486_snprintf(cap?actual:NULL,cap,f,__VA_ARGS__)==size); \
  if(cap){n=(size_t)size<cap-1?(size_t)size:cap-1;CHECK(!memcmp(actual,expect,n));CHECK(actual[n]==0);CHECK((unsigned char)actual[cap]==0x5a);} \
 } \
} while(0)
#define BAD(f,...) do{char actual[32],saved[32];memset(actual,0x5a,sizeof actual);memcpy(saved,actual,sizeof saved);CHECK(ntwst_i486_snprintf(actual,sizeof actual,f,__VA_ARGS__)==-1);CHECK(!memcmp(actual,saved,sizeof actual));}while(0)
int main(void) {
 char text[8193],empty[8],saved[8];unsigned i;int target=91;char *huge;
 SAME("%d",INT_MIN);SAME("%+09d",-17);SAME("% i",31);
 SAME("%u",UINT_MAX);SAME("%#08x",0x314u);SAME("%#X",UINT_MAX);SAME("%#o",31u);
 SAME("%hd",(int)SHRT_MIN);SAME("%hu",(int)USHRT_MAX);
 SAME("%ld",LONG_MIN);SAME("%lu",ULONG_MAX);
 SAME("%lld",LLONG_MIN);SAME("%llu",ULLONG_MAX);
 SAME("%020llu",ULLONG_MAX);SAME("%#.0x",0u);
 SAME("%zu",(size_t)123456);SAME("%td",(ptrdiff_t)-321);
 SAME("%c %s %% %d",'q',"example",-127);SAME("%-*s: %d bits",13,"RSA",2048);
 SAME("%.*s",5,"certificate");SAME("%.*s",-3,"certificate");
 SAME("%*d",-14,42);SAME("%04d-%02d-%02d",2026,10,1);
 memset(text,'t',sizeof text-1);text[sizeof text-1]=0;
 SAME("%s",text);SAME("%4096u",11u);
 for(i=0;i<120;++i) { int value=(int)i*719-30000;SAME("%+09d/%#08x/%-12.7s",value,(unsigned)value,"short"); }
 memset(empty,0x5a,sizeof empty);memcpy(saved,empty,sizeof saved);
 CHECK(ntwst_i486_snprintf(empty,sizeof empty,"%n",&target)==-1 && target==91 && !memcmp(empty,saved,sizeof empty));
 BAD("%f",1.2);BAD("%ls",(void*)text);BAD("%hhd",3);BAD("%4097u",1u);
 BAD("%*u",4097,1u);BAD("%.*s",4097,"abc");BAD("%s",(char*)NULL);
 BAD("%q",1u);BAD("%",1u);BAD("%1$d",1);
 CHECK(ntwst_i486_snprintf(NULL,1,"abc")==-1);
 CHECK(ntwst_i486_snprintf(empty,sizeof empty,NULL)==-1);
 CHECK(ntwst_i486_snprintf(NULL,0,"abc")==3);
 huge=malloc(1024*1024+2);CHECK(huge!=NULL);if(huge){memset(huge,'z',1024*1024+1);huge[1024*1024+1]=0;BAD("%s",huge);free(huge);}
 broken=1;BAD("%s","valid");broken=0;
 printf("{\"checks\":%u,\"failures\":%u,\"legacy_calls\":%u,\"windows_execution\":false}\n",checks,failures,calls);
 return failures?1:0;
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    out = args.out.absolute()
    if out.exists() or out.is_symlink():
        parser.error("new private output required")
    out.mkdir(parents=True, mode=0o700)
    source = Path(__file__).resolve().parent
    before = {n: sha(source / n) for n in ("i486_format.c", "i486_format.h")}
    for name in before:
        shutil.copyfile(source / name, out / name)
    (out / "driver.c").write_text(DRIVER)
    compiler = shutil.which("clang" if args.sanitize else "gcc")
    command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wpedantic", "-DNTWST_FORMAT_HOST_MODEL=1", "-I" + str(out),
               str(out / "driver.c"), str(out / "i486_format.c"), "-o", str(out / "model")]
    if args.sanitize:
        command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    compiled = subprocess.run(command, capture_output=True, timeout=60)
    (out / "compile.log").write_bytes(compiled.stdout + compiled.stderr)
    runs = [{"argv": command, "exit": compiled.returncode}]
    model = None
    if not compiled.returncode:
        tested = subprocess.run([str(out / "model")], capture_output=True, timeout=30)
        (out / "model.stdout").write_bytes(tested.stdout)
        (out / "model.stderr").write_bytes(tested.stderr)
        runs.append({"argv": [str(out / "model")], "exit": tested.returncode})
        if tested.stdout:
            model = json.loads(tested.stdout.splitlines()[-1])
    passed = len(runs) == 2 and not any(x["exit"] for x in runs) and \
        before == {n: sha(source / n) for n in before}
    receipt = {"status": "PASS" if passed else "FAIL", "scope": "libc oracle and modeled legacy truncation; no Windows execution",
               "source_sha256": before, "compiler": {"path": compiler, "sha256": sha(Path(compiler))},
               "runs": runs, "model": model, "sanitize": args.sanitize,
               "outputs": {p.name: sha(p) for p in out.iterdir() if p.is_file()}}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "model": model, "out": str(out)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
