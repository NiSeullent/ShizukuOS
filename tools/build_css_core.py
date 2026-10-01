#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build bounded original CSS core; host tests/PE gate only. No VM/network/scripts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import pefile

ROOT=Path(__file__).resolve().parents[1]
PROJECT=["src/m98_css_syntax.h","src/m98_css_syntax.c",
 "src/m98_css_variables.h","src/m98_css_variables.c","src/m98_css_HANDOFF.md",
 "tests/m98_css_test_support.h","tests/m98_css_syntax_host.c",
 "tests/m98_css_variables_host.c","tests/m98_css_native_gate.c",
 "benchmarks/css-selected-vectors-v1.json","tools/build_css_core.py",
 "benchmarks/css-standards-source-v1/NOTICE.md",
 "platform/freestanding/memory.c","platform/freestanding/memory.h",
 "benchmarks/win98se-ko-oem-native-exports-v1.json","LICENSE"]
KINDS="WS IDENT FUNCTION AT HASH STRING BAD_STRING URL BAD_URL NUMBER PERCENTAGE DIMENSION CDO CDC COLON SEMICOLON COMMA LPAREN RPAREN LBRACKET RBRACKET LBRACE RBRACE DELIM".split()
EXPORTS=sorted(["m98_css_tokenize","m98_css_destroy","m98_css_count","m98_css_at",
 "m98_css_value","m98_css_number","m98_css_errors","m98_css_replacements",
 "m98_css_serialize","m98_css_ascii","m98_css_empty","m98_css_append",
 "m98_css_literal","m98_css_compute","m98_css_snapshot_destroy",
 "m98_css_property_count","m98_css_lookup","m98_css_substitute"])

def require(ok,message):
 if not ok:raise RuntimeError(message)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def units(s):
 b=s.encode("utf-16-le");return [int.from_bytes(b[i:i+2],"little") for i in range(0,len(b),2)]
def carray(values):return "{"+",".join(str(n) for n in values or [0])+"}"
def vector_header(v):
 require(v["schema"]==1 and v["profile"]=="current-css-variables-active-fallback-core-v1","vector profile")
 require(v["foreign_script_execution"] is False and v["browser_wpt_pass"] is False,"no foreign/browser claims")
 lines=["/* Generated from pinned hand-transcribed core vectors; foreign HTML/JS never executes. */",
  "typedef struct {unsigned kind,flags,delim; const uint32_t *value,*number; size_t value_length,number_length;} css_expected_token;",
  "typedef struct {const uint16_t *input;size_t units;const css_expected_token *tokens;size_t count;unsigned errors;int serialize;} css_syntax_vector;",
  "typedef struct {const char *const *names,*const *values,*const *expected;size_t count;} css_variable_vector;"]
 lines.append("#ifdef M98_CSS_VECTOR_SYNTAX")
 rows=[]
 for i,row in enumerate(v["syntax"]):
  require(0<len(row["input"])<=32768 and all(type(n) is int and 0<=n<=65535 for n in row["input"]),"UTF16 vector bound")
  lines.append(f"static const uint16_t input_{i}[]={carray(row['input'])};")
  ts=[]
  for j,t in enumerate(row["tokens"]):
   require(t["kind"] in KINDS and type(t["flags"]) is int and type(t["delim"]) is int,"token shape")
   for field in ("value","number"):
    require(all(type(n) is int and 0<n<=0x10ffff and not 0xd800<=n<=0xdfff for n in t[field]),"scalar vector")
    lines.append(f"static const uint32_t {field}_{i}_{j}[]={carray(t[field])};")
   ts.append("{"+f"M98_CSS_{t['kind']},{t['flags']},{t['delim']},value_{i}_{j},number_{i}_{j},{len(t['value'])},{len(t['number'])}"+"}")
  lines.append(f"static const css_expected_token tokens_{i}[]={{"+",".join(ts)+"};")
  rows.append("{"+f"input_{i},{len(row['input'])},tokens_{i},{len(ts)},{row['errors']},{int(row['serialize'])}"+"}")
 lines.append("static const css_syntax_vector syntax_vectors[]={"+",".join(rows)+"};")
 lines.append("#endif\n#ifdef M98_CSS_VECTOR_VARIABLES")
 rows=[]
 for i,row in enumerate(v["variables"]):
  require(0<len(row["names"])<=64 and len(row["names"])==len(row["values"])==len(row["expected"]),"variable vector shape")
  for key in ("names","values","expected"):
   require(all(s is None or isinstance(s,str) and s.isascii() and len(s)<512 for s in row[key]),"bounded ASCII core vector")
   lines.append(f"static const char *const {key}_{i}[]={{"+",".join("NULL" if s is None else json.dumps(s) for s in row[key])+"};")
  rows.append("{"+f"names_{i},values_{i},expected_{i},{len(row['names'])}"+"}")
 lines.append("static const css_variable_vector variable_vectors[]={"+",".join(rows)+"};")
 lines.append("#endif")
 return "\n".join(lines)+"\n"

def pinned_sources():
 result=list(PROJECT)
 for folder in ("wpt-css-selected-v1","css-standards-source-v1"):
  p=ROOT/"benchmarks"/folder/"source-pin.json";data=json.loads(p.read_text());result.append(str(p.relative_to(ROOT)))
  require(re.fullmatch("[0-9a-f]{40}",data["revision"]),"exact upstream revision")
  for name,row in data["files"].items():
   file=p.parent/"raw"/name
   require(file.resolve().is_relative_to(p.parent/"raw") and file.is_file() and not file.is_symlink(),"bounded source path")
   require(file.stat().st_size==row["bytes"]<=524288 and digest(file)==row["sha256"],"upstream raw source hash/size")
   result.append(str(file.relative_to(ROOT)))
 return sorted(result)

def instruction_gate(text):
 instructions=re.findall(r"^\s*[0-9a-f]+:\s+([a-z][a-z0-9.]*)\s*(.*)$",text,re.MULTILINE)
 require(len(instructions)>100,"actual machine instructions missing")
 bad=[]
 for mnemonic,operand in instructions:
  if (mnemonic.startswith(("cmov","fcmov","fcomi","fucomi","prefetch","xsave","xrstor","fisttp"))
    or mnemonic in {"cpuid","rdtsc","rdmsr","wrmsr","cmpxchg8b","sysenter","sysexit","fxsave","fxrstor","mfence","lfence","sfence","pause","monitor","mwait","ud2"}
    or re.search(r"%(?:[xyz]mm\d+|mm[0-7])\b",operand)):bad.append(mnemonic)
 require(not bad,"post-i486 linked instructions: "+repr(sorted(set(bad))))
 return {"instructions_decoded":len(instructions),"post_i486_families":"absent"}

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--build-dir",type=Path,default=ROOT/"build/css-core-v4")
 args=parser.parse_args();build=args.build_dir.resolve()
 require(build.is_relative_to(ROOT/"build") and not build.exists(),"fresh own build directory required")
 names=pinned_sources();hashes={n:digest(ROOT/n) for n in names}
 vectors=json.loads((ROOT/"benchmarks/css-selected-vectors-v1.json").read_text())
 wpt=json.loads((ROOT/"benchmarks/wpt-css-selected-v1/source-pin.json").read_text())
 require(vectors["wpt_revision"]==wpt["revision"] and vectors["raw_source_sha256"]=={k:v["sha256"] for k,v in wpt["files"].items()},"vector upstream pins")
 build.mkdir(parents=True);(build/"css_selected_vectors.h").write_text(vector_header(vectors))
 steps=[]
 def run(label,command,env=None):
  r=subprocess.run(command,cwd=ROOT,env=env,text=True,capture_output=True,timeout=60)
  p=build/(label+".log");p.write_text(r.stdout+r.stderr)
  steps.append(dict(name=label,command=command,returncode=r.returncode,log=str(p),sha256=digest(p)))
  require(r.returncode==0,label+" failed: "+r.stdout+r.stderr)
  return r.stdout.strip()
 receipt=dict(schema=1,kind="current-css-token-and-variable-core-build",profile=vectors["profile"],passed=False,source_sha256=hashes,steps=steps,
  foreign_script_execution=False,native_execution=False,mshtml_style_integration=False,native_paint=False,
  browser_wpt_pass=False,full_modern_css=False,full_browser=False,wasm=False,webgpu=False,webgl=False,modern_apps=False,vm_operations=False)
 try:
  common=["-std=c99","-O1","-g","-Wall","-Wextra","-Werror","-Isrc","-Itests","-I"+str(build)]
  core=["src/m98_css_syntax.c","src/m98_css_variables.c"]
  models={}
  for test in ("syntax","variables"):
   source="tests/m98_css_"+test+"_host.c";binary=build/(test+"-host")
   flag="-DM98_CSS_VECTOR_"+test.upper()
   run(test+"-host-build",["clang"]+common+[flag]+core+[source,"-o",str(binary)])
   normal=run(test+"-host-test",[str(binary)])
   sanitized=build/(test+"-sanitize")
   run(test+"-sanitize-build",["clang"]+common+[flag,"-fsanitize=address,undefined","-fno-omit-frame-pointer"]+core+[source,"-o",str(sanitized)])
   sanitizer=run(test+"-sanitize-test",[str(sanitized)],dict(os.environ,ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",UBSAN_OPTIONS="halt_on_error=1"))
   require(normal==sanitizer,"normal/sanitizer model mismatch")
   models[test]=dict(normal=normal,sanitizer=sanitizer)
  native=["-std=c99","-Os","-Wall","-Wextra","-Werror","-Isrc","-march=i486","-mno-sse","-mno-sse2","-mno-mmx","-fno-builtin","-fno-stack-protector","-mno-stack-arg-probe"]
  objects=[]
  for label,source in (("syntax",core[0]),("variables",core[1]),("memory","platform/freestanding/memory.c"),("entry","tests/m98_css_native_gate.c")):
   o=build/(label+".o");run("native-"+label,["i686-w64-mingw32-gcc"]+native+["-c",source,"-o",str(o)]);objects.append(o)
  archive=build/"libm98css.a";run("native-archive",["i686-w64-mingw32-ar","rcsD",str(archive)]+[str(p) for p in objects[:3]])
  exports=build/"M98CSS.def";exports.write_text("LIBRARY M98CSS\nEXPORTS\n"+"\n".join(" "+n for n in EXPORTS)+"\n")
  dll=build/"M98CSS.DLL"
  run("native-dll",["i686-w64-mingw32-gcc"]+native+["-shared","-nostdlib","-Wl,--entry,_m98_css_dll_entry@12",
   "-Wl,--subsystem,windows:4.10","-Wl,--major-os-version,4","-Wl,--minor-os-version,10",
   "-Wl,--disable-dynamicbase","-Wl,--disable-nxcompat","-Wl,--disable-tsaware","-Wl,--no-insert-timestamp",
   "-Xlinker","--stack","-Xlinker","2097152,524288"]+[str(p) for p in objects]+[str(exports),"-o",str(dll)])
  with pefile.PE(str(dll)) as pe:
   h=pe.OPTIONAL_HEADER
   require(pe.FILE_HEADER.Machine==0x14c and h.Magic==0x10b and pe.is_dll(),"x86 PE32 DLL required")
   require(pe.FILE_HEADER.TimeDateStamp==0,"deterministic PE timestamp")
   require((h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion)==(4,10) and h.Subsystem==2 and (h.MajorSubsystemVersion,h.MinorSubsystemVersion)==(4,10),"Win98 GUI4.10 headers")
   require(h.SizeOfStackReserve==2097152 and h.SizeOfStackCommit==524288 and h.AddressOfEntryPoint,"native stack/entry")
   require(not h.DllCharacteristics&(0x40|0x100|0x8000),"modern loader flags")
   require(h.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics&1,"relocations")
   require(all(not h.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)),"no TLS/loadconfig/delay/CLR")
   require(not getattr(pe,"DIRECTORY_ENTRY_IMPORT",[]),"pure core must have zero imports")
   # GNU ld emits a 20-byte all-zero terminator in .idata for a no-import DLL.
   # A present directory is permitted only when exactly that null descriptor.
   directory=h.DATA_DIRECTORY[1]
   if directory.VirtualAddress:
    require(directory.Size==20 and pe.get_data(directory.VirtualAddress,20)==bytes(20),"unexpected empty import-directory bytes")
   actual=[]
   for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    require(e.name and not e.forwarder,"no forwarded/ordinal-only exports");actual.append(e.name.decode("ascii"))
   require(sorted(actual)==EXPORTS,"exact public exports")
   require(dll.stat().st_size<=1048576,"bounded native DLL")
  machine=instruction_gate(run("native-disassembly",["i686-w64-mingw32-objdump","-d","--no-show-raw-insn",str(dll)]))
  require(hashes=={n:digest(ROOT/n) for n in names},"source drift during build")
  for name in names:
   dest=build/"source"/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest);require(digest(dest)==hashes[name],"frozen source copy")
  receipt.update(passed=True,models=models,artifacts={p.name:dict(sha256=digest(p),size=p.stat().st_size) for p in (dll,archive)},
   generated_sha256={p.name:digest(p) for p in (build/"css_selected_vectors.h",exports)},syntax_vector_count=len(vectors["syntax"]),variable_vector_count=len(vectors["variables"]),
   wpt_revision=wpt["revision"],standards_revision=json.loads((ROOT/"benchmarks/css-standards-source-v1/source-pin.json").read_text())["revision"])
  receipt["artifacts"][dll.name].update(pe98_gate="pass",imports={},exports=EXPORTS,stack_reserve=2097152,stack_commit=524288,i486_instructions=machine)
 except Exception as e:
  receipt["error"]=str(e);raise
 finally:
  # Failure receipts retain the same source closure as success, including a
  # compiler gate failure. Do not silently snapshot drift as original evidence.
  if hashes=={n:digest(ROOT/n) for n in names}:
   for name in names:
    dest=build/"source"/name
    if not dest.exists():dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,dest)
  (build/"result.json").write_text(json.dumps(receipt,indent=2)+"\n")
 print(json.dumps({"result":str(build/"result.json"),"sha256":digest(build/"result.json"),"models":models,"native_execution":False},indent=2))

if __name__=="__main__":main()
