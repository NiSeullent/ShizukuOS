#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze closed original-Win98 memory measurement; no VM or staging."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PARENTS = [
 ("build/resource-native-bridge-20261001T0758-v3/result.json", "831a13eb32c6a8722acbb8959b5006ca14e3300b8b9b07086561ec582f7b9e9e"),
 ("build/resource-adapter-validation-20261001T0725-v3/result.json", "5318fc335871c33836edb50e4b4079f7a5b3655592ee6cdf6f7e1a59c89a18b5"),
]
def sha(path):
 h=hashlib.sha256()
 with Path(path).open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
 return h.hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--out",type=Path,required=True);args=ap.parse_args();out=args.out.resolve()
 if out.exists() or not out.is_relative_to(ROOT/"build"):ap.error("absent private build directory required")
 if shutil.disk_usage(ROOT).free<17*1024**3+512*1024**2:ap.error("existing 17 GiB plus 512 MiB floor required")
 out.mkdir(parents=True)
 r={"schema":"win98modern.original-memory-status.v1","status":"FAIL","utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "native_executed":False,"application_success":False,"settings_changed":False,"memory_override":False,"staging_performed":False,
    "observer_own_os_exit_proven":False,"steps":[],"cmos_7240_kib":"unverified hypothesis; raw guest snapshots required"}
 def run(command,name,timeout=120):
  log=out/(name+".log")
  with log.open("wb") as f:
   try:process=subprocess.run(command,cwd=ROOT,stdout=f,stderr=f,timeout=timeout);code=process.returncode
   except subprocess.TimeoutExpired:
    r["steps"].append({"command":command,"exit_code":None,"timeout_seconds":timeout,"log":{"path":str(log),"sha256":sha(log)}});raise
  r["steps"].append({"command":command,"exit_code":code,"log":{"path":str(log),"sha256":sha(log)}})
  if code:raise ValueError("bounded build/control failed: "+name)
  return log.read_text()
 try:
  held={};r["parents"]=[]
  for name,pin in PARENTS:
   p=ROOT/name
   if sha(p)!=pin:raise ValueError("held parent receipt changed")
   parent=json.loads(p.read_text());held.update(parent["sources"])
   dest=out/"parents"/p.parent.name/p.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
   r["parents"].append({"path":str(p),"sha256":pin,"frozen":str(dest)})
  if any(sha(ROOT/name)!=pin for name,pin in held.items()):raise ValueError("held source closure changed before build")
  r["held_sources_checked"]=len(held)
  own=sorted(p for p in HERE.rglob("*") if p.is_file())
  kernel=ROOT/"ntwin32/process_exit";common_names=("original_kernel.h","original_kernel_win98_v3.c","main_image.h","main_image.c","win98_guard.h","win98_guard.c","win98_export.h","win98_export.c")
  inventory=ROOT/"benchmarks/win98se-ko-oem-native-exports-v1.json"
  contracts=json.loads((HERE/"contracts.json").read_text());oem=ROOT/contracts["oem_kernel_path"]
  if sha(oem)!=contracts["oem_kernel_sha256"]:raise ValueError("actual OEM Kernel32 input changed")
  with pefile.PE(str(oem)) as pe:
   exports={s.name.decode():s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
   if any(exports.get(k)!=v for k,v in contracts["oem_named_rvas"].items()):raise ValueError("actual OEM memory/time API export RVA changed")
  for item in json.loads((HERE/"primary/sources.json").read_text()):
   if sha(ROOT/item["path"])!=item["sha256"]:raise ValueError("pinned primary source changed")
  paths=own+[kernel/n for n in common_names]+[ROOT/"platform/freestanding"/n for n in ("memory.c","memory.h")]+[ROOT/"shizukufs/v1/tools"/n for n in ("sha256.c","sha256.h")]+[inventory,oem]
  pins={str(p.relative_to(ROOT)):sha(p) for p in paths};r["sources"]=pins
  for p in paths:
   dest=out/"frozen"/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
   if sha(dest)!=pins[str(p.relative_to(ROOT))]:raise ValueError("source changed while freezing")
  compiler={};r["toolchain"]=[]
  for name in ("gcc","clang","i686-w64-mingw32-gcc","i686-w64-mingw32-objdump","i686-w64-mingw32-nm"):
   p=shutil.which(name)
   if not p:raise ValueError("existing tool missing: "+name)
   compiler[name]=p;r["toolchain"].append({"name":name,"path":p,"sha256":sha(p),"version":run([p,"--version"],"version-"+name).splitlines()[0]})
  for name in ("gcc","i686-w64-mingw32-gcc"):
   p=Path(run([compiler[name],"-print-prog-name=cc1"],"cc1-"+name).strip()).resolve();r["toolchain"].append({"name":name+":cc1","path":str(p),"sha256":sha(p)})
  for flag in ("-print-prog-name=as","-print-prog-name=ld","-print-libgcc-file-name"):
   raw=run([compiler["i686-w64-mingw32-gcc"],flag],"component-"+flag.split("=")[-1].lstrip("-")).strip();p=Path(raw)
   if not p.is_file():p=Path(shutil.which(raw) or "missing")
   p=p.resolve();r["toolchain"].append({"name":flag,"path":str(p),"sha256":sha(p)})
  source=out/"frozen"/HERE.relative_to(ROOT);r["host_controls"]=[]
  for kind,cc,extra in (("normal",compiler["gcc"],[]),("sanitized",compiler["clang"],["--no-default-config","-fsanitize=address,undefined","-fno-sanitize-recover=all","-fno-omit-frame-pointer"])):
   for test in ("host_test","native_common_host_test"):
    dest=out/(test+"-"+kind);inputs=[str(source/"snapshot.c"),str(source/(test+".c"))]
    options=[]
    if test=="native_common_host_test":inputs.append(str(source/"native_common.c"));options=["-I",str(source/"mock")]
    run([cc]+extra+["-std=c11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-misleading-indentation"]+options+inputs+["-o",str(dest)],test+"-"+kind+"-compile")
    log=run([str(dest)],test+"-"+kind+"-controls");m=re.search(r"RESULT PASS cases=(\d+) checks=(\d+)",log)
    if not m or "Sanitizer" in log or "runtime error" in log:raise ValueError("meaningful host controls missing")
    r["host_controls"].append({"kind":kind,"test":test,"cases":int(m[1]),"checks":int(m[2]),"binary_sha256":sha(dest)})
  native=out/"frozen/ntwin32/process_exit";crypto=out/"frozen/shizukufs/v1/tools";cc=compiler["i686-w64-mingw32-gcc"]
  common=[str(native/n) for n in ("original_kernel_win98_v3.c","main_image.c","win98_guard.c","win98_export.c")]+[str(out/"frozen/platform/freestanding/memory.c")]
  flags=[cc,"-std=c11","-march=i486","-Os","-Wall","-Wextra","-Werror","-Wno-misleading-indentation","-fno-builtin","-fno-tree-loop-distribute-patterns","-fno-stack-protector","-ffunction-sections","-fdata-sections","-nostdlib","-Wl,--gc-sections","-Wl,--entry,_entry@0","-Wl,--subsystem,windows:4.10","-Wl,--major-os-version,4","-Wl,--minor-os-version,0","-Wl,--disable-dynamicbase","-Wl,--disable-nxcompat","-Wl,--disable-tsaware","-Wl,--no-insert-timestamp"]
  includes=["-I",str(out),"-I",str(crypto)]
  shared=[str(source/"snapshot.c"),str(source/"native_common.c")]+common
  run(flags+includes+[str(source/"native_probe.c"),str(source/"probe.def")]+shared+["-lkernel32","-lgcc","-o",str(out/"MEMSTAT.EXE")],"native-probe-build")
  (out/"memory_pins.h").write_text('#define MP_PROBE_BYTES %du\n#define MP_PROBE_SHA "%s"\n'%((out/"MEMSTAT.EXE").stat().st_size,sha(out/"MEMSTAT.EXE")))
  run(flags+includes+[str(source/"native_wait.c")]+shared+[str(crypto/"sha256.c"),"-lkernel32","-lgcc","-o",str(out/"MEMWAIT.EXE")],"native-observer-build")
  r["generated_headers"]={"memory_pins.h":sha(out/"memory_pins.h")}
  abi=run([compiler["i686-w64-mingw32-objdump"],"--disassemble=_mp_memory_call@8",str(out/"MEMSTAT.EXE")],"memory-stdcall-ABI")
  if "<_mp_memory_call@8>:" not in abi or not re.search(r"ret\s+\$0x8",abi) or not re.search(r"call\s+\*",abi):raise ValueError("actual indirect memory API wrapper stdcall ABI differs")
  r["compiled_ABI"]={"wrapper":"_mp_memory_call@8","wrapper_ret_pop":8,"original_memory_argument_bytes":4,"memory_status_bytes":32,"field_offsets":[0,4,8,12,16,20,24,28],"native_observed":False}
  # Pin and freeze actual SDK/compiler headers selected by the same compiler.
  header_paths=set()
  for name in ("native_probe.c","native_wait.c","native_common.c"):
   dep=out/(name+".d");run([cc,"-std=c11"]+includes+["-M","-MT","object","-MF",str(dep),str(source/name)],"dependencies-"+name)
   words=shlex.split(dep.read_text().replace("\\\n"," ").split(":",1)[1]);header_paths.update(Path(w).resolve() for w in words if Path(w).is_file())
  r["sdk_headers"]=[]
  for p in sorted(header_paths):
   if p.is_relative_to(out):continue
   pin=sha(p);dest=out/"toolchain_headers"/str(p).lstrip("/");dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
   r["sdk_headers"].append({"path":str(p),"sha256":pin,"frozen":str(dest)})
  available=json.loads(inventory.read_text())["dlls"];r["artifacts"]=[]
  for name in ("MEMSTAT.EXE","MEMWAIT.EXE"):
   p=out/name
   with pefile.PE(str(p)) as pe:
    o=pe.OPTIONAL_HEADER;classic=(pe.FILE_HEADER.Machine,o.Magic,o.Subsystem,o.MajorSubsystemVersion,o.MinorSubsystemVersion,o.MajorOperatingSystemVersion,o.MinorOperatingSystemVersion)
    if classic!=(0x14c,0x10b,2,4,10,4,0) or pe.is_dll() or not o.AddressOfEntryPoint:raise ValueError("classic i486 PE32 GUI profile differs")
    if pe.FILE_HEADER.TimeDateStamp or o.DllCharacteristics&0x140 or any(o.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)):raise ValueError("unexpected modern runtime directory/flags")
    imports={}
    for module in getattr(pe,"DIRECTORY_ENTRY_IMPORT",()):
     dll=module.dll.decode().upper();imports[dll]=[]
     for item in module.imports:
      if not item.name or dll!="KERNEL32.DLL" or item.name.decode() not in available.get(dll,[]):raise ValueError("outside actual original OEM imports")
      imports[dll].append(item.name.decode())
    if set(imports)!={"KERNEL32.DLL"} or "GlobalMemoryStatus" in imports["KERNEL32.DLL"]:raise ValueError("measurement must use verified original pointer, not direct status import")
    if p.stat().st_size>1024*1024:raise ValueError("existing classic per-input budget exceeded")
    r["artifacts"].append({"path":str(p),"bytes":p.stat().st_size,"sha256":sha(p),"classic_profile":list(classic),"imports":imports,"native_import_gate":"PASS","native_executed":False})
  if any(sha(ROOT/name)!=pin or sha(out/"frozen"/name)!=pin for name,pin in pins.items()):raise ValueError("source changed during build")
  if any(sha(ROOT/name)!=pin for name,pin in held.items()):raise ValueError("held source closure changed during build")
  if any(sha(i["path"])!=i["sha256"] for i in r["toolchain"]+r["sdk_headers"]):raise ValueError("toolchain or actual selected SDK header changed")
  if any(sha(ROOT/name)!=pin for name,pin in PARENTS):raise ValueError("held parent changed during build")
  r.update(status="HOST_BUILD_PASS_NATIVE_PENDING",sources_stable=True,held_sources_stable=True,original_api_calls_observed=False)
 except (OSError,ValueError,subprocess.TimeoutExpired,pefile.PEFormatError) as e:r["error"]=str(e)
 result=out/"result.json";result.write_text(json.dumps(r,indent=2)+"\n")
 if r["status"]=="HOST_BUILD_PASS_NATIVE_PENDING":
  manifest={"schema":1,"kind":"isolated-guest-file-inputs","inputs":[{"source":i["path"],"guest":"C:\\VXDLAB\\"+Path(i["path"]).name,"bytes":i["bytes"],"sha256":i["sha256"]} for i in r["artifacts"]],"outputs":["C:\\VXDLAB\\MEMSTAT.LOG","C:\\VXDLAB\\MEMWAIT.LOG"],"backups":[],"source_receipts":[{"path":str(result),"sha256":sha(result)}],"command":"C:\\VXDLAB\\MEMWAIT.EXE","scope":"Three immediate original OEM GlobalMemoryStatus snapshots and real own child wait; native pending; plan only, no staging, settings changes or app execution."}
  (out/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
 print(json.dumps({"status":r["status"],"result":str(result),"sha256":sha(result),"error":r.get("error")}));return 0 if r["status"]=="HOST_BUILD_PASS_NATIVE_PENDING" else 1
if __name__=="__main__":raise SystemExit(main())
