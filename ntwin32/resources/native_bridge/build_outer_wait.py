#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a separate real child observer for held native resource bridge v3."""
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
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BASE=ROOT/"build/resource-native-bridge-20261001T0758-v3"
MEMORY=ROOT/"build/win98-memory-status-20261001T0850-v1"
PARENTS=[
 (BASE/"result.json","831a13eb32c6a8722acbb8959b5006ca14e3300b8b9b07086561ec582f7b9e9e"),
 (BASE/"manifest.json","3d56e175925db1ef36f7c80eae88f54e58293065f3255d330538a01b8f4b46a1"),
 (ROOT/"build/resource-native-bridge-independent-review-20261001T082824-v3/review.json","40f715268379dffd4f25c8663a09aaf2cb1f0eedb4833056043fb7ad1e90ddbe"),
 (MEMORY/"result.json","a03ddfc54d0c593df459eb3b465835ddd2af3d6e67c1df65f7845af6e59592cc"),
 (MEMORY/"manifest.json","c964f6b4a990058140366476ce1a3c05a198f0ce656e51f0964b90ad44a8a536"),
 (ROOT/"build/resource-native-bridge-outer-20261001T0925-v1/result.json","a95edc4ca1098b44dbc41a27ba7173723c0458566216652e4cec3b2a040b3703"),
 (ROOT/"build/resource-native-bridge-outer-20261001T0925-v1/manifest.json","181ccf6faaf9a5b3d4431dc7e4d2e56363dfb0fabb6c7324bb8d06d3ecfe8ad3"),
]
PROBE_BYTES=100618
PROBE_SHA="ae00f32b55634a9939881cc792d2af5ada72994860f186b9447e10172f39f497"
def sha(p):
 h=hashlib.sha256()
 with Path(p).open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
 return h.hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--out",required=True,type=Path);args=ap.parse_args();out=args.out.resolve()
 if out.exists() or not out.is_relative_to(ROOT/"build"):ap.error("absent private build directory required")
 if shutil.disk_usage(ROOT).free<17*1024**3+512*1024**2:ap.error("existing 17 GiB plus 512 MiB floor required")
 out.mkdir(parents=True)
 r={"schema":"win98modern.resource-bridge-outer.v1","status":"FAIL","utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"steps":[],
    "native_executed":False,"application_success":False,"staging_performed":False,"runtime_admission_changed":False,"observer_own_os_exit_proven":False}
 def run(command,name,timeout=120):
  log=out/(name+".log")
  with log.open("wb") as f:
   try:p=subprocess.run(command,cwd=ROOT,stdout=f,stderr=f,timeout=timeout);code=p.returncode
   except subprocess.TimeoutExpired:
    r["steps"].append({"command":command,"exit_code":None,"timeout_seconds":timeout,"log":{"path":str(log),"sha256":sha(log)}});raise
  r["steps"].append({"command":command,"exit_code":code,"log":{"path":str(log),"sha256":sha(log)}})
  if code:raise ValueError("bounded build/control failed: "+name)
  return log.read_text()
 try:
  r["parents"]=[]
  for p,pin in PARENTS:
   if sha(p)!=pin:raise ValueError("held producer/manifest/review changed")
   dest=out/"parents"/p.parent.name/p.name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
   if sha(dest)!=pin:raise ValueError("parent changed while freezing")
   r["parents"].append({"path":str(p),"sha256":pin,"frozen":str(dest)})
  bridge=json.loads((BASE/"result.json").read_text());memory=json.loads((MEMORY/"result.json").read_text());held=dict(bridge["sources"]);held.update(memory["sources"])
  if len(bridge["sources"])!=51 or len(memory["sources"])!=30 or any(sha(ROOT/n)!=pin for n,pin in held.items()):raise ValueError("held 51 bridge/30 memory sources changed")
  r["held_closures"]={"bridge_sources":51,"memory_sources":30,"unique_sources":len(held)}
  manifest=json.loads((BASE/"manifest.json").read_text())
  if len(manifest["inputs"])!=4 or manifest["outputs"]!=["C:\\VXDLAB\\RBPROBE.LOG"] or manifest["backups"]:raise ValueError("held original four-input plan changed")
  r["held_inputs"]=[]
  for i in manifest["inputs"]:
   p=Path(i["source"])
   if p.stat().st_size!=i["bytes"] or sha(p)!=i["sha256"]:raise ValueError("held actual closed graph input changed")
   dest=out/"inputs"/p.name;dest.parent.mkdir(exist_ok=True);shutil.copyfile(p,dest)
   if sha(dest)!=i["sha256"]:raise ValueError("input changed while freezing")
   r["held_inputs"].append(dict(i,frozen=str(dest)))
  probe=BASE/"RBPROBE.EXE"
  if probe.stat().st_size!=PROBE_BYTES or sha(probe)!=PROBE_SHA:raise ValueError("exact whole child pin changed")
  kernel=ROOT/"ntwin32/process_exit";names=("original_kernel.h","original_kernel_win98_v3.c","main_image.h","main_image.c","win98_guard.h","win98_guard.c","win98_export.h","win98_export.c")
  inventory=ROOT/"benchmarks/win98se-ko-oem-native-exports-v1.json"
  paths=[HERE/"outer_wait.c",HERE/"build_outer_wait.py"]+[kernel/n for n in names]+[ROOT/"platform/freestanding"/n for n in ("memory.c","memory.h")]+[ROOT/"shizukufs/v1/tools"/n for n in ("sha256.c","sha256.h")]+[inventory]
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
  source=out/"frozen"/HERE.relative_to(ROOT);native=out/"frozen/ntwin32/process_exit";crypto=out/"frozen/shizukufs/v1/tools"
  header=out/"rbwait_pins.h";header.write_text('#define RB_PROBE_BYTES %du\n#define RB_PROBE_SHA "%s"\n'%(PROBE_BYTES,PROBE_SHA));r["generated_headers"]={header.name:sha(header)}
  includes=["-I",str(out),"-I",str(crypto)];r["host_controls"]=[]
  for kind,cc,extra in (("normal",compiler["gcc"],[]),("sanitized",compiler["clang"],["--no-default-config","-fsanitize=address,undefined","-fno-sanitize-recover=all","-fno-omit-frame-pointer"])):
   exe=out/("observer-host-"+kind)
   run([cc]+extra+["-std=c11","-O1","-g","-Wall","-Wextra","-Werror","-Wno-misleading-indentation","-DRBWAIT_HOST_TEST"]+includes+[str(source/"outer_wait.c"),str(crypto/"sha256.c"),"-o",str(exe)],kind+"-compile")
   log=run([str(exe),str(out/"inputs/RBPROBE.EXE")],kind+"-controls");m=re.search(r"RESULT PASS cases=(\d+) checks=(\d+) clobbering_callbacks=true actual_child_executed=false",log)
   if not m or "Sanitizer" in log or "runtime error" in log:raise ValueError("actual observer failure/EOF controls missing")
   r["host_controls"].append({"kind":kind,"cases":int(m[1]),"checks":int(m[2]),"binary_sha256":sha(exe)})
  cc=compiler["i686-w64-mingw32-gcc"]
  flags=[cc,"-std=c11","-march=i486","-Os","-Wall","-Wextra","-Werror","-Wno-misleading-indentation","-fno-builtin","-fno-tree-loop-distribute-patterns","-fno-stack-protector","-ffunction-sections","-fdata-sections","-nostdlib","-Wl,--gc-sections","-Wl,--entry,_entry@0","-Wl,--subsystem,windows:4.10","-Wl,--major-os-version,4","-Wl,--minor-os-version,0","-Wl,--disable-dynamicbase","-Wl,--disable-nxcompat","-Wl,--disable-tsaware","-Wl,--no-insert-timestamp"]
  common=[str(native/n) for n in ("original_kernel_win98_v3.c","main_image.c","win98_guard.c","win98_export.c")]+[str(out/"frozen/platform/freestanding/memory.c"),str(crypto/"sha256.c")]
  run(flags+includes+[str(source/"outer_wait.c")]+common+["-lkernel32","-lgcc","-o",str(out/"RBWAIT.EXE")],"native-observer-build")
  dep=out/"native-headers.d";run([cc,"-std=c11"]+includes+["-M","-MT","object","-MF",str(dep),str(source/"outer_wait.c")],"actual-header-dependencies")
  r["sdk_headers"]=[]
  for p in sorted({Path(w).resolve() for w in shlex.split(dep.read_text().replace("\\\n"," ").split(":",1)[1]) if Path(w).is_file()}):
   if p.is_relative_to(out):continue
   pin=sha(p);dest=out/"toolchain_headers"/str(p).lstrip("/");dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest);r["sdk_headers"].append({"path":str(p),"sha256":pin,"frozen":str(dest)})
  abi=run([compiler["i686-w64-mingw32-objdump"],"--disassemble=_entry@0",str(out/"RBWAIT.EXE")],"compiled-observer-ABI")
  if "<_entry@0>:" not in abi or not re.search(r"\bcall\s+\*",abi) or "$0x7530" not in abi or "$0x1388" not in abi:raise ValueError("actual indirect native calls/30s/5s compiled observer differ")
  r["compiled_ABI"]={"entry":"_entry@0","process_struct_bytes":16,"startup_struct_bytes":68,"real_wait_ms":30000,"forced_reap_ms":5000,"forced_exit":125,"actual_native_observed":False}
  r["full_child_report_contract"]={"ordinary_result":20,"sequential_graphs":["mapped EXE","mapped DLL root"],"native_controls_per_graph":14,"success_last_error":"0x51a2b3c4","application_checks_minimum":35,"dll_fixture_return":0,"detach_successes_per_graph":4,"detach_failures_per_graph":0,"post_cleanup_handle_error":6,"final_selected_result":0,"complete_CRLF_EOF_required":True,"native_observed":False}
  path=out/"RBWAIT.EXE";available=json.loads(inventory.read_text())["dlls"]
  with pefile.PE(str(path)) as pe:
   o=pe.OPTIONAL_HEADER;classic=(pe.FILE_HEADER.Machine,o.Magic,o.Subsystem,o.MajorSubsystemVersion,o.MinorSubsystemVersion,o.MajorOperatingSystemVersion,o.MinorOperatingSystemVersion)
   if classic!=(0x14c,0x10b,2,4,10,4,0) or pe.is_dll() or not o.AddressOfEntryPoint:raise ValueError("classic i486 PE32 GUI profile differs")
   if pe.FILE_HEADER.TimeDateStamp or o.DllCharacteristics&0x140 or any(o.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)):raise ValueError("unexpected modern runtime directory/flags")
   imports={}
   for module in pe.DIRECTORY_ENTRY_IMPORT:
    dll=module.dll.decode().upper();imports[dll]=[]
    for item in module.imports:
     if not item.name or dll!="KERNEL32.DLL" or item.name.decode() not in available.get(dll,[]):raise ValueError("outside actual original OEM imports")
     imports[dll].append(item.name.decode())
   if set(imports)!={"KERNEL32.DLL"} or any(n in imports["KERNEL32.DLL"] for n in ("CreateProcessA","WaitForSingleObject","GetExitCodeProcess","TerminateProcess")):raise ValueError("must use verified original process API pointers")
  if path.stat().st_size>1024*1024:raise ValueError("existing classic per-input budget exceeded")
  r["artifact"]={"path":str(path),"bytes":path.stat().st_size,"sha256":sha(path),"classic_profile":list(classic),"imports":imports,"native_import_gate":"PASS","native_executed":False}
  if any(sha(ROOT/n)!=pin or sha(out/"frozen"/n)!=pin for n,pin in pins.items()):raise ValueError("observer source changed during build")
  if any(sha(ROOT/n)!=pin for n,pin in held.items()) or any(sha(p)!=pin for p,pin in PARENTS):raise ValueError("held bridge/memory closure changed during build")
  if any(sha(i["source"])!=i["sha256"] or sha(i["frozen"])!=i["sha256"] for i in r["held_inputs"]):raise ValueError("actual original graph changed during build")
  if any(sha(i["path"])!=i["sha256"] for i in r["toolchain"]+r["sdk_headers"]):raise ValueError("toolchain or selected SDK header changed")
  r.update(status="HOST_BUILD_PASS_NATIVE_PENDING",sources_stable=True,held_sources_stable=True,held_inputs_stable=True)
 except (OSError,ValueError,subprocess.TimeoutExpired,pefile.PEFormatError) as e:r["error"]=str(e)
 result=out/"result.json";result.write_text(json.dumps(r,indent=2)+"\n")
 if r["status"]=="HOST_BUILD_PASS_NATIVE_PENDING":
  plan=dict(manifest);plan["inputs"]=list(manifest["inputs"])+[{"source":r["artifact"]["path"],"guest":"C:\\VXDLAB\\RBWAIT.EXE","bytes":r["artifact"]["bytes"],"sha256":r["artifact"]["sha256"]}]
  plan.update(outputs=["C:\\VXDLAB\\RBPROBE.LOG","C:\\VXDLAB\\RBWAIT.LOG"],command="C:\\VXDLAB\\RBWAIT.EXE",scope="Plan only: exact unchanged four-input closed resource graph plus separate original-OEM child exit observer. No staging, settings, admission changes or Chromium execution.")
  plan["source_receipts"]=list(manifest["source_receipts"])+[{"path":str(result),"sha256":sha(result)}]
  (out/"manifest.json").write_text(json.dumps(plan,indent=2)+"\n")
 print(json.dumps({"status":r["status"],"result":str(result),"sha256":sha(result),"error":r.get("error")}));return 0 if r["status"]=="HOST_BUILD_PASS_NATIVE_PENDING" else 1
if __name__=="__main__":raise SystemExit(main())
