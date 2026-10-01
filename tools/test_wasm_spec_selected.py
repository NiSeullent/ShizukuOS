#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile original selected official WAST and execute its numeric binary oracles."""
import argparse,hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SPEC_REV="bc030375d734de845aa2246b783ca6a7ee865eb4"
SOURCE=ROOT/"build/wasm-spec-selected-sources-v2"
SOURCE_PIN="a9beffe4d27b6e52c6fb5b925cd6f881d9a64fbaabd921099f294b6cc42a8724"
TOOLS=ROOT/"build/wasm-fixture-tools-v1"
TOOL_PIN="ca8af3c91976d1b7676fbfe0951db4f603922338ba294daa893909a5085b7c05"
WABT=TOOLS/"wabt-1.0.42/bin/wast2json"
OWN=["tests/m98_wasm_spec_host.c","tools/test_wasm_spec_selected.py","docs/TRIDENT_WASM_SPEC_SELECTED.md"]
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def value(row):
 kinds={"i32":0,"i64":1,"f32":2,"f64":3};require(row["type"] in kinds,"numeric profile only")
 n=row["value"];nan=1 if n=="nan:canonical" else 2 if n=="nan:arithmetic" else 0
 if nan:n=0
 else:n=int(n);require(0<=n<=2**(32 if row["type"] in ("i32","f32") else 64)-1,"numeric bits")
 return "{"+str(kinds[row["type"]])+",UINT64_C("+str(n)+")}",nan
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--runtime-build",type=Path,required=True);p.add_argument("--runtime-receipt-sha",required=True);p.add_argument("--build-dir",type=Path,required=True);args=p.parse_args()
 runtime=args.runtime_build.resolve();build=args.build_dir.resolve();require(runtime.parent==ROOT/"build" and build.parent==ROOT/"build" and not build.exists(),"owned fresh direct build child")
 rp=runtime/"result.json";require(re.fullmatch("[0-9a-f]{64}",args.runtime_receipt_sha) and not rp.is_symlink() and rp.stat().st_size<=2097152 and sha(rp)==args.runtime_receipt_sha,"caller-pinned bounded runtime receipt")
 rdata=json.loads(rp.read_text());require(rdata["passed"] is True and rdata["native_execution"] is False,"successful static runtime build, no native claim")
 for name,digest in rdata["source_sha256"].items():require(sha(ROOT/name)==digest and sha(runtime/"source"/name)==digest,"current/frozen runtime source")
 for name,row in rdata["prepared_files"].items():
  file=runtime/"prepared"/name;require(file.resolve().is_relative_to(runtime/"prepared") and not file.is_symlink() and file.stat().st_size==row["bytes"] and sha(file)==row["sha256"],"prepared runtime source closure")
 for step in rdata["steps"]:
  log=Path(step["log"]);require(log.resolve().is_relative_to(runtime) and not log.is_symlink() and log.stat().st_size<=8388608 and sha(log)==step["sha256"],"original runtime command log")
 require(sha(SOURCE/"source-pin.json")==SOURCE_PIN and sha(TOOLS/"tool-pin.json")==TOOL_PIN,"selected official/tool manifest pins")
 originals=json.loads((SOURCE/"source-pin.json").read_text());tools=json.loads((TOOLS/"tool-pin.json").read_text());require(originals["revision"]==SPEC_REV and tools["version"]=="1.0.42","official versions")
 for base,files in ((SOURCE/"raw",originals["files"]),(TOOLS,tools["files"])):
  for name,row in files.items():
   file=base/name;require(file.resolve().is_relative_to(base) and not file.is_symlink() and file.stat().st_size==row["bytes"] and sha(file)==row["sha256"],"original dependency member")
 archive=TOOLS/"wabt-1.0.42-linux-x64.tar.gz";require(archive.stat().st_size==tools["archive_bytes"] and sha(archive)==tools["archive_sha256"],"original host fixture compiler archive")
 pins={n:sha(ROOT/n) for n in OWN};build.mkdir();steps=[];exclusions=[];commands=[];generated=[]
 receipt=dict(schema=1,kind="actual-selected-official-Wasm-numeric-core-oracles",passed=False,source_sha256=pins,runtime_receipt_sha256=sha(rp),spec_revision=SPEC_REV,official_source_pin_sha256=SOURCE_PIN,wabt_tool_pin_sha256=TOOL_PIN,steps=steps,exclusions=exclusions,native_execution=False,browser_js_api=False,browser_wasm=False,full_modern_wasm=False,full_browser=False,modern_apps=False,vm_operations=False,foreign_test_script_execution=False,foreign_host_fixture_compiler_execution=True)
 def run(label,cmd,env=None):
  result=subprocess.run(cmd,cwd=ROOT,env=env,text=True,capture_output=True,timeout=90);log=build/(label+".log");log.write_text(result.stdout+result.stderr);require(log.stat().st_size<=8388608,"bounded output")
  steps.append(dict(name=label,command=cmd,returncode=result.returncode,log=str(log),sha256=sha(log)));return result
 try:
  lines=["/* Generated from ORIGINAL pinned WAST compiled by pinned WABT. */","typedef struct {unsigned kind;const char *suite;unsigned line;const unsigned char *bytes;unsigned length;const char *name; m98_wasm_value args[8];unsigned count,results;m98_wasm_value expected[8];unsigned nan[8];const char *trap;} spec_command;"]
  for suite in ("i32","i64","f32","f64"):
   out=build/suite;out.mkdir();original=SOURCE/"raw/test/core"/(suite+".wast")
   result=run(suite+"-assembler",[str(WABT),"--enable-all",str(original),"-o",str(out/(suite+".json"))]);require(result.returncode==0,"actual official WAST compilation")
   data=json.loads((out/(suite+".json")).read_text());require(len(data["commands"])<=3000,"bounded selected command count")
   for ordinal,command in enumerate(data["commands"]):
    kind=command["type"];bytes_ref="NULL";length=0;name="";params=[];expected=[];nan=[];trap="";result_count=0;tag=f"{suite}_{ordinal}"
    if kind in ("module","assert_invalid"):
     filename=command["filename"];require(Path(filename).name==filename and filename.endswith(".wasm"),"actual compiled binary fixture")
     b=(out/filename).read_bytes();require(8<=len(b)<=1048576,"module bytes bound");lines.append("static const unsigned char fixture_"+tag+"[]={"+",".join(str(v) for v in b)+"};");bytes_ref="fixture_"+tag;length=len(b);k=0 if kind=="module" else 3
    elif kind in ("assert_return","assert_trap"):
     action=command["action"];require(action["type"]=="invoke" and "module" not in action,"single current instance invoke profile")
     name=action["field"];require(len(name)<128,"export name bound");params=[value(row)[0] for row in action["args"]];require(len(params)<=8,"arg count")
     if kind=="assert_return":
      pair=[value(row) for row in command["expected"]];expected=[x[0] for x in pair];nan=[str(x[1]) for x in pair];require(len(expected)<=8,"result count");result_count=len(expected);k=1
     else:
      trap=command["text"];typed=command.get("expected",[]);require(len(typed)<=8 and all(t["type"] in ("i32","i64","f32","f64") for t in typed),"original trap result types");result_count=len(typed);k=2
    else:
     require(kind=="assert_malformed" and command["module_type"]=="text","unsupported script protocol must be explicit")
     exclusions.append(dict(suite=suite,line=command["line"],type=kind,reason="text syntax/lexer oracle produces no Wasm binary; outside runtime validator"));continue
    row="{"+f"{k},{json.dumps(suite)},{command['line']},{bytes_ref},{length},{json.dumps(name)},"+"{"+(",".join(params) or "{0,0}")+"},"+str(len(params))+","+str(result_count)+",{"+(",".join(expected) or "{0,0}")+"},{"+(",".join(nan) or "0")+"},"+json.dumps(trap)+"}"
    commands.append(row)
   generated.extend([p for p in out.iterdir() if p.is_file()])
  lines.append("static const spec_command spec_commands[]={"+",\n".join(commands)+"};");header=build/"wasm_spec_vectors.h";header.write_text("\n".join(lines)+"\n")
  model={};receipt["models"]=model
  for label in ("host","sanitizer"):
   runtime_objs=[]
   for step in rdata["steps"]:
    if step["name"]==label+"-build":runtime_objs=[Path(n) for n in step["command"] if n.endswith(".o")]
   require(runtime_objs and runtime_objs[-1].name.startswith(label),"host linked object list")
   matches=[o for o in rdata["object_cache"] if o["object_sha256"]==sha(runtime_objs[0])];require(len(matches)==1,"one actual engine compiler provenance")
   meta=ROOT/"build/wasm-runtime-object-cache"/(matches[0]["key"]+".json");require(sha(meta)==matches[0]["provenance_sha256"],"immutable compiler/object cache provenance")
   provenance=json.loads(meta.read_text());require(provenance["object_sha256"]==sha(runtime_objs[0]),"object/cache hash")
   flags=[f.replace("PREPARED",str(runtime/"prepared")).replace("BUILD",str(runtime)).replace("ROOT",str(ROOT)) for f in provenance["context"]["flags"]]
   flags=[f for f in flags if f!="-I"+str(runtime)]+["-I"+str(build)]
   # Drop the original test main only; all real engine/port objects remain.
   runtime_objs=runtime_objs[:-1]
   for obj in runtime_objs:
    expected=[o for o in rdata["object_cache"] if o["object_sha256"]==sha(obj)];require(expected,"runtime object hash provenance")
   obj=build/(label+"-selected.o");binary=build/(label+"-selected");result=run(label+"-compile",[provenance["context"]["compiler"]]+flags+["-c",str(ROOT/OWN[0]),"-o",str(obj)]);require(result.returncode==0,"selected x87 host adapter compile")
   extra=["-fsanitize=address,undefined"] if label=="sanitizer" else []
   result=run(label+"-link",["clang" if label=="sanitizer" else "gcc"]+extra+[str(p) for p in runtime_objs]+[str(obj),"-Wl,--gc-sections","-pthread","-lm","-o",str(binary)]);require(result.returncode==0,"selected actual x87 engine link")
   result=run(label+"-tests",[str(binary)],dict(os.environ,ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",UBSAN_OPTIONS="halt_on_error=1"))
   summary=re.search(r"^SPEC_RESULT (\d+) (\d+) (\d+)$",result.stdout,re.M);require(summary,"complete actual selected test result")
   model[label]=dict(total=int(summary[1]),passed=int(summary[2]),failed=int(summary[3]),returncode=result.returncode);require(model[label]["total"]==len(commands) and model[label]["total"]==model[label]["passed"]+model[label]["failed"],"actual command count")
   require(result.returncode==(1 if model[label]["failed"] else 0),"failures must set failure exit code")
  require(model["host"]==model["sanitizer"],"normal/sanitized oracle outcome mismatch")
  generated+=[header]+[build/(label+"-selected") for label in ("host","sanitizer")]
  receipt.update(models=model,passed=model["host"]["failed"]==0,generated_files={str(p.relative_to(build)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in generated},selected_suites=["i32","i64","f32","f64"],selected_commands=len(commands))
 except Exception as error:
  receipt["error"]=str(error);raise
 finally:
  require(sha(SOURCE/"source-pin.json")==SOURCE_PIN and sha(TOOLS/"tool-pin.json")==TOOL_PIN,"official manifests drift")
  for base,files in ((SOURCE/"raw",originals["files"]),(TOOLS,tools["files"])):
   for n,row in files.items():require((base/n).stat().st_size==row["bytes"] and sha(base/n)==row["sha256"],"official original dependency drift")
  require(archive.stat().st_size==tools["archive_bytes"] and sha(archive)==tools["archive_sha256"],"original compiler archive drift")
  for n,digest in rdata["source_sha256"].items():require(sha(ROOT/n)==digest and sha(runtime/"source"/n)==digest,"runtime source drift during selected run")
  receipt["retained_files"]={str(p.relative_to(build)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(build.rglob("*")) if p.is_file() and not p.is_symlink()}
  require(pins=={n:sha(ROOT/n) for n in OWN},"selected adapter source drift")
  for n in OWN:
   out=build/"source"/n;out.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/n,out)
  (build/"result.json").write_text(json.dumps(receipt,indent=2)+"\n")
 print(json.dumps(dict(result=str(build/"result.json"),sha256=sha(build/"result.json"),models=model),indent=2));return 0 if receipt["passed"] else 1
if __name__=="__main__":sys.exit(main())
