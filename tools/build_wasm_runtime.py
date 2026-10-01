#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build real, bounded standalone WAMR; host/sanitizer/PE evidence, never a VM."""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess,tarfile,urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pefile
ROOT=Path(__file__).resolve().parents[1]
REV="f5f57c09aee623436f5fb87a90798fdd2cdf39fd"
ARCHIVE_SHA="620d40c4c67269f371a46ef4923d398ef96cdf569a7f66e6aab70788e235f907"
ARCHIVE_BYTES=6136546
OWN=["src/m98_wasm.h","src/m98_wasm.c","src/m98_wasm_math.h","src/m98_wasm_math.c",
 "src/m98_wasm_platform_internal.h","src/m98_wasm_platform.c","tests/m98_wasm_host.c",
 "tests/m98_wasm_native_gate.c","tools/build_wasm_runtime.py","docs/TRIDENT_WASM_RUNTIME.md",
 "benchmarks/win98se-ko-oem-native-exports-v1.json","LICENSE","tools/i486_instruction_gate.py","tests/test_i486_instruction_gate.py"]
COMMON_PINS={"tools/i486_instruction_gate.py":"6ba89c7a521e6a7b17e18519f27ed3d1f860d3f8e7ed7d9c89302ea960088973","tests/test_i486_instruction_gate.py":"6a0ff7367a2c32d09bebda68283b4be710cf27ddae67b21a571424655edabe51"}
CONFIG={"WASM_ENABLE_INTERP":1,"WASM_ENABLE_FAST_INTERP":0,"WASM_ENABLE_LABELS_AS_VALUES":0,
 "WASM_ENABLE_AOT":0,"WASM_ENABLE_JIT":0,"WASM_ENABLE_FAST_JIT":0,"WASM_ENABLE_LIBC_BUILTIN":0,
 "WASM_ENABLE_LIBC_WASI":0,"WASM_ENABLE_UVWASI":0,"WASM_ENABLE_LIB_PTHREAD":0,"WASM_ENABLE_THREAD_MGR":0,
 "WASM_ENABLE_SHARED_MEMORY":0,"WASM_ENABLE_SHARED_HEAP":0,"WASM_ENABLE_MULTI_MODULE":0,
 "WASM_ENABLE_SIMD":0,"WASM_ENABLE_GC":1,"WASM_ENABLE_REF_TYPES":1,"WASM_ENABLE_TAIL_CALL":1,
 "WASM_ENABLE_BULK_MEMORY":1,"WASM_ENABLE_BULK_MEMORY_OPT":1,"WASM_ENABLE_EXTENDED_CONST_EXPR":1,"WASM_ENABLE_MULTI_MEMORY":1,
 "WASM_ENABLE_MEMORY64":0,"WASM_ENABLE_EXCE_HANDLING":0,"WASM_ENABLE_TAGS":0,"WASM_ENABLE_STRINGREF":0,
 "WASM_ENABLE_INSTRUCTION_METERING":1,"WASM_MEM_ALLOC_WITH_USAGE":1,"WASM_MEM_ALLOC_WITH_USER_DATA":1,
 "WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS":0,"WASM_DISABLE_HW_BOUND_CHECK":1,"WASM_DISABLE_STACK_HW_BOUND_CHECK":1,"WASM_DISABLE_WRITE_GS_BASE":1,
 "WASM_DISABLE_WAKEUP_BLOCKING_OP":1,"WASM_UINT64_IS_ATOMIC":0,"WASM_UINT32_IS_ATOMIC":0,
 "WASM_UINT16_IS_ATOMIC":0,"WASM_TABLE_MAX_SIZE":1024,"BH_HAS_DLFCN":0}
EXPORTS=sorted("m98_wasm_open m98_wasm_close m98_wasm_load m98_wasm_unload m98_wasm_instantiate m98_wasm_instance_close m98_wasm_call m98_wasm_memory_size m98_wasm_memory_grow m98_wasm_memory_read m98_wasm_memory_write m98_wasm_inspect".split())
def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def safe_source(source):
 require(source.resolve().is_relative_to(ROOT/"build") and not source.is_symlink(),"owned ignored source directory")
 archive=source/"wamr.tar.gz"
 require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size==ARCHIVE_BYTES and sha(archive)==ARCHIVE_SHA,"original immutable archive")
 members={};skipped=[];total=0;prefix="wasm-micro-runtime-"+REV+"/"
 with tarfile.open(archive,"r:gz") as tar:
  for member in tar:
   if member.isdir():continue
   require(member.name.startswith(prefix),"archive prefix")
   name=member.name[len(prefix):];p=Path(name)
   require(name and not p.is_absolute() and ".." not in p.parts and name not in members,"safe unique member")
   if not member.isfile():
    require(name=="language-bindings/python/LICENSE" and member.issym() and member.linkname=="../../LICENSE","unexpected nonregular member")
    skipped.append(name);continue
   require(member.size<=8388608,"bounded archive member");total+=member.size;require(total<=134217728,"bounded source archive")
   data=tar.extractfile(member).read();actual=source/"source"/name
   require(actual.is_file() and not actual.is_symlink() and actual.stat().st_size==len(data) and sha(actual)==hashlib.sha256(data).hexdigest(),"original archive/source mismatch: "+name)
   members[name]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
 require(len(members)==2001 and skipped==["language-bindings/python/LICENSE"],"complete regular source snapshot")
 return members
def fetch_source(source):
 # Explicit opt-in download, confined to a fresh ignored build child. Original
 # archives and every regular file/license survive both success and failure.
 require(source.parent==ROOT/"build" and not source.exists(),"fresh owned source download directory")
 source.mkdir();receipt=dict(passed=False,revision=REV,archive_sha256=ARCHIVE_SHA,archive_bytes=ARCHIVE_BYTES,foreign_script_execution=False)
 try:
  url="https://codeload.github.com/wasm-micro-runtime/wasm-micro-runtime/tar.gz/"+REV;receipt["url"]=url
  with urllib.request.urlopen(url,timeout=30) as response:data=response.read(ARCHIVE_BYTES+1)
  archive=source/"wamr.tar.gz";archive.write_bytes(data)
  require(len(data)==ARCHIVE_BYTES and sha(archive)==ARCHIVE_SHA,"downloaded original archive pin")
  prefix="wasm-micro-runtime-"+REV+"/";total=0;seen=set();dest=source/"source";dest.mkdir()
  with tarfile.open(archive,"r:gz") as tar:
   for member in tar:
    if member.isdir():continue
    require(member.name.startswith(prefix),"download archive prefix");name=member.name[len(prefix):];rel=Path(name)
    require(name and not rel.is_absolute() and ".." not in rel.parts and name not in seen,"safe unique download member");seen.add(name)
    if not member.isfile():
     require(name=="language-bindings/python/LICENSE" and member.issym() and member.linkname=="../../LICENSE","unexpected download nonregular member");continue
    require(member.size<=8388608,"bounded downloaded member");total+=member.size;require(total<=134217728,"bounded original extraction")
    out=dest/rel;out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("xb") as f:f.write(tar.extractfile(member).read())
  members=safe_source(source);receipt.update(passed=True,regular_files=len(members),regular_bytes=sum(row["bytes"] for row in members.values()),skipped_license_symlink="language-bindings/python/LICENSE -> ../../LICENSE; original root LICENSE retained")
 except Exception as error:receipt["error"]=str(error);raise
 finally:(source/"source-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
def prepare(source,build,members):
 dest=build/"prepared";dest.mkdir()
 selected=[name for name in members if name.startswith("core/") and (name.endswith(".h") or name.endswith(".c") or name.endswith(".inc"))]
 for name in selected:
  out=dest/name;out.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/"source"/name,out)
 runtime=dest/"core/iwasm/interpreter/wasm_runtime.c";s=runtime.read_text()
 anchor="    /* Execute start function for both main instance and sub instance */"
 require(s.count(anchor)==1,"start metering patch anchor")
 s=s.replace(anchor,"    /* Win98 port: actual dispatch meter also protects the start function. */\n    wasm_runtime_set_instruction_count_limit(exec_env, m98_wasm_start_budget());\n"+anchor)
 for text in ['post_inst_func =\n            lookup_post_instantiate_func(module_inst, "__post_instantiate");',
              'call_ctors_func =\n            lookup_post_instantiate_func(module_inst, "__wasm_call_ctors");']:
  require(s.count(text)==1,"nonbrowser ctor patch anchor");s=s.replace(text,text.split(" =")[0]+" = NULL; /* Browser profile: only the Wasm start section executes. */")
 runtime.write_text(s)
 interp=dest/"core/iwasm/interpreter/wasm_interp_classic.c";s=interp.read_text()
 require(s.count("CHECK_INSTRUCTION_LIMIT();")==4,"dispatch end metering anchors")
 s=s.replace("CHECK_INSTRUCTION_LIMIT();","(void)0; /* Meter occurs before every actual switch dispatch. */")
 anchor="    while (frame_ip < frame_ip_end) {\n        opcode = *frame_ip++;"
 require(s.count(anchor)==1,"actual classic dispatch anchor")
 s=s.replace(anchor,"    while (frame_ip < frame_ip_end) {\n        CHECK_INSTRUCTION_LIMIT();\n        opcode = *frame_ip++;");interp.write_text(s)
 for filename,typename in (("core/iwasm/interpreter/wasm_interp.h","WASMInterpFrame"),("core/iwasm/interpreter/wasm.h","WASMBranchBlock")):
  file=dest/filename;s=file.read_text();start="typedef struct "+typename+" {";end="} "+typename+";"
  require(s.count(start)==1 and s.count(end)==1,"explicit four-byte interpreter layout anchor")
  s=s.replace(start,"/* Win98 port: bytecode cells and interpreter frames have four-byte alignment. */\n#pragma pack(push,4)\n"+start).replace(end,end+"\n#pragma pack(pop)");file.write_text(s)
 memory=dest/"core/iwasm/common/wasm_memory.c";s=memory.read_text()
 anchor="    if (!(memory_data_new =\n              realloc_func(Alloc_For_LinearMemory, full_size_mmaped,"
 require(s.count(anchor)==1,"usage-aware realloc patch anchor")
 s=s.replace(anchor,"    /* Preserve a valid offset before realloc may free the original block. */\n    uintptr_t m98_heap_offset = heap_size > 0\n        ? (uintptr_t)heap_data_old - (uintptr_t)memory_data_old : 0;\n"+anchor)
 anchor="(char *)heap_data_old\n                                      + (memory_data_new - memory_data_old)"
 require(s.count(anchor)==1,"heap migration pointer patch anchor");s=s.replace(anchor,"(char *)memory_data_new + m98_heap_offset")
 anchor="    memory->heap_data = memory_data_new + (heap_data_old - memory_data_old);\n    memory->heap_data_end = memory->heap_data + heap_size;"
 require(s.count(anchor)==1,"absent heap rebase patch anchor")
 s=s.replace(anchor,"    if (heap_size > 0) {\n        memory->heap_data = memory_data_new + m98_heap_offset;\n        memory->heap_data_end = memory->heap_data + heap_size;\n    } else {\n        memory->heap_data = memory->heap_data_end = NULL;\n    }");memory.write_text(s)
 # Make the upstream platform include select the original, owner-guarded Win98
 # port. Preserve every upstream header/license; no NT/SRWLOCK/UCRT platform.
 internal=dest/"core/shared/platform/include/platform_internal.h";internal.write_bytes((ROOT/"src/m98_wasm_platform_internal.h").read_bytes())
 for name in selected:
  if name.endswith(".c"):
   p=dest/name;s=p.read_text()
   # Explicit, recorded prelude after original copyright/SPDX, not a guessed
   # link-library override. Original source bytes remain separately preserved.
   s='#include "m98_wasm_platform_internal.h"\n#define M98_WASM_MATH_MAP\n#include "m98_wasm_math.h"\n'+s;p.write_text(s)
 patches={name:dict(original_sha256=members[name]["sha256"],prepared_sha256=sha(dest/name)) for name in selected if sha(dest/name)!=members[name]["sha256"]}
 return dest,patches,{str(p.relative_to(dest)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in dest.rglob("*") if p.is_file()}
def u(n):
 result=[]
 while True:
  byte=n&127;n>>=7;result.append(byte|(128 if n else 0))
  if not n:return bytes(result)
def section(kind,data):return bytes([kind])+u(len(data))+data
def vector(rows):return u(len(rows))+b"".join(rows)
def string(s):b=s.encode();return u(len(b))+b
def module(functions,memories=(),imports=(),start=None,data=None):
 types=[b"\x60"+vector([bytes([v]) for v in params])+vector([bytes([v]) for v in results]) for _,params,results,_ in list(imports)+list(functions)]
 result=b"\0asm\x01\0\0\0"+section(1,vector(types))
 if imports:result+=section(2,vector([string(im[0][0])+string(im[0][1])+b"\x00"+u(i) for i,im in enumerate(imports)]))
 result+=section(3,vector([u(i+len(imports)) for i in range(len(functions))]))
 if memories:result+=section(5,vector([b"\x01"+u(a)+u(b) for a,b in memories]))
 result+=section(7,vector([string(f[0])+b"\x00"+u(i+len(imports)) for i,f in enumerate(functions)]))
 if start is not None:result+=section(8,u(start))
 result+=section(10,vector([u(len(f[3])+2)+b"\x00"+f[3]+b"\x0b" for f in functions]))
 if data is not None:result+=section(11,vector([b"\x00\x41\x00\x0b"+u(len(data))+data]))
 return result
def fixtures(build):
 i=0x7f;l=0x7e;f=0x7d;d=0x7c
 rows={
 "arithmetic":module([("add",[i,i],[i],b"\x20\0\x20\1\x6a"),("div",[i,i],[i],b"\x20\0\x20\1\x6d"),("wide",[l,l],[l],b"\x20\0\x20\1\x7c"),("pair",[i],[i,i],b"\x20\0\x20\0")]),
 "memory":module([("size",[],[i],b"\x3f\0"),("grow",[i],[i],b"\x20\0\x40\0"),("load",[i],[i],b"\x20\0\x28\2\0"),("store",[i,i],[],b"\x20\0\x20\1\x36\2\0"),("copy",[i,i,i],[],b"\x20\0\x20\1\x20\2\xfc\x0a\0\0"),("fill",[i,i,i],[],b"\x20\0\x20\1\x20\2\xfc\x0b\0")],[(1,4)],data=b"Wasm98"),
 "imports":module([("invoke",[i,i],[i],b"\x20\0\x20\1\x10\0")],imports=[(("host","sum"),[i,i],[i],b"")]),
 "missing_import":module([("invoke",[],[i],b"\x10\0")],imports=[(("missing","absent"),[],[i],b"")]),
 "infinite":module([("loop",[],[],b"\x03\x40\x0c\0\x0b")]),
 "recursion":module([("recurse",[],[],b"\x10\0")]),
 "tail_infinite":module([("tail_loop",[],[],b"\x12\0")]),
 "start_infinite":module([("boot",[],[],b"\x03\x40\x0c\0\x0b")],start=0),
 "start_trap":module([("boot",[],[],b"\x00")],start=0),
 "tail":module([("first",[i],[i],b"\x20\0\x12\1"),("second",[i],[i],b"\x20\0\x41\1\x6a")]),
 "multimemory":module([("size",[],[i],b"\x3f\1")],[(1,2),(2,3)]),
 "float":module([("nearest",[d],[d],b"\x20\0\x9e"),("sqrt",[d],[d],b"\x20\0\x9f"),("fnearest",[f],[f],b"\x20\0\x90"),("fsqrt",[f],[f],b"\x20\0\x91"),("min",[d,d],[d],b"\x20\0\x20\1\xa4"),("max",[d,d],[d],b"\x20\0\x20\1\xa5")]),
 "bad_type":module([("bad",[],[i],b"")]),
 "unreachable":module([("trap",[],[],b"\x00")]),
 "too_much_memory":module([("size",[],[i],b"\x3f\0")],[(257,300)]),
 }
 rows["bad_magic"]=b"BAD!\x01\0\0\0";rows["truncated"]=rows["arithmetic"][:-1]
 (build/"original-fixtures").mkdir();lines=["/* Original binary fixtures; not compiled official spec modules. */"]
 for name,b in rows.items():
  (build/"original-fixtures"/(name+".wasm")).write_bytes(b)
  lines.append("static const unsigned char wasm_"+name+"[]={"+",".join(str(x) for x in b)+"};")
 (build/"wasm_original_fixtures.h").write_text("\n".join(lines)+"\n")
 return {k:dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest(),origin="original-owned-binary-encoder") for k,v in rows.items()}
# Closed set for actual 32-bit i486 disassembly. Prefixes are parsed rather
# than allowing the following instruction to disappear after an operandless nop.
I486=set("mov movb movw movl movsbl movswl movzbl movzwl movsb movsw movsl stos stosb stosw stosl push pushl pop popl pusha popa add addb addw addl adc adcb adcw adcl sub subb subw subl sbb sbbb sbbw sbbl cmp cmpb cmpw cmpl test testb testw testl and andb andw andl or orb orw orl xor xorb xorw xorl not notb notw notl neg negb negw negl inc incb incw incl dec decb decw decl mul mulb mulw mull imul imulb imulw imull div divb divw divl idiv idivb idivw idivl shl shlb shlw shll sal salb salw sall shr shrb shrw shrl sar sarb sarw sarl shld shldw shldl shrd shrdw shrdl rol rolb rolw roll ror rorb rorw rorl rcl rcr bt btl btw btc btr bts bsf bsr lea leal xchg xchgb xchgw xchgl xadd cmpxchg jmp call ret retl leave nop hlt clc stc cmc cld std cli sti sahf lahf pushf popf cbtw cwtl cltd int into iret bound enter loop loope loopne jecxz je jne ja jae jb jbe jg jge jl jle jo jno js jns jp jnp jz jnz seta setae setb setbe sete setne setg setge setl setle seto setno sets setns setp setnp fld fldl flds fldt fld1 fldz fldpi fldl2e fldl2t fldlg2 fldln2 fst fstl fsts fstp fstpl fstps fstpt fild filds fildl fildll fist fistl fists fistp fistps fistpl fistpll fadd faddp fadds faddl fsub fsubp fsubs fsubl fsubr fsubrp fmul fmulp fmuls fmull fdiv fdivp fdivs fdivl fdivr fdivrp fcom fcomp fcompp fcoms fcoml fcomps fcompl fucom fucomp fucompp ftst fxam fxch fchs fabs fsqrt frndint fscale fprem fprem1 fyl2x fyl2xp1 f2xm1 fptan fpatan fsin fcos fsincos fdecstp fincstp ffree fnop fldcw fnstcw fstcw fnstsw fstsw fnstenv fstenv fldenv fnsave fsave frstor fninit finit fnclex fclex fwait wait".split())
def instruction_gate(s):
 decoded=[]
 for line in s.splitlines():
  if not re.match(r"^[ \t]*[0-9a-f]+:",line):continue
  match=re.match(r"^[ \t]*[0-9a-f]+:[ \t]+([a-z][a-z0-9.]*)[ \t]*(.*)$",line)
  require(match is not None,"unparsed decoded machine line: "+line)
  mnemonic,operands=match.groups()
  while mnemonic in {"rep","repz","repe","repnz","repne","lock","data16","addr16"}:
   parts=operands.split(None,1);require(parts,"empty instruction prefix");mnemonic=parts[0];operands=parts[1] if len(parts)>1 else ""
  decoded.append((mnemonic,operands))
 require(len(decoded)>500,"full linked machine decode")
 bad=[m for m,o in decoded if m not in I486 or re.search(r"%(?:[xyz]mm\d+|mm[0-7])\b",o)]
 require(not bad,"unsupported/post-i486 instructions "+repr(sorted(set(bad))))
 return dict(instructions_decoded=len(decoded),post_i486_families="absent",parser="per-line-horizontal-whitespace-closed-i486-mnemonics")
def instruction_controls():
 baseline="\n".join(f"{i:x}:\tmov %eax,%eax" for i in range(600))
 instruction_gate(baseline);passed=[]
 for prefix,modern in (("nop","mfence"),("ret","vzeroupper"),("nop","tzcnt")):
  stream=baseline+"\n1000:\t"+prefix+"\n1001:\t"+modern+"\n"
  try:instruction_gate(stream)
  except RuntimeError as e:require(modern in str(e),"control must identify actual modern instruction");passed.append(prefix+"->"+modern)
  else:raise RuntimeError("decoder accepted forbidden control "+modern)
 return passed
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--build-dir",type=Path,required=True);parser.add_argument("--source-dir",type=Path,default=ROOT/"build/wasm-runtime-sources-v3");parser.add_argument("--fetch-source",action="store_true",help="download pinned original source into a fresh --source-dir");args=parser.parse_args()
 build=args.build_dir.resolve();source=args.source_dir.resolve();require(build.parent==ROOT/"build" and not build.exists(),"fresh direct child of owned build")
 pins={n:sha(ROOT/n) for n in OWN}
 require(all(pins[n]==digest for n,digest in COMMON_PINS.items()),"reviewed common gate source SRI")
 if args.fetch_source:fetch_source(source)
 members=safe_source(source);build.mkdir();steps=[]
 receipt=dict(schema=1,decoder_controls=[],kind="bounded-standalone-wamr-current-interpreter",passed=False,source_sha256=pins,
  upstream_revision=REV,upstream_archive_sha256=ARCHIVE_SHA,upstream_archive_bytes=ARCHIVE_BYTES,license="Apache-2.0 WITH LLVM-exception",config=CONFIG,steps=steps,
  native_execution=False,browser_wasm=False,browser_js_api=False,full_modern_wasm=False,mshtml_integration=False,full_browser=False,webgpu=False,webgl=False,modern_apps=False,vm_operations=False,foreign_script_execution=False)
 def run(label,command,env=None,success=True):
  p=build/(label+".log");r=subprocess.run(command,cwd=ROOT,env=env,text=True,capture_output=True,timeout=180);p.write_text(r.stdout+r.stderr)
  record=dict(name=label,command=command,returncode=r.returncode,log=str(p),sha256=sha(p));steps.append(record);r.m98_record=record;require(p.stat().st_size<=8388608,"bounded build output")
  if success:require(r.returncode==0,label+": "+(r.stdout+r.stderr)[-3500:])
  return r
 try:
  receipt["decoder_controls"]=instruction_controls()
  run("full-i486-control-tests",["python3",str(ROOT/"tests/test_i486_instruction_gate.py")])
  prepared,patches,prepared_pins=prepare(source,build,members);receipt.update(patches=patches,prepared_files=prepared_pins,original_fixtures=fixtures(build))
  parts=["core/iwasm/interpreter/wasm_loader.c","core/iwasm/interpreter/wasm_runtime.c","core/iwasm/interpreter/wasm_interp_classic.c"]
  parts+=[str(p.relative_to(prepared)) for p in sorted((prepared/"core/iwasm/common").glob("*.c")) if p.name not in {"wasm_application.c","wasm_shared_memory.c"}]
  parts += ["core/iwasm/common/arch/invokeNative_general.c"]
  parts+=[str(p.relative_to(prepared)) for p in sorted((prepared/"core/shared/utils").glob("*.c")) if p.name not in {"bh_queue.c","runtime_timer.c"}]
  parts+=["core/shared/mem-alloc/mem_alloc.c"]+[str(p.relative_to(prepared)) for p in sorted((prepared/"core/shared/mem-alloc/ems").glob("*.c"))]
  parts+=[str(p.relative_to(prepared)) for p in sorted((prepared/"core/iwasm/common/gc").glob("*.c"))]
  units=[prepared/p for p in parts]+[ROOT/p for p in ("src/m98_wasm.c","src/m98_wasm_platform.c","src/m98_wasm_math.c")]
  includes=["src","tests",str(build)]+[str(prepared/p) for p in ("core","core/iwasm/include","core/iwasm/common","core/iwasm/common/gc","core/iwasm/interpreter","core/shared/utils","core/shared/mem-alloc","core/shared/platform/include")]
  flags=["-std=gnu99","-O1","-g","-Wall","-Wextra","-Wno-unused-parameter","-Wno-unused-function","-ffunction-sections","-fdata-sections","-fno-strict-aliasing","-mfpmath=387","-mpc64","-ffloat-store"]+["-I"+p for p in includes]+[f"-D{k}={v}" for k,v in CONFIG.items()]+["-DBH_MALLOC=wasm_runtime_malloc","-DBH_FREE=wasm_runtime_free"]
  cache=ROOT/"build/wasm-runtime-object-cache";cache.mkdir(exist_ok=True);cache_references=[]
  headers={n:p["sha256"] for n,p in prepared_pins.items() if n.endswith((".h",".inc"))}
  headers.update({n:pins[n] for n in OWN if n.endswith(".h")})
  def compile_units(label,compiler,selected,selected_flags):
   compiler_version=run(label+"-compiler-version",[compiler,"--version"]).stdout.splitlines()[0]
   def compile_one(item):
    index,p=item
    obj=build/(label+"-%02d.o"%index)
    normalized=[v.replace(str(prepared),"PREPARED").replace(str(build),"BUILD").replace(str(ROOT),"ROOT") for v in selected_flags]
    local_headers=dict(headers)
    if p==ROOT/"tests/m98_wasm_host.c":local_headers["wasm_original_fixtures.h"]=sha(build/"wasm_original_fixtures.h")
    context=dict(compiler=compiler,compiler_version=compiler_version,flags=normalized,source_sha256=sha(p),headers=local_headers)
    key=hashlib.sha256(json.dumps(context,sort_keys=True).encode()).hexdigest();cached=cache/(key+".o");meta=cache/(key+".json")
    if cached.exists() and meta.exists():
     provenance=json.loads(meta.read_text());require(provenance["context"]==context and provenance["object_sha256"]==sha(cached),"cached object provenance");shutil.copyfile(cached,obj)
     cache_references.append(dict(key=key,object_sha256=sha(obj),source=str(p),provenance_sha256=sha(meta),reused=True))
    else:
     result=run(label+"-compile-%02d"%index,[compiler]+selected_flags+["-c",str(p),"-o",str(obj)])
     shutil.copyfile(obj,cached);provenance=dict(context=context,object_sha256=sha(obj),original_command=result.m98_record["command"],compile_log_sha256=result.m98_record["sha256"]);meta.write_text(json.dumps(provenance,indent=2)+"\n")
     cache_references.append(dict(key=key,object_sha256=sha(obj),source=str(p),provenance_sha256=sha(meta),reused=False))
    return obj
   with ThreadPoolExecutor(max_workers=2) as pool:return list(pool.map(compile_one,enumerate(selected)))
  receipt["effective_engine_config"]={}
  def record_config(label,compiler,selected_flags):
   output=run(label+"-effective-engine-config",[compiler]+selected_flags+["-dM","-E",str(prepared/"core/iwasm/interpreter/wasm_interp_classic.c")]).stdout
   actual={m[1]:m[2] for m in re.finditer(r"^#define (WASM_[A-Z0-9_]+)[ \t]+([^\r\n]+)$",output,re.M)}
   require(all(actual.get(k)==str(v) for k,v in CONFIG.items() if k.startswith("WASM_")),"compiler effective engine feature configuration")
   receipt["effective_engine_config"][label]=dict(sorted(actual.items()))
  model={}
  for label,sanitize in (("host",False),("sanitizer",True)):
   extra=["-fsanitize=address,undefined","-fno-omit-frame-pointer"] if sanitize else []
   record_config(label,"gcc",flags+extra+["-DM98_WASM_TESTING=1"])
   binary=build/("wasm-"+label)
   objects=compile_units(label,"gcc",units+[ROOT/"tests/m98_wasm_host.c"],flags+extra+["-DM98_WASM_TESTING=1"])
   run(label+"-build",["clang" if sanitize else "gcc"]+extra+[str(p) for p in objects]+["-Wl,--gc-sections","-pthread","-lm","-o",str(binary)])
   result=run(label+"-tests",[str(binary)],dict(os.environ,ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",UBSAN_OPTIONS="halt_on_error=1"));model[label]=result.stdout.strip()
  require(model["host"]==model["sanitizer"],"host/sanitizer mismatch");receipt["models"]=model
  controls=[]
  for label,program,needle in (("asan","#include <stdlib.h>\nint main(void){volatile char *p=malloc(1);p[2]=1;free((void*)p);return 0;}\n","heap-buffer-overflow"),("ubsan","#include <stdint.h>\nint main(void){volatile int32_t x=2147483647;return x+1;}\n","signed integer overflow")):
   file=build/(label+"-control.c");file.write_text(program);obj=build/(label+"-control.o");binary=build/(label+"-control")
   sanitizer_flag="-fsanitize="+("address" if label=="asan" else "undefined")
   run(label+"-control-compile",["gcc","-O1","-g","-mfpmath=387","-mpc64","-ffloat-store",sanitizer_flag,"-fno-omit-frame-pointer","-c",str(file),"-o",str(obj)])
   run(label+"-control-link",["clang",sanitizer_flag,str(obj),"-o",str(binary)])
   result=run(label+"-control-test",[str(binary)],dict(os.environ,ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",UBSAN_OPTIONS="halt_on_error=1"),success=False)
   require(result.returncode!=0 and needle in result.stderr,"instrumented deliberate control must fail")
   controls.append(dict(name=label,source_sha256=sha(file),object_sha256=sha(obj),binary_sha256=sha(binary),actual_returncode=result.returncode,expected_diagnostic=needle))
  receipt["sanitizer_controls"]=controls
  nativeflags=flags+["-Os","-D__USE_MINGW_ANSI_STDIO=0","-march=i486","-mfpmath=387","-mpc64","-mno-sse","-mno-sse2","-mno-mmx","-ffloat-store","-fno-builtin","-fno-stack-protector","-fno-delete-null-pointer-checks","-mno-stack-arg-probe","-DBUILD_TARGET_X86_32"]
  macros=run("native-original-crt-macros",["i686-w64-mingw32-gcc","-std=gnu99","-D__USE_MINGW_ANSI_STDIO=0","-dM","-E","-x","c",str(ROOT/"src/m98_wasm_platform_internal.h")]).stdout
  required_macros={"__USE_MINGW_ANSI_STDIO":"0","PRId64":'"I64d"',"PRIi64":'"I64i"',"PRIu64":'"I64u"',"PRIx64":'"I64x"',"PRIX64":'"I64X"'}
  actual_macros={n:re.search(r"^#define "+n+r"[ \t]+([^\r\n]+)$",macros,re.M).group(1) for n in required_macros}
  require(actual_macros==required_macros,"actual compiler original-CRT numeric formatting macros")
  receipt["native_crt_profile"]=dict(compiler_derived_macros=actual_macros,dynamic_symbols={"MSVCRT.DLL":["_vsnprintf"]},system_path_check_implemented=True,native_dynamic_resolution_tested=False)
  record_config("native","i686-w64-mingw32-gcc",nativeflags)
  objects=compile_units("native","i686-w64-mingw32-gcc",units+[ROOT/"tests/m98_wasm_native_gate.c"],nativeflags)
  exports=build/"M98WASM.def";exports.write_text("LIBRARY M98WASM\nEXPORTS\n"+"\n".join(" "+n for n in EXPORTS)+"\n")
  dll=build/"M98WASM.DLL";run("native-link",["i686-w64-mingw32-gcc"]+nativeflags+["-shared","-nostdlib","-Wl,--exclude-all-symbols","-Wl,--strip-debug","-Wl,--gc-sections","-Wl,--entry,_m98_wasm_dll_entry@12","-Wl,--subsystem,windows:4.10","-Wl,--major-os-version,4","-Wl,--minor-os-version,10","-Wl,--disable-dynamicbase","-Wl,--disable-nxcompat","-Wl,--disable-tsaware","-Wl,--no-insert-timestamp","-Xlinker","--stack","-Xlinker","2097152,524288"]+[str(p) for p in objects]+[str(exports),"-lmsvcrt","-lkernel32","-lgcc","-o",str(dll)])
  installed=json.loads((ROOT/"benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())
  with pefile.PE(str(dll)) as pe:
   h=pe.OPTIONAL_HEADER;require(pe.FILE_HEADER.Machine==0x14c and h.Magic==0x10b and pe.is_dll(),"PE32 x86 DLL")
   require((h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion)==(4,10) and h.Subsystem==2 and (h.MajorSubsystemVersion,h.MinorSubsystemVersion)==(4,10),"Win98 4.10 headers")
   require(pe.FILE_HEADER.TimeDateStamp==0 and h.SizeOfStackReserve==2097152 and h.SizeOfStackCommit==524288 and h.AddressOfEntryPoint,"timestamp/stack/entry")
   require(not h.DllCharacteristics&(0x40|0x100|0x8000) and h.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics&1,"flags/relocations")
   require(all(not h.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)),"no TLS/loadconfig/delay/CLR")
   imports_actual={}
   catalog=installed["dlls"]
   require("_vsnprintf" in catalog["MSVCRT.DLL"],"original installed dynamic CRT export")
   for entry in pe.DIRECTORY_ENTRY_IMPORT:
    name=entry.dll.decode().upper();require(name in catalog,"original installed DLL: "+name);available=catalog[name]
    names=[]
    for imp in entry.imports:
     require(imp.name is not None,"no ordinal import");n=imp.name.decode();require(n in available,"original Win98 export: "+name+"!"+n);names.append(n)
    imports_actual[name]=sorted(names)
   actual=sorted(e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name and not e.forwarder);require(actual==EXPORTS,"public exports")
   require(dll.stat().st_size<=1048576,"bounded native image")
  spec=importlib.util.spec_from_file_location("m98_wasm_frozen_i486_gate",ROOT/"tools/i486_instruction_gate.py")
  gate_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate_module)
  machine,raw=gate_module.scan(dll);require(machine["artifact_sha256"]==sha(dll),"exact full-decode artifact")
  log=build/"native-disassembly-complete.log";log.write_bytes(raw);require(sha(log)==machine["disassembly_sha256"],"complete raw decode hash")
  steps.append(dict(name="native-disassembly-complete",command=machine["command"],returncode=0,log=str(log),sha256=sha(log)))
  machine["scanner_source_sha256"]=COMMON_PINS["tools/i486_instruction_gate.py"]
  receipt.update(passed=True,artifacts={dll.name:dict(bytes=dll.stat().st_size,sha256=sha(dll),pe98_gate="pass",imports=imports_actual,exports=EXPORTS,i486_instructions=machine)},linked_units=parts,object_cache=cache_references)
 except Exception as error:receipt["error"]=str(error);raise
 finally:
  receipt["object_cache"]=locals().get("cache_references",[])
  receipt["retained_binaries"]={p.name:dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(build.iterdir()) if p.is_file() and (p.name.endswith(".DLL") or p.name in {"wasm-host","wasm-sanitizer","asan-control","ubsan-control"})}
  require(pins=={n:sha(ROOT/n) for n in OWN},"owned source drift")
  for name in OWN:
   out=build/"source"/name;out.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,out)
  receipt["original_source_files"]=members
  (build/"result.json").write_text(json.dumps(receipt,indent=2)+"\n")
 print(json.dumps(dict(result=str(build/"result.json"),sha256=sha(build/"result.json"),models=model,native_execution=False),indent=2))
if __name__=="__main__":main()
