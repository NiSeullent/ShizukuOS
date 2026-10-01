#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded, pinned local interpreter build. No VM, network or installation."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import pefile

ROOT = Path(__file__).resolve().parents[1]
QVER = "2026-06-04"
MREV = "c4e1bb3994c14ed5112c894d15a451bf00f0d501"
ARCHIVES = {
    "quickjs-2026-06-04.tar.xz": "b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a",
    f"musl-{MREV}.tar.gz": "b124fa46818a524d373a176b3262a9c26f421d5972073110f3fe51690a9ac4f1",
}
UNITS = "quickjs.c cutils.c libregexp.c libunicode.c dtoa.c".split()
MATH = "acosh asinh atanh expm1 log1p log2 cbrt trunc fmin fmax hypot pow round log2_data pow_data exp_data __math_divzero __math_invalid __math_oflow __math_uflow __math_xflow".split()
EXPORTS = sorted("m98_script_open m98_script_bind_root m98_script_eval m98_script_invoke m98_script_invoke_this m98_script_jobs m98_script_release_result m98_script_info m98_script_close".split())
DYNAMIC = "_vsnprintf gmtime localtime mktime sin cos tan acos asin atan exp log log10 sqrt floor ceil fabs sinh cosh tanh atan2 fmod frexp ldexp".split()
SOURCES = "src/m98_trident_script.h src/m98_trident_script.c src/m98_trident_script_win32.c src/m98_trident_script.def src/m98_trident_script_port.h src/m98_trident_script_port.c src/m98_trident_script_fp.c src/m98_trident_script_HANDOFF.md tests/m98_trident_script_host.c tests/m98_trident_script_guest.c tests/m98_trident_script_platform_host.c tests/m98_trident_script_port_host.c tests/m98_trident_script_win32_mock.c tests/m98_trident_script_win32_mock.h tests/m98_trident_script_sanitizer_fault.c tests/trident_es2026_selected.js tests/trident_numeric_selected.js tools/build_trident_script.py benchmarks/win98se-ko-oem-native-exports-v1.json".split()

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def digest(path):
    require(path.is_file() and not path.is_symlink(), f"regular file required: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()

def pins(names):
    return {str(p): digest(p) for p in names}

def extract(archive, target, prefix, wanted):
    found = {}
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        require(len(members) < 10000, "archive member bound")
        total = 0
        for m in members:
            p = Path(m.name)
            require(not p.is_absolute() and ".." not in p.parts, "unsafe archive path")
            if not m.name.startswith(prefix + "/"):
                continue
            name = m.name[len(prefix)+1:]
            if not wanted(name):
                continue
            require(m.isfile() and not m.issym() and not m.islnk() and m.size <= 3000000, "regular bounded source member")
            require(name not in found, "duplicate archive source")
            total += m.size
            require(total < 8000000, "extracted source bound")
            stream = tar.extractfile(m)
            require(stream is not None, "archive read")
            data = stream.read(m.size+1)
            require(len(data) == m.size, "archive member size")
            destination = target/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            found[name] = hashlib.sha256(data).hexdigest()
    return found

def prepare(out):
    q = out/"prepared"/"quickjs"
    m = out/"prepared"/"math"
    dependencies = {}
    for name, sha in ARCHIVES.items():
        path = ROOT/"build/trident-script-sources"/name
        require(digest(path) == sha, "primary archive pin mismatch")
        dependencies[name] = {"path": str(path), "sha256": sha, "size": path.stat().st_size}
    qpins = extract(ROOT/"build/trident-script-sources/quickjs-2026-06-04.tar.xz", q, "quickjs-2026-06-04",
                    lambda n: n in UNITS or ("/" not in n and n.endswith(".h")) or n == "LICENSE")
    math_names = {"src/math/"+n+".c" for n in MATH}
    math_names |= {"src/math/"+n for n in ("log2_data.h", "pow_data.h", "exp_data.h")}
    math_names |= {"COPYRIGHT", "VERSION", "src/internal/libm.h", "arch/generic/fp_arch.h"}
    mpins = extract(ROOT/f"build/trident-script-sources/musl-{MREV}.tar.gz", m, f"musl-{MREV}", lambda n: n in math_names)
    require(set(mpins) == math_names, "complete portable math dependency set")
    # Original source copies and per-file notices remain next to prepared files.
    for directory in (q, m):
        shutil.copytree(directory, out/"original"/directory.name)
    text = (q/"quickjs.c").read_text()
    require(text.count("#define CONFIG_ATOMICS\n") == 1, "Atomics patch anchor")
    text = text.replace("#define CONFIG_ATOMICS\n", "/* Native profile: Atomics and shared memory disabled. */\n")
    declaration = "\n#ifdef _WIN32\nextern int64_t m98_qjs_clock_us(void);\nextern struct tm *m98_qjs_gmtime(const time_t *);\nextern struct tm *m98_qjs_localtime(const time_t *);\nextern time_t m98_qjs_mktime(struct tm *);\n#endif\n#define M98_SCRIPT_MATH_MAP\n#define M98_SCRIPT_FORMAT_MAP\n#include \"m98_trident_script_port.h\"\n"
    text = text.replace('#include "dtoa.h"\n', '#include "dtoa.h"\n'+declaration, 1)
    old = "    struct timeval tv;\n    gettimeofday(&tv, NULL);\n    ctx->random_state = ((int64_t)tv.tv_sec * 1000000) + tv.tv_usec;"
    require(text.count(old) == 1, "random clock patch anchor")
    text = text.replace(old, "#ifdef _WIN32\n    ctx->random_state = m98_qjs_clock_us();\n#else\n"+old+"\n#endif")
    old = "    struct timeval tv;\n    gettimeofday(&tv, NULL);\n    return (int64_t)tv.tv_sec * 1000 + (tv.tv_usec / 1000);"
    require(text.count(old) == 1, "UTC clock patch anchor")
    text = text.replace(old, "#ifdef _WIN32\n    return m98_qjs_clock_us() / 1000;\n#else\n"+old+"\n#endif")
    for old, new in (("tm = gmtime(&ti);", "tm = m98_qjs_gmtime(&ti);"),
                     ("tm = localtime(&ti);", "tm = m98_qjs_localtime(&ti);"),
                     ("gm_ti = mktime(tm);", "gm_ti = m98_qjs_mktime(tm);"),
                     ("loc_ti = mktime(tm);", "loc_ti = m98_qjs_mktime(tm);")):
        require(text.count(old) == 1, "timezone patch anchor")
        text = text.replace(old, new)
    (q/"quickjs.c").write_text(text)
    for name, anchor in (("cutils.c", '#include "cutils.h"'), ("libregexp.c", '#include "libunicode.h"'), ("dtoa.c", '#include "dtoa.h"')):
        path = q/name
        text = path.read_text()
        require(text.count(anchor) == 1, "helper mapping anchor")
        text = text.replace(anchor, anchor+'\n#define M98_SCRIPT_MATH_MAP\n#define M98_SCRIPT_FORMAT_MAP\n#include "m98_trident_script_port.h"')
        path.write_text(text)
    # musl internal names share spelling with glibc's public alias declarations.
    # Namespace only the actual libm helper/table identifiers, after extracting
    # original sources; never alter host system headers or compiler builtins.
    libm=(m/"src/internal/libm.h").read_text()
    helpers=set(re.findall(r"hidden\s+(?:long double|double|float|int)\s+(\w+)\s*\(",libm))
    helpers.update(("__signgam","__exp_data","__pow_log_data","__log2_data"))
    for path in list(m.rglob("*.c"))+list(m.rglob("*.h")):
        text=path.read_text()
        for helper in sorted(helpers,key=len,reverse=True):
            text=re.sub(r"\b"+re.escape(helper)+r"\b","m98_musl_"+helper,text)
        if path.name in ("exp_data.h","pow_data.h","log2_data.h"):
            text=text.replace("#include <features.h>","/* hidden is supplied explicitly; no musl libc prelude is needed. */")
        path.write_text(text)
    for name in MATH:
        path = m/"src/math"/(name+".c")
        text = path.read_text()
        # Include every system declaration first; macros must never rename a
        # dllimport declaration to one of our actual portable definitions.
        text = '#include <math.h>\n#include <stdint.h>\n#include <float.h>\n#include "libm.h"\n#define M98_SCRIPT_MATH_MAP\n#include "m98_trident_script_port.h"\n'+text
        path.write_text(text)
    (m/"endian.h").write_text("#define __LITTLE_ENDIAN 1234\n#define __BIG_ENDIAN 4321\n#define __BYTE_ORDER __LITTLE_ENDIAN\n")
    # No architecture libm override, no prebuilt libc or i686 helper library.
    shutil.copyfile(m/"arch/generic/fp_arch.h", m/"fp_arch.h")
    return q, m, {"archives": dependencies, "quickjs_original_sha256": qpins, "musl_original_sha256": mpins,
                  "quickjs_version": QVER, "musl_revision": MREV,
                  "urls": ["https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz", f"https://git.musl-libc.org/cgit/musl/snapshot/musl-{MREV}.tar.gz"]}

def pe_gate(path, dll, oem):
    with pefile.PE(str(path)) as pe:
        h = pe.OPTIONAL_HEADER
        require(pe.FILE_HEADER.Machine == 0x14c and h.Magic == 0x10b and pe.is_dll() == dll, "PE32/type")
        require(pe.FILE_HEADER.TimeDateStamp == 0 and h.AddressOfEntryPoint, "timestamp/entry")
        require((h.MajorOperatingSystemVersion,h.MinorOperatingSystemVersion,h.Subsystem,h.MajorSubsystemVersion,h.MinorSubsystemVersion)==(4,10,2,4,10), "Win98 GUI version")
        require((h.SizeOfStackReserve,h.SizeOfStackCommit)==(2097152,524288), "explicit new stack profile")
        require(not h.DllCharacteristics & (0x40|0x100|0x8000), "modern flags")
        require(h.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics & 1, "relocations")
        require(all(not h.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)), "TLS/load-config/delay/CLR")
        imports = {}
        for module in pe.DIRECTORY_ENTRY_IMPORT:
            name = module.dll.decode("ascii").upper()
            require(name in {"KERNEL32.DLL","MSVCRT.DLL"}, "native import module")
            names = []
            for row in module.imports:
                require(row.name is not None, "ordinal import")
                names.append(row.name.decode("ascii"))
            require(set(names) <= set(oem[name]), f"non-OEM import {name}: {set(names)-set(oem[name])}")
            imports[name] = sorted(names)
        actual=[]
        if hasattr(pe,"DIRECTORY_ENTRY_EXPORT"):
            for row in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                require(row.name is not None and not row.forwarder, "export forwarder/ordinal")
                actual.append(row.name.decode("ascii"))
        require(sorted(actual)==(EXPORTS if dll else []), "exact exports")
        require(path.stat().st_size <= 1048576, "native per-input <=1MiB guard")
        return {"sha256":digest(path),"size":path.stat().st_size,"imports":imports,"exports":sorted(actual),
                "stack_reserve":h.SizeOfStackReserve,"stack_commit":h.SizeOfStackCommit,"pe98_gate":"pass"}

def instruction_gate(disassembly):
    forbidden=[]
    instructions=re.findall(r"^\s*[0-9a-f]+:\s+([a-z][a-z0-9.]*)\s*(.*)$",disassembly,re.MULTILINE)
    require(len(instructions)>100,"actual machine instructions required")
    for mnemonic,operands in instructions:
        if (mnemonic.startswith(("cmov","fcmov","fcomi","fucomi","prefetch","xsave","xrstor","fisttp"))
                or mnemonic in {"cpuid","rdtsc","rdmsr","wrmsr","cmpxchg8b","sysenter","sysexit",
                                "fxsave","fxrstor","mfence","lfence","sfence","pause","monitor","mwait","ud2"}
                or re.search(r"%(?:[xyz]mm\d+|mm[0-7])\b",operands)):
            forbidden.append(mnemonic)
    require(not forbidden,"post-i486 linked instruction present: "+repr(sorted(set(forbidden))))
    return {"instructions_decoded":len(instructions),"post_i486_families":"absent"}

def main():
    require(__debug__, "Python -O refused before output writes")
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--nonce",required=True)
    args=parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9_-]{12,96}",args.nonce),"nonce")
    out=args.output if args.output.is_absolute() else ROOT/args.output
    out=out.absolute()
    require(out.parent.resolve().is_relative_to((ROOT/"build").resolve()) and not out.exists() and not out.is_symlink(),"fresh build-only checkpoint required")
    source={name:digest(ROOT/name) for name in SOURCES}
    oem=json.loads((ROOT/SOURCES[-1]).read_text())["dlls"]
    require(set(DYNAMIC)<=set(oem["MSVCRT.DLL"]),"dynamic original CRT exports")
    out.mkdir(parents=True)
    steps=[]
    def run(command,name,env=None,timeout=900):
        p=subprocess.run(command,cwd=ROOT,env=env,text=True,capture_output=True,timeout=timeout)
        log=out/(name+".log");log.write_text(p.stdout+p.stderr)
        steps.append({"argv":command,"returncode":p.returncode,"log":str(log),"sha256":digest(log)})
        require(p.returncode==0,f"{name} failed: {(p.stdout+p.stderr)[-5000:]}")
        return p.stdout.strip()
    q,m,dependency=prepare(out)
    header=out/"selected.h"
    embedded=[]
    for name,label in (("trident_es2026_selected.js","es2026"),("trident_numeric_selected.js","numeric")):
        data=(ROOT/"tests"/name).read_bytes();require(0<len(data)<16384,"selected source bound")
        embedded.append("static const char m98_selected_"+label+"[]={"+",".join(str(b) for b in data)+",0};\n")
    header.write_text("".join(embedded))
    inputs=pins(sorted((out/"prepared").rglob("*.*")))
    include=["-Isrc","-I"+str(q),"-I"+str(m),"-I"+str(m/"src/internal"),"-I"+str(m/"src/math")]
    common=["-std=gnu11","-O0","-g0","-fwrapv","-ffunction-sections","-fdata-sections","-fno-stack-protector","-ffp-contract=off","-fexcess-precision=standard",'-DCONFIG_VERSION="'+QVER+'"',"-Dhidden="]+include
    host=["gcc"]+common+["-mfpmath=387"]
    native=["i686-w64-mingw32-gcc"]+common+["-march=i486","-mhard-float","-mno-sse","-mno-sse2","-mno-mmx","-mno-stack-arg-probe","-D_USE_32BIT_TIME_T","-D_WIN32_WINNT=0x0400","-D__USE_MINGW_ANSI_STDIO=0"]
    tool_ids={}
    for tool in ("gcc","clang","i686-w64-mingw32-gcc","i686-w64-mingw32-strip","i686-w64-mingw32-objdump"):
        path=Path(shutil.which(tool) or "missing")
        require(path.exists(),"compiler/tool missing")
        tool_ids[tool]={"path":str(path.resolve()),"sha256":digest(path.resolve()),"version":run([tool,"--version"],tool+"-identity")}
    runtime_dir=Path(run(["clang","-print-resource-dir"],"sanitizer-resource-directory"))/"lib/x86_64-redhat-linux-gnu"
    link_inputs={str(runtime_dir/name):digest(runtime_dir/name) for name in ("libclang_rt.asan_static.a","libclang_rt.asan.a","libclang_rt.asan.a.syms")}
    for name in ("libgcc.a","libmsvcrt.a","libkernel32.a"):
        path=Path(run(["i686-w64-mingw32-gcc","-print-file-name="+name],"native-link-input-"+name)).resolve()
        link_inputs[str(path)]=digest(path)
    cache=ROOT/"build/trident-script-object-cache";cache.mkdir(exist_ok=True)
    objects=[]
    # Every prepared header and port header participates, since the compiler
    # may consume one without it appearing as a direct source argument.
    context={str(p.relative_to(out)):sha for p,sha in ((Path(p),h) for p,h in inputs.items())}
    context["src/m98_trident_script_port.h"]=source["src/m98_trident_script_port.h"]
    def compile_one(task):
        flags,unit,label=task
        recipe={"compiler":tool_ids[flags[0]],"flags":flags[1:],"source":str(unit),"source_sha256":digest(unit),"header_context":({name:sha for name,sha in context.items() if name=="src/m98_trident_script_port.h" or (name.endswith(".h") and (name.startswith("prepared/quickjs/") if unit.is_relative_to(q) else name.startswith("prepared/math/")))} if unit.is_relative_to(out/"prepared") else {**source,**{name:sha for name,sha in context.items() if name.endswith(".h")}})}
        # Output checkpoint paths do not affect semantics and are normalized
        # solely for reuse; the exact executed command is retained separately.
        normalized=json.dumps(recipe,sort_keys=True).replace(str(out),"<CHECKPOINT>")
        key=hashlib.sha256(normalized.encode()).hexdigest()
        obj=cache/(key+".o");receipt=cache/(key+".json")
        command=flags+["-c",str(unit),"-o",str(obj)]
        reused=False
        if obj.exists() or receipt.exists():
            require(obj.exists() and receipt.exists() and not receipt.is_symlink(),"partial/unsafe object cache")
            old=json.loads(receipt.read_text())
            require(old["recipe_normalized"]==normalized and old["object_sha256"]==digest(obj),"cache provenance mismatch")
            reused=True
        else:
            run(command,label+"-compile")
            receipt.write_text(json.dumps({"recipe_normalized":normalized,"command":command,"object_sha256":digest(obj)},indent=2)+"\n")
        item={"key":key,"recipe":recipe,"executed_command":json.loads(receipt.read_text())["command"],"object":str(obj),"sha256":digest(obj),"reused":reused}
        objects.append(item)
        return str(obj)
    units=[q/name for name in UNITS]+[m/"src/math"/(name+".c") for name in MATH]
    models={}
    environment=dict(os.environ,ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",UBSAN_OPTIONS="halt_on_error=1")
    for profile,flags in (("host",host),("sanitize",host+["-fsanitize=address,undefined","-fno-omit-frame-pointer"]),("native",native)):
        with ThreadPoolExecutor(max_workers=2) as pool:
            compiled=list(pool.map(compile_one,[(flags,unit,profile+"-"+unit.stem) for unit in units]))
        if profile!="native":
            def host_link(names,binary,label):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    own_flags=[f for f in flags if f!="-fwrapv"] if label=="fault-control" else flags
                    own=list(pool.map(compile_one,[(own_flags,ROOT/name,profile+"-own-"+Path(name).stem) for name in names]))
                if profile=="sanitize":
                    # System GCC's libasan.so is absent on this host. Preserve
                    # GCC/x87 instrumentation and use the already installed
                    # Clang runtime only at link. Fault controls below prove
                    # both ASan and UBSan reporting are active for this mix.
                    command=["clang","-fsanitize=address,undefined"]
                else:
                    command=["gcc"]
                library=compiled if label=="interpreter" else [compiled[len(UNITS)+MATH.index("round")]] if label=="format" else []
                run(command+own+library+["-Wl,--gc-sections","-lm","-pthread","-o",str(binary)],profile+"-"+label+"-link")
            binary=out/profile
            host_link(["src/m98_trident_script.c","src/m98_trident_script_port.c","src/m98_trident_script_fp.c","tests/m98_trident_script_platform_host.c","tests/m98_trident_script_host.c"],binary,"interpreter")
            result=run([str(binary)],profile+"-run",environment if profile=="sanitize" else None,timeout=60)
            require("\"checks\":34" in result and "\"checks\":24" in result and "PASS: real bounded QuickJS host" in result,"actual selected interpreter verdict")
            format_binary=out/(profile+"-format")
            host_link(["src/m98_trident_script_port.c","tests/m98_trident_script_platform_host.c","tests/m98_trident_script_port_host.c"],format_binary,"format")
            format_result=run([str(format_binary)],profile+"-format-run",environment if profile=="sanitize" else None,timeout=60)
            require(format_result.startswith("PASS: bounded C99 formatting"),"format contract verdict")
            platform_binary=out/(profile+"-platform")
            # The actual platform source is included by its fault fixture.
            platform_flags=flags+["-Itests"]
            obj=compile_one((platform_flags,ROOT/"tests/m98_trident_script_win32_mock.c",profile+"-platform"))
            command=["clang","-fsanitize=address,undefined"] if profile=="sanitize" else ["gcc"]
            run(command+[obj,"-lm","-o",str(platform_binary)],profile+"-platform-link")
            platform_result=run([str(platform_binary)],profile+"-platform-run",environment if profile=="sanitize" else None,timeout=60)
            require(platform_result.startswith("PASS: actual Win32 platform"),"production platform fault-double verdict")
            models[profile]={"interpreter":result,"format":format_result,"platform":platform_result,"native_execution":False}
            if profile=="sanitize":
                fault=out/"sanitizer-fault-control"
                host_link(["tests/m98_trident_script_sanitizer_fault.c"],fault,"fault-control")
                controls=[]
                for argument,marker in (("asan","AddressSanitizer: heap-buffer-overflow"),("ubsan","runtime error: signed integer overflow")):
                    command=[str(fault),argument]
                    p=subprocess.run(command,cwd=ROOT,env=environment,text=True,capture_output=True,timeout=30)
                    log=out/("fault-"+argument+".log");log.write_text(p.stdout+p.stderr)
                    require(p.returncode!=0 and marker in p.stderr,"sanitizer negative control did not reject")
                    controls.append({"argv":command,"returncode":p.returncode,"expected_failure":True,"marker":marker,"log":str(log),"sha256":digest(log)})
                models[profile]["instrumentation_fault_controls"]=controls
        else:
            link=["-nostdlib","-Wl,--gc-sections","-Wl,--subsystem,windows:4.10","-Wl,--major-os-version,4","-Wl,--minor-os-version,10","-Wl,--disable-dynamicbase","-Wl,--disable-nxcompat","-Wl,--disable-tsaware","-Wl,--no-insert-timestamp","-Xlinker","--stack","-Xlinker","2097152,524288"]
            unstripped=out/"M98QJS.unstripped.dll"
            run(flags+link+["-shared","-Wl,--entry,_DllMain@12"]+compiled+["src/m98_trident_script.c","src/m98_trident_script_port.c","src/m98_trident_script_fp.c","src/m98_trident_script_win32.c","src/m98_trident_script.def","-lmsvcrt","-lkernel32","-lgcc","-o",str(unstripped)],"native-link")
            dll=out/"M98QJS.DLL";shutil.copyfile(unstripped,dll)
            run(["i686-w64-mingw32-strip","--strip-unneeded","--preserve-dates",str(dll)],"native-strip")
            disassembly=run(["i686-w64-mingw32-objdump","-d","--no-show-raw-insn",str(unstripped)],"native-disassembly")
            dll_instructions=instruction_gate(disassembly)
            dll_gate=pe_gate(dll,True,oem)
            probe=out/"QJS13PR.EXE"
            run(flags+link+['-DM98_SCRIPT_NONCE="'+args.nonce+'"','-DM98_SCRIPT_SHA256="'+digest(dll)+'"','-DM98_SCRIPT_SELECTED_HEADER="'+str(header)+'"',"-Wl,--entry,_mainCRTStartup","tests/m98_trident_script_guest.c","-lkernel32","-lgcc","-o",str(probe)],"native-probe")
            probe_gate=pe_gate(probe,False,oem)
            probe_disassembly=run(["i686-w64-mingw32-objdump","-d","--no-show-raw-insn",str(probe)],"native-probe-disassembly")
            probe_gate["i486_instructions"]=instruction_gate(probe_disassembly)
            dll_gate["i486_instructions"]=dll_instructions
    require(models["host"]["interpreter"]==models["sanitize"]["interpreter"] and models["host"]["format"]==models["sanitize"]["format"] and models["host"]["platform"]==models["sanitize"]["platform"],"sanitizer semantic mismatch")
    for name in SOURCES:
        target=out/"source"/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
        require(digest(target)==source[name],"frozen source mismatch")
    require(source=={name:digest(ROOT/name) for name in SOURCES} and inputs==pins([Path(p) for p in inputs]),"source drift during build")
    result={"passed":True,"profile":"bounded-local-trident-quickjs-v1","nonce":args.nonce,"source_sha256":source,"dependency":dependency,"prepared_sha256":inputs,"embedded_fixture_header_sha256":digest(header),"tool_identities":tool_ids,"link_input_sha256":link_inputs,"object_cache":objects,"models":models,"artifacts":{dll.name:dll_gate,probe.name:probe_gate,unstripped.name:{"sha256":digest(unstripped),"size":unstripped.stat().st_size}},"dynamic_original_crt_exports":DYNAMIC,"steps":steps,"feature_profile":{"atomics":False,"shared_memory":False,"stack_check":True,"external_modules":False,"std_os_workers":False,"js_double":"IEEE754 binary64","native_long_double":"x87 80bit,64bit significand","portable_math":"pinned musl subset; generic profile","host_basic_math":"host libc","native_basic_math":"original system MSVCRT","host_fpu":"x87 standard excess precision","native_fpu":"i486 x87 FNSAVE/FRSTOR full caller-state preservation; PC64 nearest masked exceptions","script_stack_limit":262144,"pe_stack_commit":524288},"selected_es2026_checks":34,"selected_numeric_checks":24,"native_guest_execution_verified":False,"native_math_verified":False,"mshtml_dom_verified":False,"html5_verified":False,"wasm_verified":False,"full_es2026_conformance_verified":False,"applications_verified":False,"user_objective_complete":False}
    (out/"result.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({"passed":True,"receipt":str(out/"result.json"),"models":models,"native_guest_execution_verified":False}))

if __name__=="__main__":
    main()
