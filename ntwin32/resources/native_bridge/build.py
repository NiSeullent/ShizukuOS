#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a hash-closed resource graph and separately patched native loader copy."""
import argparse
import datetime
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
V3 = ROOT / "build/resource-adapter-validation-20261001T0725-v3/result.json"
V3_SHA = "5318fc335871c33836edb50e4b4079f7a5b3655592ee6cdf6f7e1a59c89a18b5"
REVIEW = ROOT / "build/resource-adapter-independent-review-20261001T0730-v3/review.json"
REVIEW_SHA = "f64fcca2c0da3bd9c93595461c001c42f795b18f7f4a71682107a07c7ed5c6f1"


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1048576), b""):
            h.update(b)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    out = parser.parse_args().out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("absent private build directory required")
    if shutil.disk_usage(ROOT).free < 17 * 1024**3 + 512 * 1024**2:
        parser.error("existing 17 GiB plus 512 MiB floor required")
    out.mkdir(parents=True)
    receipt = {"schema": "win98modern.patched-native-resource-bridge.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "steps": [],
               "native_executed": False, "application_success": False, "chromium_entry_calls": 0,
               "held_loader_modified": False, "default_runtime_admission_changed": False,
               "resource_diagnostic": "private execute3; exact own graph SHA256 required before attach/entry",
               "native_acceptance": "pending parent release and genuine guest evidence"}

    def run(command, name, timeout=120):
        log = out / (name + ".log")
        with log.open("wb") as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=stream, timeout=timeout)
        receipt["steps"].append({"command": command, "exit_code": result.returncode,
                                  "log": {"path": str(log), "sha256": sha(log)}})
        if result.returncode:
            raise ValueError("bounded compilation/control failed: " + name)
        return log.read_text()

    try:
        if sha(V3) != V3_SHA or sha(REVIEW) != REVIEW_SHA:
            raise ValueError("accepted v3 producer/review changed")
        parent = json.loads(V3.read_text())
        pins = dict(parent["sources"])
        names = ("bridge.h", "bridge.c", "native_hooks.inc", "patch_loader.py", "graph_data.rc", "graph_app.rc",
                 "graph_data.def", "graph_app.def", "graph_data.c", "graph_app.c", "native_probe.c", "host_test.c", "README.md", "build.py")
        for name in names:
            p = HERE / name; pins[str(p.relative_to(ROOT))] = sha(p)
        for name in ("tls_runtime.c", "tls_runtime.h", "build.py"):
            p = ROOT / "ntwin32/native_loader" / name; pins[str(p.relative_to(ROOT))] = sha(p)
        for name, pin in parent["sources"].items():
            if sha(ROOT / name) != pin or sha(V3.parent / "frozen" / name) != pin:
                raise ValueError("held v3 current/frozen source changed")
        receipt["sources"] = pins
        for name, pin in pins.items():
            p = out / "frozen" / name;p.parent.mkdir(parents=True, exist_ok=True);shutil.copyfile(ROOT / name, p)
            if sha(p) != pin:
                raise ValueError("source changed during freezing")
        receipt["parents"] = []
        for p, pin in ((V3, V3_SHA), (REVIEW, REVIEW_SHA)):
            target = out / "parents" / p.parent.name / p.name;target.parent.mkdir(parents=True, exist_ok=True);shutil.copyfile(p, target)
            receipt["parents"].append({"path": str(p), "sha256": pin, "frozen": str(target)})
        tools = {}
        for name in ("i686-w64-mingw32-gcc", "i686-w64-mingw32-windres", "gcc", "clang", "i686-w64-mingw32-objdump"):
            p = shutil.which(name)
            if not p:
                raise ValueError("existing compiler/ABI tool missing")
            tools[name] = p
        receipt["toolchain"] = [dict(i) for i in parent["compilers"]]
        for name, p in tools.items():
            if not any(i["path"] == p for i in receipt["toolchain"]):
                receipt["toolchain"].append({"name": name, "path": p, "sha256": sha(p)})
        if any(sha(i["path"]) != i["sha256"] for i in receipt["toolchain"]):
            raise ValueError("accepted compiler/toolchain changed")
        frozen = out / "frozen";source = frozen / "ntwin32/resources/native_bridge"
        resources = frozen / "ntwin32/resources";native = frozen / "ntwin32/native_loader"
        kernel = frozen / "ntwin32/process_exit";crypto = frozen / "shizukufs/v1/tools";memory = frozen / "platform/freestanding/memory.c"
        cc = tools["i686-w64-mingw32-gcc"]
        flags = [cc, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                 "-fno-builtin", "-fno-tree-loop-distribute-patterns", "-fno-stack-protector", "-ffunction-sections",
                 "-fdata-sections", "-nostdlib", "-Wl,--gc-sections", "-Wl,--subsystem,windows:4.10",
                 "-Wl,--major-os-version,4", "-Wl,--minor-os-version,0", "-Wl,--disable-dynamicbase",
                 "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp",
                 "-Xlinker", "--stack", "-Xlinker", "4194304,65536"]
        for kind in ("data", "app"):
            run([tools["i686-w64-mingw32-windres"], "-O", "coff", str(source / ("graph_" + kind + ".rc")), str(out / (kind + ".o"))], kind + "-resource-compile")
        run(flags + ["-shared", "-Wl,--entry,_DllMain@12", "-Wl,--out-implib," + str(out / "rbdata.a"),
                     str(source / "graph_data.c"), str(source / "graph_data.def"), str(out / "data.o"), "-lkernel32", "-o", str(out / "RBDATA.DLL")], "data-DLL-build")
        for name, extra in (("RBAPP.EXE", ["-Wl,--entry,_entry@0"]), ("RBROOT.DLL", ["-DNRB_DLL_ROOT", "-shared", "-Wl,--entry,_DllMain@12"])):
            run(flags + extra + [str(source / "graph_app.c"), str(source / "graph_app.def"), str(out / "app.o"),
                                str(out / "rbdata.a"), "-lkernel32", "-o", str(out / name)], name + "-build")
        header = "typedef struct nrb_pin {const char *name;unsigned bytes;const char *sha;} nrb_pin;\n#define NRB_GRAPH_FILES 3u\nstatic const nrb_pin nrb_graph_pins[]={\n"
        for name in ("RBAPP.EXE", "RBROOT.DLL", "RBDATA.DLL"):
            p = out / name;header += ' {"%s",%du,"%s"},\n' % (name, p.stat().st_size, sha(p))
        header += "};\n";(out / "graph_pins.h").write_text(header)
        spec = importlib.util.spec_from_file_location("frozen_resource_patch", source / "patch_loader.py")
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        original = (native / "native.c").read_text();patched = module.patch(original)
        (out / "patched").mkdir();(out / "patched/native.c").write_text(patched)
        entry_definition="void WINAPI entry(void)"
        if patched.count(entry_definition)!=1:
            raise ValueError("exact probe wrapper entry seam differs")
        # Rename just the function definition, never preprocessor tokens in
        # PE headers or m->pe.entry fields across translation units.
        probe_copy=patched.replace(entry_definition,"void WINAPI held_loader_entry(void)")
        (out / "patched/probe_loader.c").write_text(probe_copy)
        diff = ''.join(difflib.unified_diff(original.splitlines(True), patched.splitlines(True), fromfile="held/native.c", tofile="patched/native.c"))
        (out / "native.patch").write_text(diff)
        receipt["patched_loader"] = {"base": str(native / "native.c"), "base_sha256": sha(native / "native.c"),
                                     "path": str(out / "patched/native.c"), "sha256": sha(out / "patched/native.c"),
                                     "diff": str(out / "native.patch"), "diff_sha256": sha(out / "native.patch"),
                                     "probe_copy":str(out/"patched/probe_loader.c"),"probe_copy_sha256":sha(out/"patched/probe_loader.c"),
                                     "probe_only_change":"loader entry function definition renamed; headers/field names unchanged"}
        # Neither parser nor profile is patched. Ordinary CLI/worker modes remain
        # textually exact; the only execute3 call lives in own native_probe.c.
        for name in ("valid_arguments", "worker", "supervised", "entry"):
            pattern = r"(?:static [^\n]+ |void WINAPI )" + name + r"\([^\n]*\)\n\{.*?\n\}"
            a = re.search(pattern, original, re.S);b = re.search(pattern, patched, re.S)
            if not a or not b or a[0] != b[0]:
                raise ValueError("ordinary native CLI/control changed: " + name)
        includes = ["-I", str(out), "-I", str(frozen), "-I", str(native), "-I", str(crypto)]
        core = [str(source / "bridge.c"), str(resources / "win32_adapter.c"), str(resources / "resources.c"), str(native / "pe.c"), str(crypto / "sha256.c")]
        host_results = []
        for kind, compiler, extra in (("normal", tools["gcc"], []), ("sanitized", tools["clang"],
                ["--no-default-config", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"])):
            executable = out / ("bridge-host-" + kind)
            run([compiler] + extra + ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation"] + includes + core +
                [str(source / "host_test.c"), "-o", str(executable)], kind + "-host-compile")
            text = run([str(executable), str(out / "RBAPP.EXE"), str(out / "RBDATA.DLL")], kind + "-host-controls")
            match = re.search(r"RESULT PASS cases=(\d+) checks=(\d+) native_executed=false application_success=false", text)
            if not match or "runtime error" in text or "Sanitizer" in text:
                raise ValueError("actual bridge lifetime/gate controls missing")
            host_results.append({"kind": kind, "cases": int(match[1]), "checks": int(match[2]), "sha256": sha(executable)})
        receipt["host_controls"] = host_results
        common = [str(kernel / n) for n in ("original_kernel_win98_v3.c", "main_image.c", "win98_guard.c", "win98_export.c")]
        common += [str(memory), str(native / "tls_runtime.c")]
        for name, sourcefile in (("RBPROBE.EXE", source / "native_probe.c"), ("RBLOAD.EXE", out / "patched/native.c")):
            run(flags + includes + ["-Wl,--entry,_entry@0", str(sourcefile)] + core + common + ["-lkernel32", "-lgcc", "-o", str(out / name)], name + "-build")
        receipt["graph_header"] = {"path": str(out / "graph_pins.h"), "sha256": sha(out / "graph_pins.h")}
        inventory = frozen / "benchmarks/win98se-ko-oem-native-exports-v1.json"
        available = {k.upper(): set(v) for k, v in json.loads(inventory.read_text())["dlls"].items()};artifacts = []
        for name in ("RBAPP.EXE", "RBROOT.DLL", "RBDATA.DLL", "RBPROBE.EXE", "RBLOAD.EXE"):
            p = out / name
            with pefile.PE(str(p)) as pe:
                o = pe.OPTIONAL_HEADER
                if (pe.FILE_HEADER.Machine,o.Magic,o.Subsystem,o.MajorSubsystemVersion,o.MinorSubsystemVersion,o.MajorOperatingSystemVersion,o.MinorOperatingSystemVersion)!=(0x14c,0x10b,2,4,10,4,0):
                    raise ValueError("classic i486 PE32 GUI profile differs")
                if o.DllCharacteristics&0x140 or any(o.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14)) or pe.is_dll()!=name.endswith('.DLL'):
                    raise ValueError("unexpected native profile")
                if bool(o.DATA_DIRECTORY[2].VirtualAddress)!=(name in ("RBAPP.EXE","RBROOT.DLL","RBDATA.DLL")):
                    raise ValueError("own resource graph/native host resource identity differs")
                imports = {}
                for d in getattr(pe,"DIRECTORY_ENTRY_IMPORT",()):
                    dll=d.dll.decode().upper();imports[dll]=[]
                    for symbol in d.imports:
                        if not symbol.name:
                            raise ValueError("native ordinal imports remain unsupported")
                        api=symbol.name.decode()
                        if api not in available.get(dll,set()) and not (dll=="RBDATA.DLL" and api=="RData@12"):
                            raise ValueError("outside exact OEM/private imports: "+dll+"!"+api)
                        imports[dll].append(api)
                expected={"KERNEL32.DLL","RBDATA.DLL"} if name in ("RBAPP.EXE","RBROOT.DLL") else {"KERNEL32.DLL"}
                if set(imports)!=expected or p.stat().st_size>1024*1024:
                    raise ValueError("classic closure/input budget differs")
                exports={s.name.decode() for s in getattr(getattr(pe,"DIRECTORY_ENTRY_EXPORT",None),"symbols",()) if s.name}
                expected_exports={"RData@12"} if name=="RBDATA.DLL" else {"NtwResourceResult","NtwResourceChecks","NtwPeFixture"} if name in ("RBAPP.EXE","RBROOT.DLL") else set()
                if exports!=expected_exports:
                    raise ValueError("actual own export closure differs")
                artifacts.append({"path":str(p),"bytes":p.stat().st_size,"sha256":sha(p),"imports":imports,"exports":sorted(exports),"oem_private_import_gate":"PASS","native_executed":False})
        wrapped=[("_resource_find_ex_a@16",16),("_resource_find_ex_w@16",16),("_resource_find_a@12",12),("_resource_find_w@12",12),
                 ("_resource_load@8",8),("_resource_lock@4",4),("_resource_size@8",8),("_resource_free@4",4)]
        for index,(symbol,argument_bytes) in enumerate(wrapped):
            code=run([tools["i686-w64-mingw32-objdump"],"--disassemble="+symbol,str(out/"RBPROBE.EXE")],"resource-wrapper-ABI-"+str(index))
            if "<"+symbol+">:" not in code or not re.search(r"ret\s+\$0x%x\b"%argument_bytes,code):
                raise ValueError("actual resource wrapper stdcall return differs: "+symbol)
        receipt["compiled_wrapper_ABI"]=[{"symbol":s,"return_argument_bytes":n} for s,n in wrapped]
        # Preserve exact prior compiler/source/gate receipts; no original target execution.
        if any(sha(ROOT / n)!=pin or sha(frozen/n)!=pin for n,pin in pins.items()):
            raise ValueError("held/new source changed during build")
        if sha(V3)!=V3_SHA or sha(REVIEW)!=REVIEW_SHA or any(sha(i["path"])!=i["sha256"] for i in receipt["toolchain"]):
            raise ValueError("accepted parent/toolchain changed")
        receipt.update(status="HOST_BUILD_PASS_NATIVE_PENDING",artifacts=artifacts,sources_stable=True,
                       ordinary_cli_control_identical=True,pe_profiles_and_limits_unmodified=True,
                       closed_native_controls=["default mode2 resource imports still BLOCKED","mode3 application and DLL-root resources",
                          "GetProcAddress same resource route","retained data after FreeLibrary","four successful resource calls during DLL detach",
                          "unregister before mapping release","post-cleanup stale data INVALID_HANDLE"],
                       actual_native_controls_observed=False)
        receipt["compiled_native_last_error_controls"]={"per_graph":14,"mapped_EXE_and_native_DLL_host_NULL":True,"observed_in_guest":False}
    except (OSError,ValueError,subprocess.TimeoutExpired,pefile.PEFormatError) as error:
        receipt["error"] = str(error)
    result=out/"result.json";result.write_text(json.dumps(receipt,indent=2)+'\n')
    if receipt["status"]=="HOST_BUILD_PASS_NATIVE_PENDING":
        manifest={"schema":1,"kind":"isolated-guest-file-inputs","inputs":[{"source":i["path"],"guest":"C:\\VXDLAB\\"+Path(i["path"]).name,
                  "bytes":i["bytes"],"sha256":i["sha256"]} for i in receipt["artifacts"] if Path(i["path"]).name!="RBLOAD.EXE"],
                  "outputs":["C:\\VXDLAB\\RBPROBE.LOG"],"backups":[],"source_receipts":[{"path":str(result),"sha256":sha(result)}],
                  "command":"C:\\VXDLAB\\RBPROBE.EXE","scope":"Plan only: hash-closed own native resource graph against separately patched loader. No production source change/Chromium admission or execution."}
        (out/"manifest.json").write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({"status":receipt["status"],"result":str(result),"sha256":sha(result),"error":receipt.get("error")}))
    return 0 if receipt["status"]=="HOST_BUILD_PASS_NATIVE_PENDING" else 1


if __name__=="__main__":
    raise SystemExit(main())
