#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Capture actual HKCU frontend bodies, execute host contracts, compile whole PE units."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).with_name("hkcu_identity_host.c")
W64 = Path("shizukudos/win64")


def definition(source, name):
    match = re.search(r"^[^\n;{}]*\b" + name + r"\([^;{}]*\)\s*\{", source, re.M)
    if not match:
        raise ValueError("missing actual definition: " + name)
    depth, state, i = 1, "code", match.end()
    while i < len(source):
        c, pair = source[i], source[i:i + 2]
        if state == "line":
            if c == "\n": state = "code"
        elif state == "comment":
            if pair == "*/": state = "code"; i += 1
        elif state in ("string", "char"):
            if c == "\\": i += 1
            elif c == ('"' if state == "string" else "'"): state = "code"
        elif pair == "//": state = "line"; i += 1
        elif pair == "/*": state = "comment"; i += 1
        elif c == '"': state = "string"
        elif c == "'": state = "char"
        elif c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if not depth: return source[match.start():i + 1]
        i += 1
    raise ValueError("unbounded actual definition: " + name)


def no_includes(source):
    return re.sub(r"^\s*#\s*include[^\n]*\n", "", source, flags=re.M)


def capture(source_ref=None):
    names = [W64 / "ntdll/rtlreg.c", W64 / "ntdll/ntobj.c", W64 / "dlls/advapi32/reg.c",
             W64 / "dlls/advapi32/reg_current_user.c", W64 / "dlls/advapi32/token.c",
             W64 / "include/ntreg.h", W64 / "include/nt.h", W64 / "build.py",
             FIXTURE.relative_to(ROOT), Path(__file__).resolve().relative_to(ROOT),
             Path("shizukudos/abi/shz_auth.h"), Path("shizukudos/accounts/account.h")]
    pending, data = [ROOT / name for name in names], {}
    while pending:
        path = pending.pop().resolve()
        relative = path.relative_to(ROOT)
        if relative in data: continue
        if source_ref and path not in (FIXTURE, Path(__file__).resolve()):
            contents = subprocess.run(["git", "show", source_ref + ":" + str(relative)], cwd=ROOT,
                                      capture_output=True, check=True).stdout
        else: contents = path.read_bytes()
        data[relative] = contents
        for include in re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"', contents, re.M):
            choices = [path.parent / include.decode(), ROOT / W64 / "include" / include.decode()]
            found = next((p for p in choices if p.is_file()), None)
            if found is None: raise ValueError("unresolved local include: " + include.decode())
            pending.append(found)
    return data


def run(command, output, env=None):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)
    output.write_text(result.stdout + result.stderr)
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="fresh owned evidence directory")
    parser.add_argument("--source-ref", help="optional immutable old commit; current fixture/runner remain identical")
    args = parser.parse_args(); out = args.out.resolve()
    if out.exists(): raise SystemExit("fresh output directory required")
    source_ref = subprocess.run(["git", "rev-parse", "--verify", args.source_ref + "^{commit}"], cwd=ROOT,
                                capture_output=True, text=True, check=True).stdout.strip() if args.source_ref else None
    data = capture(source_ref); snap = out / "source"
    for name, contents in data.items():
        target = snap / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(contents)
    src = lambda name: data[W64 / name].decode()
    rtl, reg, token = src("ntdll/rtlreg.c"), src("dlls/advapi32/reg.c"), src("dlls/advapi32/token.c")
    record = re.search(r"typedef struct shz_token_info \{.*?\} shz_token_info;", src("include/nt.h"), re.S).group(0)
    rendered = token.split("typedef struct { BYTE revision,count;", 1)[1].split("PSID sec_user_sid(", 1)[0]
    rendered = "typedef struct { BYTE revision,count;" + rendered
    prefix = no_includes(reg.split("/* ---------------------------------------------------------------- ANSI conversion */", 1)[0])
    functions = "\n".join(definition(reg, n) for n in ("open_w", "RegOpenKeyExW", "create_w", "RegCreateKeyExW", "RegCloseKey"))
    notify = reg.split("/* ---------------------------------------------------------------- change notification */", 1)[1]
    notify = notify.split("DLLAPI LONG WINAPI RegNotifyChangeKeyValue(", 1)[0]
    native_wrappers = "\n".join(definition(src("ntdll/ntobj.c"), n) for n in
                                 ("NtOpenProcessTokenEx", "NtOpenProcessToken", "NtOpenThreadTokenEx", "NtOpenThreadToken"))
    fixture = data[FIXTURE.relative_to(ROOT)].decode()
    replacements = {
        "/* ACTUAL_TOKEN_RECORD */": record + '\n#include "../shizukudos/abi/shz_auth.h"',
        "/* ACTUAL_NTREG_HEADER */": no_includes(src("include/ntreg.h")),
        "/* ACTUAL_TOKEN_WRAPPERS */": native_wrappers,
        "/* ACTUAL_TOKEN_USER_RENDERING */": rendered,
        "/* ACTUAL_RTLREG_UNIT */": no_includes(rtl),
        "/* ACTUAL_REGISTRY_FRONTEND */": prefix + "\n" + functions + "\n" + notify,
        "/* ACTUAL_REG_CURRENT_USER_UNIT */": no_includes(src("dlls/advapi32/reg_current_user.c")),
    }
    if "format_user_sid(" in rtl: fixture = "#define HAS_BOUNDED_SID_FORMAT 1\n" + fixture
    if "g_notify_users" in reg: fixture = "#define HAS_USER_NOTIFY_CACHE 1\n" + fixture
    for marker, body in replacements.items(): fixture = fixture.replace(marker, body)
    generated = snap / FIXTURE.relative_to(ROOT); generated.write_text(fixture)
    results = []
    for compiler in ("gcc", "clang"):
        cc = shutil.which(compiler)
        if not cc: raise SystemExit("missing installed compiler: " + compiler)
        flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                 "-Wno-unused-const-variable", "-fshort-wchar"]
        if compiler == "clang": flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
        executable = out / compiler; command = [cc, *flags, str(generated), "-o", str(executable)]
        code = run(command, out / (compiler + "-compile.log")); row = {"compiler": compiler, "command": command, "compile_exit": code}
        if not code:
            row["run_exit"] = run([str(executable)], out / (compiler + "-run.log"),
                                  dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"))
            row["executable_sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
            print(compiler, (out / (compiler + "-run.log")).read_text().splitlines()[0])
        else: print((out / (compiler + "-compile.log")).read_text())
        results.append(row)
    # Read the actual builder's common flags without importing or executing it.
    builder = src("build.py")
    import ast
    tree = ast.parse(builder)
    common = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == "COMMON" for t in n.targets))
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc: raise SystemExit("missing installed project compiler")
    for name, defines in (("ntdll/rtlreg.c", ["-DSHZ_NTDLL_BUILD"]), ("dlls/advapi32/reg.c", ["-DBUILDING_ADVAPI32"]),
                          ("dlls/advapi32/reg_current_user.c", ["-DBUILDING_ADVAPI32"])):
        obj = out / (Path(name).stem + ".obj")
        command = [cc, *common, *defines, "-I", str(snap / W64 / "include"), "-c", str(snap / W64 / name), "-o", str(obj)]
        code = run(command, out / (Path(name).stem + "-mingw.log"))
        row = {"whole_production_unit": name, "command": command, "compile_exit": code, "object_only": True}
        if not code: row["object_sha256"] = hashlib.sha256(obj.read_bytes()).hexdigest()
        results.append(row); print(name, "object PASS" if not code else "object FAIL")
    stable = data == capture(source_ref)
    good = stable and all(r["compile_exit"] == 0 and (r.get("object_only") or r.get("run_exit", 1) == 0) for r in results)
    receipt = {"schema": "shizuku-hkcu-identity-host/1", "status": "PASS_HOST_AND_PRODUCTION_OBJECTS" if good else "FAIL_HOST_EVIDENCE",
               "source_sha256": {str(n): hashlib.sha256(b).hexdigest() for n, b in data.items()}, "source_stable": stable,
               "source_ref": source_ref,
               "generated_fixture_sha256": hashlib.sha256(generated.read_bytes()).hexdigest(), "results": results,
               "bounded_sid_helper_present": "format_user_sid(" in rtl, "VM_executed": False,
               "native_Windows98_login_or_impersonation_verified": False,
               "scope": "actual frontend C bodies; host native transport/heap adapters; whole captured MinGW units"}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(receipt["status"]); return 0 if good else 1


if __name__ == "__main__": raise SystemExit(main())
