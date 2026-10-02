#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Small frozen public FAT32 helper controls; no install/media/VM operations.

--legacy-control executes an explicitly synthetic unrelocated copy model.
The same fixture links the real helper without that flag. Per-child8MiB
RLIMIT_FSIZE and observed64MiB leaf checks are not a hard aggregate allocation
quota or a bound on subprocess PIPE RAM. External compiler/sysroot closure,
full installer wiring and actual Windows98/native boot are not established.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
FILES = ["AGENTS.md", "shizukudos/win64/build.py",
         "shizukudos/win64/setup/native_fat32_relocate.h",
         "shizukudos/win64/setup/native_fat32_relocate.c",
         "shizukudos/install/tests/native_fat32_relocate_host.c",
         "shizukudos/install/tests/test_native_fat32_relocate_host.py"]
MIB = 1024 * 1024


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def usage(out):
    return sum(p.stat().st_size for p in out.rglob("*") if p.is_file())


def group_live(pgid):
    live = []
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            f = (p / "stat").read_text().rsplit(")", 1)[1].split()
            if int(f[2]) == pgid and f[0] not in ("Z", "X"):
                live.append(int(p.name))
        except FileNotFoundError:
            pass
    return live


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * MIB, 8 * MIB))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_owned(argv, command_seconds=25):
    """One new owned group,parameterized deadline + .5s TERM +1.5s KILL."""
    r = {"command_seconds": command_seconds, "argv": list(map(str, argv)), "returncode": None, "leader_reaped": False,
         "timed_out": False, "interrupted": False, "execution_error": False,
         "cleanup_failed": False, "group_term_attempted": False,
         "group_kill_attempted": False, "owned_group_live_members": []}
    proc = None
    stdout = stderr = ""
    start = time.monotonic()
    def send(sig):
        r["group_term_attempted" if sig == signal.SIGTERM else "group_kill_attempted"] = True
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        except OSError as exc:
            r["cleanup_failed"] = True
            r["cleanup_error"] = str(exc)
    try:
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                   UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        proc = subprocess.Popen(r["argv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, errors="replace", start_new_session=True,
                                preexec_fn=child_limits, env=env)
        r["owned_group"] = proc.pid
        stdout, stderr = proc.communicate(timeout=command_seconds)
        r["owned_group_live_members"] = group_live(proc.pid)
        if r["owned_group_live_members"]:
            r["cleanup_failed"] = True
    except subprocess.TimeoutExpired:
        r["timed_out"] = True
    except KeyboardInterrupt:
        r["interrupted"] = True
    except Exception as exc:
        r["execution_error"] = True
        r["execution_error_detail"] = type(exc).__name__ + ": " + str(exc)
    finally:
        if proc is not None and any(r[k] for k in
                                   ("timed_out", "interrupted", "execution_error", "cleanup_failed")):
            send(signal.SIGTERM)
            try:
                stdout, stderr = proc.communicate(timeout=.5)
            except subprocess.TimeoutExpired:
                pass
            except KeyboardInterrupt:
                r["interrupted"] = True
            except Exception as exc:
                r["cleanup_failed"] = True
                r["cleanup_error"] = str(exc)
            finally:
                send(signal.SIGKILL)  # never skipped just because leader exited0
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                try:
                    stdout, stderr = proc.communicate(timeout=min(.05, max(.001, deadline-time.monotonic())))
                    r["owned_group_live_members"] = group_live(proc.pid)
                    if proc.returncode is not None and not r["owned_group_live_members"]:
                        break
                except subprocess.TimeoutExpired:
                    pass
                except KeyboardInterrupt:
                    r["interrupted"] = True
                    send(signal.SIGKILL)
                except Exception as exc:
                    r["cleanup_failed"] = True
                    r["cleanup_error"] = str(exc)
                    break
            else:
                r["cleanup_failed"] = True
            proc.poll()
        if proc is not None:
            r["returncode"] = proc.returncode
            r["leader_reaped"] = proc.returncode is not None
        r["elapsed_seconds"] = time.monotonic() - start
    r["admitted"] = (r["returncode"] == 0 and r["leader_reaped"] and
                     not any(r[k] for k in ("timed_out", "interrupted", "execution_error", "cleanup_failed")))
    return r, stdout, stderr


def common_flags(path):
    for n in ast.parse(path.read_text()).body:
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "COMMON" for t in n.targets):
            value = ast.literal_eval(n.value)
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                break
            return value
    raise ValueError("actual setup COMMON unavailable")


def machine(path):
    b = path.read_bytes()
    if b[:4] == b"\x7fELF":
        return {3: "i386", 62: "x86_64"}.get(int.from_bytes(b[18:20], "little"), "unknown-ELF")
    return {0x14c: "i386", 0x8664: "x86_64"}.get(int.from_bytes(b[:2], "little"), "unknown-COFF")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--legacy-control", action="store_true")
    args = ap.parse_args()
    out = (ROOT / args.out).resolve()
    if not out.is_relative_to((ROOT / "build").resolve()) or out.exists():
        raise SystemExit("requires fresh own build leaf")
    out.mkdir(parents=True)
    result = {"schema": "native-fat32-host/v1", "status": "FAIL", "mode": "synthetic-unrelocated" if args.legacy_control else "actual-helper",
              "records": [], "source_before_sha256": {}, "source_after_sha256": {},
              "frozen_source_sha256": {}, "tool_before_sha256": {}, "tool_first_use_sha256": {},
              "tool_after_sha256": {}, "generated_first_use_sha256": {}, "host": [], "objects": [], "prefix_vectors": [], "errors": [],
              "caps": {"command_seconds": 25, "compiler_seconds": 60, "term_seconds": .5, "kill_seconds": 1.5,
                       "child_per_file_bytes": 8*MIB, "observed_leaf_bytes": 64*MIB,
                       "hard_aggregate_quota": False, "stdout_RAM_bound": False},
              "scope": {"external_sysroot_compiler_support_closed": False, "linked_consumer": False,
                        "installer_wired": False, "media_or_disk_job": False, "native_boot": False,
                        "AP_SMP": False, "full_ISO": False, "actual_Windows98_goal_complete": False}}
    tools = {}
    frozen = out / "frozen"
    def execute(argv, name):
        if usage(out) > 64*MIB:
            raise ValueError("observed leaf limit before command")
        exe = str(Path(argv[0]).resolve())
        if exe not in result["tool_first_use_sha256"] and exe in result["tool_before_sha256"]:
            result["tool_first_use_sha256"][exe] = digest(exe)
            if result["tool_first_use_sha256"][exe] != result["tool_before_sha256"][exe]:
                raise ValueError("tool changed before first use")
        for p, want in result["frozen_source_sha256"].items():
            if digest(frozen/p) != want or digest(ROOT/p) != want:
                raise ValueError("source changed before command: " + p)
        for arg in argv:
            p = Path(arg)
            if p.is_absolute() and p.is_relative_to(out) and p.is_file():
                key, value = str(p.relative_to(out)), digest(p)
                if key in result["generated_first_use_sha256"] and result["generated_first_use_sha256"][key] != value:
                    raise ValueError("input changed after first use: " + key)
                result["generated_first_use_sha256"][key] = value
        r, stdout, stderr = run_owned(argv, 60 if name.endswith("-compile") else 25)
        r["name"] = name
        result["records"].append(r)
        for suffix, data in (("stdout", stdout), ("stderr", stderr)):
            p = out / (name + "." + suffix + ".log")
            p.write_text(data)
            r[suffix + "_log"] = p.name
            r[suffix + "_sha256"] = digest(p)
        if usage(out) > 64*MIB:
            raise ValueError("observed leaf limit after command")
        return r, stdout
    try:
        for p in FILES:
            data = (ROOT/p).read_bytes()
            result["source_before_sha256"][p] = hashlib.sha256(data).hexdigest()
            dest = frozen/p
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            result["frozen_source_sha256"][p] = digest(dest)
        for name in ("gcc", "clang", "x86_64-w64-mingw32-gcc", "nm", "objdump"):
            tools[name] = str(Path(shutil.which(name) or "missing-tool").resolve(strict=True))
        if shutil.which("i686-w64-mingw32-gcc"):
            tools["i386"] = str(Path(shutil.which("i686-w64-mingw32-gcc")).resolve())
        else:
            tools["i386"] = tools["clang"]
        result["tools"] = tools
        result["tool_before_sha256"] = {p: digest(p) for p in sorted(set(tools.values()))}
        for k in ("gcc", "clang", "x86_64-w64-mingw32-gcc", "i386"):
            r, _ = execute([tools[k], "--version"], "version-" + k)
            if not r["admitted"]:
                raise ValueError("compiler identity command refused")
        fixture = frozen/FILES[4]
        helper = frozen/FILES[3]
        for compiler, extra in (("gcc", ["-O2"]), ("clang", ["-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
            binary = out / (compiler + "-host")
            sources = [fixture] if args.legacy_control else [fixture, helper]
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", *extra]
            if args.legacy_control:
                flags += ["-DNATIVE_FAT32_LEGACY_CONTROL"]
            cr, _ = execute([tools[compiler], *flags, *sources, "-o", binary], compiler + "-compile")
            row = {"compiler": compiler, "sanitizers": compiler == "clang", "compile_admitted": cr["admitted"]}
            result["host"].append(row)
            if not cr["admitted"]:
                continue
            vectors = out / (compiler + "-vectors")
            vectors.mkdir()
            rr, stdout = execute([binary, vectors], compiler + "-run")
            metrics = re.findall(r"native-fat32 checks=(\d+) failures=(\d+)", stdout)
            row.update(run_admitted=rr["admitted"], returncode=rr["returncode"], metrics=metrics)
            if len(metrics) != 1:
                raise ValueError("missing actual host metrics")
            row["checks"], row["failures"] = map(int, metrics[0])
            for k, backup in ((0, 6), (1, 10)):
                src = (vectors/f"{k}-source.bin").read_bytes()
                dst = (vectors/f"{k}-relocated.bin").read_bytes()
                expected = bytearray(src)
                expected[28:32] = b"\x78\x56\x34\x12"
                expected[backup*512+28:backup*512+32] = b"\x78\x56\x34\x12"
                result["prefix_vectors"].append({"compiler": compiler, "backup_sector": backup, "bytes": len(src),
                    "valid": len(src) == len(dst) == 8192 and src[28:32] == src[backup*512+28:backup*512+32] == b"\0"*4 and dst == expected,
                    "source_prefix_sha256": hashlib.sha256(src).hexdigest(),
                    "expected_relocated_prefix_sha256": hashlib.sha256(expected).hexdigest(),
                    "actual_relocated_prefix_sha256": hashlib.sha256(dst).hexdigest(),
                    "qualification": "Only synthetic8KiB prefix, not whole64MiB volume digest or installer SHA validation."})
        if not args.legacy_control:
            consumer = out / "consumer.c"
            consumer.write_text('#include "native_fat32_relocate.h"\nint consumer(const unsigned char *p,const unsigned char *b,const unsigned char *f,const unsigned char *bf,unsigned char *w){shz_native_fat32_relocate_t q;int s=shz_native_fat32_relocate_stage(p,512,b,512,f,512,bf,512,0,67108864,2048,133119,&q,sizeof q);return s?s:shz_native_fat32_relocate_overlay(&q,sizeof q,0,w,512);}\n')
            result["generated_consumer_sha256"] = digest(consumer)
            setup_flags = common_flags(frozen/FILES[1])
            for target, compiler in (("x86_64", tools["x86_64-w64-mingw32-gcc"]), ("i386", tools["i386"])):
                flags = setup_flags if compiler != tools["clang"] else ["--target=i386-none-elf", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-stack-protector"]
                for label, src in (("helper", helper), ("consumer", consumer)):
                    obj, dep = out/(target+"-"+label+".o"), out/(target+"-"+label+".d")
                    r, _ = execute([compiler, *flags, "-I", helper.parent, "-MMD", "-MF", dep, "-c", src, "-o", obj], target+"-"+label+"-compile")
                    item = {"target": target, "input": str(src), "compile_admitted": r["admitted"]}
                    result["objects"].append(item)
                    if not r["admitted"]:
                        continue
                    dependencies = dep.read_text().replace("\\\n", " ").split(":", 1)[1].split()
                    item["local_dependency_sha256"] = {p: digest(p) for p in dependencies}
                    item["dependencies_bound"] = str(src) in dependencies and str(helper.parent/"native_fat32_relocate.h") in dependencies
                    item["machine"] = machine(obj)
                    nr, text = execute([tools["nm"], "--undefined-only", obj], target+"-"+label+"-nm")
                    item["nm_admitted"] = nr["admitted"]
                    item["undefined_symbols"] = [line.split()[-1].lstrip("_") for line in text.splitlines() if line.strip()]
                    if label == "helper":
                        item["undefined_expected"] = (not item["undefined_symbols"] if target == "x86_64" else
                                                      set(item["undefined_symbols"]).issubset({"udivdi3"}))
                        item["compile_only_libgcc_dependency"] = bool(item["undefined_symbols"])
                    else:
                        item["undefined_expected"] = item["undefined_symbols"] == ["shz_native_fat32_relocate_overlay", "shz_native_fat32_relocate_stage"]
                    dr, _ = execute([tools["objdump"], "-f", obj], target+"-"+label+"-machine")
                    item["machine_record_admitted"] = dr["admitted"]
        hosts = result["host"]
        if args.legacy_control:
            result["red_control_observed"] = len(hosts) == 2 and all(h.get("checks", 0) > 0 and h.get("failures", 0) > 0 and h.get("returncode") == 1 and h["compile_admitted"] for h in hosts)
        else:
            good = len(hosts) == 2 and all(h.get("run_admitted") and h.get("checks", 0) > 0 and h.get("failures") == 0 for h in hosts)
            good &= len(result["objects"]) == 4 and all(x.get("compile_admitted") and x.get("dependencies_bound") and x.get("machine") == x["target"] and x.get("nm_admitted") and x.get("undefined_expected") and x.get("machine_record_admitted") for x in result["objects"])
            good &= len(result["prefix_vectors"]) == 4 and all(x["valid"] for x in result["prefix_vectors"])
            result["status"] = "PASS" if good else "FAIL"
    except BaseException as exc:
        result["errors"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        for key, paths in (("source_after_sha256", [ROOT/p for p in result["source_before_sha256"]]),
                           ("tool_after_sha256", list(result["tool_before_sha256"]))):
            for p in paths:
                try:
                    result[key][str(Path(p).relative_to(ROOT)) if key.startswith("source") else str(p)] = digest(p)
                except Exception as exc:
                    result["errors"].append("final pin: " + str(exc))
        result["inputs_stable"] = result["source_before_sha256"] == result["source_after_sha256"] == result["frozen_source_sha256"] and result["tool_before_sha256"] == result["tool_after_sha256"]
        result["artifact_sha256"] = {str(p.relative_to(out)): digest(p) for p in sorted(out.rglob("*")) if p.is_file() and p.name != "result.json"}
        if any(result["artifact_sha256"].get(k) != v for k, v in result["generated_first_use_sha256"].items()):
            result["status"] = "FAIL"
            result["errors"].append("generated input changed after first use")
        result["artifact_map_excludes"] = ["result.json (receipt independently hashed by caller)"]
        result["observed_leaf_bytes_excluding_receipt"] = usage(out)
        if result["errors"] or not result["inputs_stable"] or any(any(r[k] for k in ("timed_out", "interrupted", "execution_error", "cleanup_failed")) or not r["leader_reaped"] for r in result["records"]):
            result["status"] = "FAIL"
            result["red_control_observed"] = False
        result["receipt_bytes"] = 0
        for _ in range(8):
            result["observed_leaf_bytes_including_receipt"] = result["observed_leaf_bytes_excluding_receipt"] + result["receipt_bytes"]
            if result["observed_leaf_bytes_including_receipt"] > 64*MIB:
                result["status"] = "FAIL"
            body = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
            if len(body) == result["receipt_bytes"]:
                break
            result["receipt_bytes"] = len(body)
        (out/"result.json").write_bytes(body)
    print(result["status"], out/"result.json", flush=True)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
