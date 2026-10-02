#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Static fault controls for a frozen theme build; never launch a guest.

Run with python3 -O and fresh --output-dir beneath this worktree's build/.
The real builder gate rejects eight one-field PE corruptions. The installed
MinGW SDK checks a real positive GUI copy and rejects its missing-flags2 copy.
The no-argument builder must reject its nonempty historical directory early.
Only this test's fresh directory may receive copies, compiler logs or receipts.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import resource
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import time
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
RESERVE = 20 * 1024**3
BUDGET = 2 * 1024**2
RAM = 6 * 1024**3
TIMEOUT = 30
POLL_SECONDS = 0.05
FALSE_FLAGS = {"native_execution": False, "native_gui_verified": False,
               "os_wide_theme_verified": False, "application_functionality_verified": False}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum=16 * 1024**2):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical input: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        import stat
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "unbounded/nonregular input")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        after = os.fstat(fd)
        require(len(data) == before.st_size and all(getattr(before, field) == getattr(after, field)
                for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")), "input changed while reading")
        return data
    finally:
        os.close(fd)


def receipt(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=unique)
    require(isinstance(result, dict), "receipt must be an object")
    return result


def mem_available():
    return next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:"))


def own_bytes(directory):
    total = 0
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "unexpected output symlink")
        if path.is_file():
            total += path.stat().st_size
    return total


def rss(group):
    total = 0
    for path in Path("/proc").glob("[0-9]*"):
        try:
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group:
                total += next((int(line.split()[1]) * 1024 for line in
                               (path / "status").read_text().splitlines() if line.startswith("VmRSS:")), 0)
        except (OSError, ValueError, IndexError):
            continue
    return total


def guard(directory, samples, group=None):
    values = {"free_bytes": shutil.disk_usage(ROOT).free, "mem_available_bytes": mem_available(),
              "own_bytes": own_bytes(directory), "owned_group_rss_bytes": rss(group) if group else 0}
    samples.append(values)
    require(values["free_bytes"] >= RESERVE, "disk reserve breached")
    require(values["mem_available_bytes"] >= RAM, "available memory floor breached")
    require(values["own_bytes"] <= BUDGET, "own output budget breached")
    require(values["owned_group_rss_bytes"] <= RAM, "owned process-group RSS limit breached")


def write(path, data, directory, samples):
    guard(directory, samples)
    require(own_bytes(directory) + len(data) <= BUDGET, "write exceeds own budget")
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    require(read(path) == data, "new output readback differs")
    guard(directory, samples)


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024, 128 * 1024))
    resource.setrlimit(resource.RLIMIT_AS, (RAM, RAM))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT))


def stop_owned(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def command(argv, name, directory, samples, steps):
    guard(directory, samples)
    start = time.monotonic()
    step = {"command": argv, "timeout_seconds": TIMEOUT, "stdout": name + ".stdout",
            "stderr": name + ".stderr"}
    steps.append(step)
    process = None
    try:
        with (directory / step["stdout"]).open("xb") as out, (directory / step["stderr"]).open("xb") as err:
            process = subprocess.Popen(argv, cwd=ROOT, stdout=out, stderr=err, start_new_session=True,
                                       preexec_fn=limits, env=dict(os.environ, LC_ALL="C", LANG="C",
                                                                 PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(directory)))
            step["owned_process_group"] = process.pid
            while process.poll() is None:
                guard(directory, samples, process.pid)
                require(time.monotonic() - start <= TIMEOUT, "owned command timeout")
                time.sleep(POLL_SECONDS)
            step["returncode"] = process.wait()
    except BaseException as error:
        if process is not None:
            stop_owned(process)
        step["error"] = str(error)
        raise
    finally:
        step["elapsed_seconds"] = time.monotonic() - start
        for field in ("stdout", "stderr"):
            path = directory / step[field]
            if path.exists():
                step[field + "_sha256"] = digest(read(path, 128 * 1024))
    guard(directory, samples)
    return step


def local_directory(value, existing):
    path = Path(value)
    path = path if path.is_absolute() else ROOT / path
    require(path.absolute() == path and path.is_relative_to(ROOT / "build"), "directory must be canonical beneath own build/")
    if existing:
        require(path.resolve(strict=True) == path and path.is_dir(), "invalid artifact directory")
    else:
        require(path.parent.resolve(strict=True) == path.parent and not path.exists() and not path.is_symlink(),
                "output directory must be fresh with an existing canonical parent")
    return path


def tree_identity(directory):
    rows = {}
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "historical directory contains unexpected symlink")
        value = path.stat()
        rows[str(path.relative_to(directory))] = [value.st_dev, value.st_ino, value.st_mode,
                                                value.st_size, value.st_mtime_ns, value.st_ctime_ns]
    return rows


def early_default_guard(source):
    main = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "main")
    for node in main.body:
        if isinstance(node, ast.If) and ast.unparse(node.test) == "BUILD.exists() and any(BUILD.iterdir())":
            require(any(isinstance(child, ast.Raise) for child in node.body), "default guard must reject")
            return
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == "BUILD.mkdir":
            break
    raise ValueError("unconditional nonempty default-directory rejection must precede BUILD.mkdir")


def run(artifact_directory, directory, samples, steps):
    frozen = {}
    def pin(path, maximum=16 * 1024**2):
        data = read(path, maximum)
        frozen[str(path)] = digest(data)
        return data
    build_data = pin(artifact_directory / "result.json")
    build = receipt(build_data)
    require(build.get("passed") is True and build.get("native_win98") == "not_tested", "not a successful static-only build receipt")
    require(set(build.get("artifacts", {})) == {"M98THEME.DLL", "M98THPRO.EXE", "M98THSTA.EXE", "SHZAPPEAR.EXE"},
            "exact four frozen theme artifacts required")
    sources = build.get("source_sha256")
    require(isinstance(sources, dict) and sources, "missing frozen source pins")
    for name, expected in sources.items():
        require(isinstance(name, str) and not Path(name).is_absolute() and ".." not in Path(name).parts,
                "invalid relative source")
        require(digest(pin(ROOT / name)) == expected, "frozen source generation differs: " + name)
    pin(Path(__file__).resolve())
    builder_path = ROOT / "tools/build_theme_engine.py"
    app_path = ROOT / "apps/shizukuos-appearance/main.c"
    require(all(str(path) in frozen for path in (builder_path, app_path, ROOT / "src/uxtheme_engine.def",
                                                ROOT / "src/uxtheme_engine_win32.c")), "required builder/app/provider source pins absent")
    for name, row in build["artifacts"].items():
        require(Path(name).name == name, "invalid artifact name")
        data = pin(artifact_directory / name, 1024**2)
        require(digest(data) == row["sha256"] and len(data) == row["bytes"], "artifact differs from frozen receipt")
        listing = pin(artifact_directory / (name + ".i486.log"))
        require(digest(listing) == row["i486"]["disassembly_sha256"], "frozen CPU listing changed")
    early_default_guard(read(builder_path))
    # Inspected builder top level only defines data/functions. main() is not run
    # during import; the real pe_gate is compiled with optimization enabled.
    sys.path.insert(0, str(ROOT / "tools"))
    module = types.ModuleType("theme_build_gate_control")
    module.__file__ = str(builder_path)
    exec(compile(read(builder_path), str(builder_path), "exec", optimize=2), module.__dict__)
    module.BUILD = artifact_directory
    require(set(module.SOURCES) == set(sources), "builder source closure differs from receipt")
    import pefile
    pin(Path(pefile.__file__).resolve())
    provider = artifact_directory / "M98THEME.DLL"
    require(module.pe_gate(provider, True)["pe98_gate"] == "pass", "positive provider rejected")
    original = read(provider)
    controls = []
    with pefile.PE(data=original) as pe:
        for index in (9, 10, 13, 14):
            entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
            require(entry.VirtualAddress == entry.Size == 0, "positive modern directory must be empty")
            for member, offset in (("VirtualAddress", 0), ("Size", 4)):
                changed = bytearray(original)
                struct.pack_into("<I", changed, entry.get_file_offset() + offset, 1)
                path = directory / ("directory-%d-%s.dll" % (index, member))
                write(path, bytes(changed), directory, samples)
                pin(path)
                try:
                    module.pe_gate(path, True)
                except ValueError as error:
                    require(str(error) == "unsupported directory " + str(index), "rejection had an unrelated cause")
                    controls.append({"directory": index, "member": member, "rejected": True,
                                     "reason": str(error), "copy_sha256": digest(read(path))})
                else:
                    raise ValueError("malformed paired directory accepted")
    require(len(controls) == 8, "eight malformed directory controls required")
    app = read(app_path).decode("utf-8")
    typedef = "typedef HRESULT (WINAPI *draw_text_fn)(HTHEME,HDC,int,int,LPCWSTR,int,DWORD,DWORD,const RECT *);"
    call = "DT_CENTER | DT_VCENTER | DT_SINGLELINE, 0, rect);"
    require(app.count(typedef) == app.count(call) == 1, "review changed GUI ABI anchors before deriving controls")
    bad = app.replace(typedef, typedef.replace("DWORD,DWORD", "DWORD"))
    bad = bad.replace(call, call.replace(", 0, rect", ", rect"))
    require('"DrawThemeText ABI"' in bad, "original SDK ABI assertion missing")
    positive = directory / "appearance-positive.c"
    negative = directory / "appearance-missing-flags2.c"
    write(positive, app.encode(), directory, samples)
    write(negative, bad.encode(), directory, samples)
    pin(positive)
    pin(negative)
    compiler = shutil.which("i686-w64-mingw32-gcc")
    require(compiler is not None, "MinGW GCC is required")
    compiler = Path(compiler).resolve(strict=True)
    pin(compiler, 64 * 1024**2)
    common = [str(compiler), "-std=c11", "-Wall", "-Wextra", "-Werror", "-Isrc", "-Intwddm/include"]
    depfile = directory / "sdk-inputs.d"
    dependency_step = command(common + ["-M", "-MF", str(depfile), "-MT", "abi-positive", str(positive)],
                              "sdk-dependencies", directory, samples, steps)
    require(dependency_step["returncode"] == 0, "official SDK dependency discovery failed")
    dependencies = read(depfile).decode().replace("\\\n", " ")
    require(dependencies.startswith("abi-positive:"), "unexpected dependency target")
    sdk = []
    for spelling in shlex.split(dependencies.split(":", 1)[1]):
        path = Path(spelling)
        path = (ROOT / path if not path.is_absolute() else path).resolve(strict=True)
        sdk.append({"compiler_spelling": spelling, "canonical_path": str(path), "sha256": digest(pin(path))})
    require(any(row["canonical_path"].endswith("/uxtheme.h") for row in sdk), "actual SDK uxtheme.h not consumed")
    good_step = command(common + ["-fsyntax-only", str(positive)], "sdk-positive", directory, samples, steps)
    require(good_step["returncode"] == 0, "positive GUI failed the real SDK syntax/ABI check")
    bad_step = command(common + ["-fsyntax-only", str(negative)], "sdk-negative", directory, samples, steps)
    diagnostic = read(directory / bad_step["stderr"]).decode("utf-8", "replace")
    require(bad_step["returncode"] != 0 and "static assertion failed" in diagnostic and "DrawThemeText ABI" in diagnostic,
            "missing-flags2 GUI was not rejected by the original real SDK ABI assertion")
    historical = ROOT / "build/theme-engine"
    require(historical.is_dir() and any(historical.iterdir()), "no nonempty historical default directory for rejection control")
    old_receipt = historical / "result.json"
    historical_hash = digest(pin(old_receipt))
    before = tree_identity(historical)
    default_step = command([sys.executable, "-O", "-B", str(builder_path)], "default-nonempty", directory, samples, steps)
    require(default_step["returncode"] != 0 and "preserve previous evidence" in
            read(directory / default_step["stderr"]).decode("utf-8", "replace"), "default builder did not reject before writes")
    require(tree_identity(historical) == before and digest(read(old_receipt)) == historical_hash,
            "historical default tree/receipt changed")
    for path, expected in frozen.items():
        require(digest(read(Path(path), 64 * 1024**2)) == expected, "late frozen input drift: " + path)
    outputs = {path.name: digest(read(path)) for path in directory.iterdir() if path.is_file()}
    return {"schema": "shizukuos.theme-build-fault-controls.v1", "passed": True,
            "scope": "host/static regression only", "python_optimized": sys.flags.optimize > 0,
            "builder_pe_gate_compile_optimization": 2, "build_receipt_sha256": digest(build_data),
            "artifact_directory": str(artifact_directory), "frozen_inputs_sha256": frozen,
            "inputs_rehashed_after_controls": True, "malformed_directory_rejections": controls,
            "sdk_inputs": sdk, "sdk_positive_passed": True, "sdk_missing_flags2_rejected": True,
            "historical_default_rejected_before_writes": True,
            "historical_result_sha256_before_after": historical_hash, "output_sha256": outputs, **FALSE_FLAGS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    directory = None
    samples, steps = [], []
    try:
        require(sys.flags.optimize > 0, "run this regression with python3 -O")
        artifact = local_directory(args.artifact_dir, True)
        destination = local_directory(args.output_dir, False)
        require(not destination.is_relative_to(artifact), "new output must be outside frozen artifact directory")
        require(shutil.disk_usage(ROOT).free >= RESERVE + BUDGET, "insufficient reserve+2MiB headroom")
        require(mem_available() >= RAM, "insufficient6GiB available memory")
        destination.mkdir()
        directory = destination
        result = run(artifact, directory, samples, steps)
        guard(directory, samples)
        result.update(commands=steps, resources={"reserve_bytes": RESERVE, "output_budget_bytes": BUDGET,
                      "RAM_bytes": RAM, "sample_interval_seconds": POLL_SECONDS,
                      "sampled_output_high_water_bytes": max(row["own_bytes"] for row in samples),
                      "sampled_group_RSS_high_water_bytes": max(row["owned_group_rss_bytes"] for row in samples),
                      "lowest_sampled_free_bytes": min(row["free_bytes"] for row in samples),
                      "sampling_limit": "Samples are not atomic; transient overshoot between polls is possible. Child FSIZE128KiB; owned group only is terminated and reaped on failure."})
        payload = (json.dumps(result, indent=2) + "\n").encode()
        write(directory / "result.json", payload, directory, samples)
        print(json.dumps({"passed": True, "receipt": str(directory / "result.json"),
                          "sha256": digest(payload), "own_output_bytes": own_bytes(directory), **FALSE_FLAGS}))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        failure = {"schema": "shizukuos.theme-build-fault-controls.v1", "passed": False,
                   "error": str(error), "commands": steps, **FALSE_FLAGS}
        if directory is not None:
            payload = (json.dumps(failure, indent=2) + "\n").encode()
            if own_bytes(directory) + len(payload) <= BUDGET:
                with (directory / "failed-result.json").open("xb") as stream:
                    stream.write(payload)
        print(json.dumps(failure))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
