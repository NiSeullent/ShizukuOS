#!/usr/bin/env python3
"""Restore and cross-build pinned, actual WebKit engine sources privately.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
This tool never installs packages, launches a guest, or certifies rendering.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import stat
import subprocess
import time
import types
import urllib.request


HERE = Path(__file__).resolve().parent
GIB = 1024 ** 3


def load_tool_bundle(*, builder=False, driver=False):
    """Load each helper from pinned bytes, rather than an older module cache."""
    path = HERE / "core_tool_snapshot.py"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 ** 2:
            raise ValueError("Snapshot bootstrap must be a bounded regular file")
        data = b""
        while len(data) <= 1024 ** 2:
            block = os.read(descriptor, 65536)
            if not block:
                break
            data += block
        after = os.fstat(descriptor)
        named = path.stat(follow_symlinks=False)
    finally:
        os.close(descriptor)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    if (len(data) != before.st_size or identity(before) != identity(after)
            or identity(named) != identity(after)):
        raise ValueError("Snapshot bootstrap changed while being captured")
    module = types.ModuleType("_engine_snapshot_bootstrap")
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    bundle = module.engine_bundle(builder=builder, driver=driver)
    if bundle.snapshots["core_tool_snapshot"][0] != data:
        raise ValueError("Snapshot bootstrap changed before helper loading")
    return bundle


def validate_build_profile(*args, **kwargs):
    bundle = load_tool_bundle()
    try:
        return bundle.modules["core_jsc_profile_gate"].validate_build_profile(*args, **kwargs)
    finally:
        bundle.verify()


def sha256(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def allocated(directory):
    total = 0
    for path in directory.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                total += path.lstat().st_blocks * 512
        except FileNotFoundError:
            # Ninja/compiler temporary files can disappear during inspection.
            continue
    return total


def check_space(work, budget, check_budget=True):
    if shutil.disk_usage(work).free < 20 * GIB:
        raise RuntimeError("Host free-space floor of 20 GiB reached")
    if check_budget and allocated(work) > budget:
        raise RuntimeError("Private engine build exceeded its declared disk budget")


def signal_owned_build_session(process, sig):
    """Ninja creates separate job groups within the session we created."""
    groups = set()
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[3]) == process.pid:
                groups.add(int(fields[2]))
        except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
            continue
    for group in groups:
        try:
            os.killpg(group, sig)
        except ProcessLookupError:
            pass
    return groups


def terminate_owned_build_session(process):
    signal_owned_build_session(process, signal.SIGTERM)
    # Deliver pending termination to jobs temporarily held for guest prep.
    signal_owned_build_session(process, signal.SIGCONT)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        signal_owned_build_session(process, signal.SIGKILL)
        process.wait()
    finally:
        # A job group can outlive Ninja or ignore graceful termination.
        signal_owned_build_session(process, signal.SIGKILL)


def run(command, work, name, receipt, budget, env=None, timeout=1200, cwd=None):
    log = work / (name + ".log")
    sequence = 0
    while log.exists():
        sequence += 1
        log = work / (name + "-" + str(sequence).zfill(3) + ".log")
    check_space(work, budget)
    started = time.monotonic()
    last_budget_check = started
    with log.open("wb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True, env=env, cwd=cwd)
        try:
            while process.poll() is None:
                time.sleep(5)
                now = time.monotonic()
                inspect_budget = now - last_budget_check >= 60
                check_space(work, budget, check_budget=inspect_budget)
                if inspect_budget:
                    last_budget_check = now
                if time.monotonic() - started > timeout:
                    raise TimeoutError("Bounded build step exceeded timeout: " + name)
        except BaseException as failure:
            terminate_owned_build_session(process)
            output.flush()
            receipt.setdefault("steps", []).append({"name": name, "argv": command,
                "returncode": process.returncode, "interrupted": True,
                "reason": str(failure) or type(failure).__name__, "log": str(log), "log_sha256": sha256(log)})
            write_receipt(work, receipt)
            raise
    receipt.setdefault("steps", []).append({"name": name, "argv": command,
                                            "returncode": process.returncode,
                                            "log": str(log), "log_sha256": sha256(log)})
    write_receipt(work, receipt)
    if process.returncode:
        raise RuntimeError("Actual source build failed; inspect " + str(log))


def write_receipt(work, receipt):
    target = work / "core-build.json"
    with (work / ".core-build-receipt.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        disk = json.loads(target.read_text()) if target.exists() else {}
        merged = {**disk, **receipt}
        steps = disk.get("steps", []).copy()
        for step in receipt.get("steps", []):
            if step not in steps:
                steps.append(step)
        if steps:
            merged["steps"] = steps
        temporary = work / (".core-build-" + str(os.getpid()) + ".json")
        temporary.write_text(json.dumps(merged, indent=2) + "\n")
        temporary.replace(target)
        receipt.update(merged)


def runtime_link_input(directory):
    """Bind the real source-matched GCC TLS port before linking the engine."""
    if directory is None:
        raise ValueError("The Win9x configure phase requires --runtime with a genuine runtime compile receipt")
    receipt_path = directory.resolve() / "runtime-compile.json"
    compiled = json.loads(receipt_path.read_text())
    pin_path = HERE / "core_runtime_pin.json"
    pin = json.loads(pin_path.read_text())
    item = compiled["profiles"]["win9x"]
    obj = Path(item["object"])
    companion = pin["companion"]
    if (compiled["pin_sha256"] != sha256(pin_path)
            or compiled["source_sha256"] != pin["after_sha256"]
            or sha256(Path(compiled["source"])) != pin["after_sha256"]
            or sha256(HERE / pin["source"]) != pin["after_sha256"]
            or sha256(HERE / pin["patch"]) != pin["patch_sha256"]
            or item["returncode"] != 0 or item["api_selection_gate"] != "PASS"
            or item["companion_selection_gate"] != "PASS"
            or sha256(obj) != item["object_sha256"]
            or not compiled["installed_runtime_unchanged"]
            or not compiled["installed_emutls_runtime_unchanged"]
            or compiled["companion_source_sha256"] != companion["after_sha256"]
            or sha256(Path(compiled["companion_source"])) != companion["after_sha256"]
            or sha256(HERE / companion["source"]) != companion["after_sha256"]
            or sha256(HERE / companion["patch"]) != companion["patch_sha256"]
            or sha256(Path(companion["extraction_receipt"]["path"])) != companion["extraction_receipt"]["sha256"]):
        raise ValueError("Genuine private runtime source/object/compile receipt binding failed")
    for dependency in [pin["installed_runtime"], companion["installed_runtime"], *pin["config_headers"]]:
        if sha256(Path(dependency["path"])) != dependency["sha256"]:
            raise ValueError("Installed source-matched compiler/runtime changed before engine link")
    paths = [receipt_path, pin_path, obj, Path(compiled["source"]), Path(compiled["companion_source"]),
             HERE / pin["source"], HERE / pin["patch"], HERE / companion["source"], HERE / companion["patch"],
             Path(companion["extraction_receipt"]["path"]), Path(pin["installed_runtime"]["path"]),
             Path(companion["installed_runtime"]["path"])]
    paths += [Path(row["path"]) for row in pin["config_headers"]]
    for row in pin["license_files"]:
        path = HERE / row["path"]
        if sha256(path) != row["sha256"]:
            raise ValueError("Exact genuine runtime license notice differs from its source pin")
        paths.append(path)
    for row in compiled["compiler_tools"]:
        path = Path(row["path"])
        if sha256(path) != row["sha256"]:
            raise ValueError("Actual runtime-producing compiler tool changed after compilation")
        paths.append(path)
    for row in item["compiler_inputs"] + item["companion_compile"]["compiler_inputs"]:
        path = Path(row["path"])
        if sha256(path) != row["sha256"]:
            raise ValueError("Actual paired-runtime compiler dependency changed after compilation")
        paths.append(path)
    for component in item["components"]:
        path = Path(component["object"])
        if sha256(path) != component["sha256"]:
            raise ValueError("Genuine component object differs from the combined runtime")
        paths.append(path)
    input_pins = [{"path": str(path.resolve()), "sha256": sha256(path)} for path in dict.fromkeys(paths)]
    return obj, {"receipt": str(receipt_path), "receipt_sha256": sha256(receipt_path),
                 "pin_sha256": sha256(pin_path), "object": str(obj),
                 "object_sha256": sha256(obj), "input_pins": input_pins,
                 "native_dll_lifetime": "NOT-VERIFIED"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("source", "icu", "perl", "memory", "statistics", "optional", "allocator", "configure", "runloop", "allocator-object", "wtf", "jsc"))
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--iewebkit-repo", type=Path, required=True)
    parser.add_argument("--cached-webkit", type=Path, required=True)
    parser.add_argument("--budget-mib", type=int, default=2048)
    parser.add_argument("--runtime", type=Path,
                        help="Private genuine GCC TLS runtime build, required for configure")
    args = parser.parse_args()
    work = args.work.resolve()
    repo = args.iewebkit_repo.resolve()
    if work == HERE or HERE in work.parents or work == repo or repo in work.parents:
        parser.error("Engine work must remain outside both source repositories")
    if args.budget_mib < 1024 or args.budget_mib > 4096:
        parser.error("Use a bounded 1024 through 4096 MiB disk budget")
    work.mkdir(parents=True, exist_ok=True)
    budget = args.budget_mib * 1024 ** 2
    pin = json.loads((repo / "porting/webkit-source.json").read_text())
    receipt_path = work / "core-build.json"
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text())
        if receipt["upstream_commit"] != pin["commit"]:
            raise ValueError("Existing build belongs to another source pin")
    else:
        receipt = {"schema": "iewebkit-real-core-build-v1",
                   "upstream_commit": pin["commit"], "archive_sha256": pin["archive_sha256"],
                   "disk_budget_bytes": budget, "host_reserve_bytes": 20 * GIB,
                   "target": "Win9x x86 C_LOOP interpreter bring-up",
                   "engine_provider_built": False, "guest_rendering": "NOT-VERIFIED"}
    source = work / pin["archive_root"]
    build = work / "build-jsc-win9x"
    check_space(work, budget)
    if args.phase == "source":
        cache = args.cached_webkit.resolve()
        if sha256(cache) != pin["archive_sha256"]:
            raise ValueError("Cached upstream archive failed its exact source pin")
        archive = work / cache.name
        if not archive.exists():
            shutil.copyfile(cache, archive)
        elif sha256(archive) != pin["archive_sha256"]:
            raise ValueError("Private archive differs from the verified upstream pin")
        run(["python3", "-B", str(repo / "porting/bootstrap.py"), "--work-dir", str(work)],
            work, "source-restore", receipt, budget)
        profile = json.loads((HERE / "core_profile.json").read_text())
        core_overrides = {item["path"]: item["after_sha256"] for item in profile["files"]}
        core_applied = all(sha256(source / path) == expected
                           for path, expected in core_overrides.items())
        if core_applied:
            canonical = json.loads((repo / "porting/webkit-patches.json").read_text())
            for item in canonical["patches"]:
                expected = core_overrides.get(item["path"], item["after_sha256"])
                if sha256(source / item["path"]) != expected:
                    raise ValueError("Reviewed engine port source differs: " + item["path"])
                if sha256(repo / "porting" / item["patch"]) != item["patch_sha256"]:
                    raise ValueError("Reviewed engine patch changed: " + item["patch"])
            receipt["existing_port_patches_revalidated"] = True
        else:
            run(["python3", "-B", str(repo / "porting/apply-webkit-patches.py"),
                 "--source", str(source)], work, "existing-port-patches", receipt, budget)
        port_pin = json.loads((HERE / "source-pin.json").read_text())
        target = source / port_pin["upstream_file"]
        current = sha256(target)
        if current == port_pin["upstream_sha256"]:
            patch = HERE / port_pin["patch"]
            if sha256(patch) != port_pin["patch_sha256"]:
                raise ValueError("RunLoop source patch differs from its reviewed pin")
            run(["patch", "--batch", "-p1", "-d", str(source), "-i", str(patch)],
                work, "runloop-port-patch", receipt, budget)
        elif current != port_pin["modified_sha256"]:
            raise ValueError("Existing RunLoop source contains unrecognized modifications")
        if sha256(target) != port_pin["modified_sha256"]:
            raise ValueError("Modified RunLoop source failed its exact pin")
        header = target.with_name("RunLoopWin9x.h")
        if sha256(header) != sha256(HERE / port_pin["new_header"]):
            raise ValueError("Actual engine backend header differs from the native fixture")
        receipt["runloop_source_sha256"] = sha256(target)
        receipt["runloop_backend_sha256"] = sha256(header)
        receipt["source_restored"] = True
    elif args.phase == "icu":
        run(["sh", str(repo / "porting/build-icu-x86.sh"), str(work / "icu-work"), "1", "win9x"],
            work, "actual-icu-build", receipt, budget, timeout=3600)
    elif args.phase == "perl":
        perl_work = work / "perl-work"
        perl_work.mkdir(exist_ok=True)
        package = perl_work / "perl-bignum-0.67-512.el10.noarch.rpm"
        expected = "93cc32a35c0b74c751bd1351dc9547f34cb5ac6d6b0fe78631b33bb29192a0e1"
        url = "https://repo.almalinux.org/almalinux/10/AppStream/x86_64/os/Packages/" + package.name
        if not package.exists():
            with urllib.request.urlopen(url, timeout=30) as response:
                data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
                raise ValueError("Pinned host-only Perl RPM failed its bounded source check")
            with package.open("xb") as target:
                target.write(data)
        if sha256(package) != expected:
            raise ValueError("Existing private host-only Perl RPM differs from its source pin")
        run(["sh", str(repo / "porting/bootstrap-perl-bignum.sh"), str(perl_work)],
            work, "private-host-perl", receipt, budget)
        receipt["host_perl_package_sha256"] = expected
        receipt["host_perl_source_url"] = url
    elif args.phase == "memory":
        memory_pin = json.loads((HERE / "core_memory_pin.json").read_text())
        if memory_pin["upstream_commit"] != pin["commit"]:
            raise ValueError("Memory portability patch belongs to another engine source pin")
        patch = HERE / memory_pin["patch"]
        if sha256(patch) != memory_pin["patch_sha256"]:
            raise ValueError("Memory portability patch differs from its reviewed source pin")
        states = [sha256(source / item["path"]) for item in memory_pin["files"]]
        before = [item["before_sha256"] for item in memory_pin["files"]]
        after = [item["after_sha256"] for item in memory_pin["files"]]
        if states == before:
            for item in memory_pin["new_files"]:
                if (source / item["path"]).exists():
                    raise ValueError("Preserve unrecognized existing memory backend file")
            run(["patch", "--batch", "-p1", "-d", str(source), "-i", str(patch)],
                work, "actual-memory-port-patch", receipt, budget)
        elif states != after:
            raise ValueError("Memory portability sources contain unrecognized modifications")
        for item in memory_pin["files"]:
            if sha256(source / item["path"]) != item["after_sha256"]:
                raise ValueError("Actual memory portability source failed its final source pin")
        for item in memory_pin["new_files"]:
            if sha256(source / item["path"]) != item["sha256"] or sha256(HERE / item["source"]) != item["sha256"]:
                raise ValueError("Actual engine memory backend differs from the native probe helper")
        receipt["memory_port_patch_sha256"] = memory_pin["patch_sha256"]
        receipt["memory_port_policy"] = memory_pin["policy"]
    elif args.phase == "statistics":
        statistics_pin = json.loads((HERE / "core_statistics_pin.json").read_text())
        patch = HERE / statistics_pin["patch"]
        if statistics_pin["upstream_commit"] != pin["commit"] or sha256(patch) != statistics_pin["patch_sha256"]:
            raise ValueError("Statistics port differs from its exact source/patch pin")
        header = statistics_pin["requires_header"]
        if sha256(source / header["path"]) != header["sha256"]:
            raise ValueError("Apply the shared Win9x memory port before statistics")
        item = statistics_pin["files"][0]
        target = source / item["path"]
        current = sha256(target)
        if current == item["before_sha256"]:
            run(["patch", "--batch", "-p1", "-d", str(source), "-i", str(patch)],
                work, "actual-statistics-port-patch", receipt, budget)
        elif current != item["after_sha256"]:
            raise ValueError("Preserve unrecognized actual statistics source changes")
        if sha256(target) != item["after_sha256"]:
            raise ValueError("Actual statistics port failed its final source pin")
        receipt["statistics_port_patch_sha256"] = statistics_pin["patch_sha256"]
        receipt["statistics_measurement"] = statistics_pin["measurement"]
    elif args.phase == "optional":
        optional_pin = json.loads((HERE / "core_optional_api_pin.json").read_text())
        patch = HERE / optional_pin["patch"]
        if optional_pin["upstream_commit"] != pin["commit"] or sha256(patch) != optional_pin["patch_sha256"]:
            raise ValueError("Optional API source port failed its exact prerequisite pins")
        states = [sha256(source / item["path"]) for item in optional_pin["files"]]
        before = [item["before_sha256"] for item in optional_pin["files"]]
        after = [item["after_sha256"] for item in optional_pin["files"]]
        if states == before:
            run(["patch", "--batch", "-p1", "-d", str(source), "-i", str(patch)],
                work, "actual-optional-api-port-patch", receipt, budget)
        elif states != after:
            raise ValueError("Preserve unrecognized actual optional API source changes")
        if [sha256(source / item["path"]) for item in optional_pin["files"]] != after:
            raise ValueError("Optional API source port failed its final source pins")
        receipt["optional_api_port_patch_sha256"] = optional_pin["patch_sha256"]
        receipt["optional_api_capability_limits"] = optional_pin["capability_limits"]
    elif args.phase == "allocator":
        allocator_pin = json.loads((HERE / "core_allocator_pin.json").read_text())
        patch = HERE / allocator_pin["patch"]
        if allocator_pin["upstream_commit"] != pin["commit"] or sha256(patch) != allocator_pin["patch_sha256"]:
            raise ValueError("Real allocator/CryptoAPI source port failed its exact prerequisite pin")
        states = [sha256(source / item["path"]) for item in allocator_pin["files"]]
        before = [item["before_sha256"] for item in allocator_pin["files"]]
        after = [item["after_sha256"] for item in allocator_pin["files"]]
        if states == before:
            run(["patch", "--batch", "-p1", "-d", str(source), "-i", str(patch)],
                work, "actual-allocator-tls-crypto-patch", receipt, budget)
        elif states != after:
            raise ValueError("Preserve unrecognized allocator/CryptoAPI source modifications")
        if [sha256(source / item["path"]) for item in allocator_pin["files"]] != after:
            raise ValueError("Actual allocator/CryptoAPI source failed its final source pin")
        receipt["allocator_tls_crypto_port_patch_sha256"] = allocator_pin["patch_sha256"]
    elif args.phase == "configure":
        profile = json.loads((HERE / "core_profile.json").read_text())
        states = [sha256(source / item["path"]) for item in profile["files"]]
        original_states = [item["before_sha256"] for item in profile["files"]]
        final_states = [item["after_sha256"] for item in profile["files"]]
        if states == original_states:
            patch = HERE / profile["patch"]
            if sha256(patch) != profile["patch_sha256"]:
                raise ValueError("Actual Windows-loop profile patch has changed")
            run(["patch", "--batch", "-p1", "-d", str(source), "-i", str(patch)],
                work, "windows-loop-profile-patch", receipt, budget)
        elif states != final_states:
            raise ValueError("Actual engine configuration source contains unexpected edits")
        if [sha256(source / item["path"]) for item in profile["files"]] != final_states:
            raise ValueError("Windows-loop profile failed its final source pins")
        icu = work / "icu-work/prefix-x86-win9x"
        for archive in ("libsicuuc.a", "libsicuin.a", "libsicudt.a"):
            if not (icu / "lib" / archive).is_file():
                raise ValueError("Complete the actual x86 ICU dependency build first")
        runtime_object, runtime_receipt = runtime_link_input(args.runtime)
        hook_pin_path = HERE / "core_runtime_link_pin.json"
        hook_pin = json.loads(hook_pin_path.read_text())
        hook = HERE / hook_pin["source"]
        if sha256(hook) != hook_pin["sha256"]:
            raise ValueError("Actual target dependency/profile hook changed after its source pin")
        # Canonical configure-jsc-me.sh rechecks its original source hashes;
        # this independent profile carries two reviewed additional source edits.
        command = ["cmake", "-S", str(source), "-B", str(build), "-G", "Ninja",
                   "-DCMAKE_TOOLCHAIN_FILE=" + str(repo / "porting/mingw-me-toolchain.cmake"),
                   "-DPORT=JSCOnly", "-DIEWEBKIT_WIN9X=ON", "-DEVENT_LOOP_TYPE=Windows",
                   "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                   "-DCMAKE_PROJECT_INCLUDE=" + str(hook),
                   "-DIEWEBKIT_WIN9X_RUNTIME_OBJECT=" + str(runtime_object),
                   "-DCMAKE_DISABLE_PRECOMPILE_HEADERS=ON",
                   "-DCMAKE_BUILD_TYPE=MinSizeRel", "-DENABLE_JIT=OFF", "-DENABLE_C_LOOP=ON",
                   "-DENABLE_WEBASSEMBLY=OFF", "-DENABLE_REMOTE_INSPECTOR=OFF",
                   "-DENABLE_STATIC_JSC=ON", "-DENABLE_API_TESTS=OFF", "-DUSE_SYSTEM_MALLOC=OFF",
                   "-DUSE_MIMALLOC=ON", "-DICU_INCLUDE_DIR=" + str(icu / "include"),
                   "-DICU_UC_LIBRARY_RELEASE=" + str(icu / "lib/libsicuuc.a"),
                   "-DICU_I18N_LIBRARY_RELEASE=" + str(icu / "lib/libsicuin.a"),
                   "-DICU_DATA_LIBRARY_RELEASE=" + str(icu / "lib/libsicudt.a"),
                   "-DCMAKE_CXX_FLAGS=-g0 -ffunction-sections -fdata-sections "
                   "-DWINVER=0x0410 -D_WIN32_WINDOWS=0x0410 -D_WIN32_WINNT=0x0400 -DU_STATIC_IMPLEMENTATION",
                   "-DCMAKE_EXE_LINKER_FLAGS=" + shlex.quote(str(runtime_object))
                   + " -static -static-libgcc -static-libstdc++ -Wl,--gc-sections"
                   + " -Wl,--major-os-version,4,--minor-os-version,0,--major-subsystem-version,4,--minor-subsystem-version,0"]
        run(command, work, "actual-jsc-configure", receipt, budget)
        config = (build / "cmakeconfig.h").read_text()
        if "#define IEWEBKIT_WIN9X 1" not in config or "#define USE_WINDOWS_EVENT_LOOP 1" not in config:
            raise ValueError("Actual generated target configuration omitted the Win9x Windows loop")
        if "#define USE_GENERIC_EVENT_LOOP 1" in config:
            raise ValueError("Actual target configuration combines incompatible RunLoop layouts")
        receipt["configuration_sha256"] = sha256(build / "cmakeconfig.h")
        receipt["event_loop"] = "Windows"
        receipt["windows_loop_profile_patch_sha256"] = profile["patch_sha256"]
        receipt["runtime_link_input"] = runtime_receipt
        graph = (build / "build.ninja").read_text()
        jsc_rule = next(line for line in graph.splitlines() if line.startswith("build bin/jsc.exe: "))
        allocator_entry = next(item for item in json.loads((build / "compile_commands.json").read_text())
                               if item["file"].endswith("/mimalloc/src/static.c"))
        if str(runtime_object) not in jsc_rule.split(" || ", 1)[0] or "-DIEWEBKIT_WIN9X=1" not in shlex.split(allocator_entry["command"]):
            raise ValueError("Configured genuine runtime dependency or standalone allocator Win9x definition is absent")
        receipt["target_link_profile_hook"] = {"source": str(hook), "sha256": sha256(hook),
                    "pin_sha256": sha256(hook_pin_path), "runtime_incremental_link_input": True,
                    "allocator_explicit_win9x_definition": True}
        # Bind the effective generated target, including the actual link flags.
        # A dependency alone does not prove the private runtime reaches the link.
        receipt["jsc_build_profile"] = validate_build_profile(work, source, repo, runtime_object)
        # Reconfiguration never retroactively certifies an older executable.
        receipt["jsc"] = None
    else:
        if args.phase == "runloop":
            target = "Source/WTF/wtf/CMakeFiles/WTF.dir/win/RunLoopWin.cpp.obj"
            artifact = build / target
        elif args.phase == "allocator-object":
            target = "Source/bmalloc/mimalloc/mimalloc/CMakeFiles/mimalloc-obj.dir/src/static.c.obj"
            artifact = build / target
        else:
            target = "WTF" if args.phase == "wtf" else "jsc"
            artifact = build / ("lib/libWTF.a" if target == "WTF" else "bin/jsc.exe")
        env = os.environ.copy()
        vendor = work / "perl-work/unpacked/usr/share/perl5/vendor_perl"
        if args.phase == "jsc":
            linked_runtime = receipt.get("runtime_link_input")
            if not linked_runtime:
                raise ValueError("Configure the real source-matched Win9x runtime before linking JSC")
            runtime_object, current_runtime = runtime_link_input(Path(linked_runtime["receipt"]).parent)
            if current_runtime != linked_runtime:
                raise ValueError("Configured private runtime changed before actual JSC compilation/link")
            configured_profile = receipt.get("jsc_build_profile")
            if not configured_profile or not configured_profile.get("profile_gate_passed"):
                raise ValueError("Configure and bind the actual generated JSC profile before building")
            validate_build_profile(work, source, repo, runtime_object, expected=configured_profile)
            module = vendor / "bigint.pm"
            if not module.is_file() or sha256(module) != "6d96c7213f87203014e8e6ec43eb6c8069707f4399ccb2ceb59dd0a30aa52772":
                raise ValueError("Run the pinned host-only perl phase before JSC generation")
            env["PERL5LIB"] = str(vendor) + (os.pathsep + env["PERL5LIB"] if env.get("PERL5LIB") else "")
        run(["ninja", "-C", str(build), "-j1", target],
            work, "actual-" + args.phase + "-build", receipt, budget, env=env, timeout=3600)
        if not artifact.is_file():
            raise ValueError("Successful target did not produce the expected engine artifact")
        if args.phase == "jsc":
            _, final_runtime = runtime_link_input(Path(linked_runtime["receipt"]).parent)
            if final_runtime != linked_runtime:
                raise ValueError("Preserve linked JSC: private runtime changed during build")
            validate_build_profile(work, source, repo, runtime_object, expected=configured_profile)
        receipt[args.phase] = {"path": str(artifact), "sha256": sha256(artifact),
                           "bytes": artifact.stat().st_size}
        if args.phase == "jsc":
            receipt["jsc"]["build_profile_sha256"] = hashlib.sha256(json.dumps(
                configured_profile, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
            receipt["jsc"]["runtime_receipt_sha256"] = linked_runtime["receipt_sha256"]
    receipt["allocated_bytes"] = allocated(work)
    receipt["host_free_bytes"] = shutil.disk_usage(work).free
    write_receipt(work, receipt)
    print(json.dumps({"phase": args.phase, "allocated_bytes": receipt["allocated_bytes"],
                      "host_free_bytes": receipt["host_free_bytes"], "work": str(work)}))


if __name__ == "__main__":
    main()
