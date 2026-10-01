#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare an argument-free native startup and wrap the pinned theme consumer.

The only additional guest mutation is insertion of C:\\VXDLAB\\NTTHBOOT.EXE
into one existing, empty [windows] run= value on the new private COW clone.
Shared canonical sources and the frozen observer/probe/provider stay intact.
Preparation never launches a VM. Execution requires a separately selected
exact plan digest; the normal native lane, source, space and COW gates remain.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import stat
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
GUEST_INI = "::/WINDOWS/WIN.INI"
STARTUP_EXE = r"C:\VXDLAB\NTTHBOOT.EXE"
OBSERVER = r"C:\VXDLAB\NTTHRUN.EXE"
NAMES = ("M98THEME.DLL", "NTTHGUI.EXE", "NTTHRUN.EXE", "THNONCE.TXT", "NTTHBOOT.EXE")
GUEST_DIR = "C:" + chr(92) + "VXDLAB" + chr(92)
OUTPUTS = ("THEME.LOG", "THOBS.LOG", "THENTRY.LOG", "THBOOT.LOG")
RESERVE = 20 * 1024**3
QUOTA = 256 * 1024**2
OUTPUT_LIMIT = 16 * 1024**2
MAX_INI = 64 * 1024
SOURCE_FILES = ("tools/theme_startup_trial.py", "tests/test_theme_startup_trial.py",
                "ntwddm/win98/theme_startup/launcher.c", "ntwddm/win98/theme_startup/launcher_mock_test.c",
                "ntwddm/win98/theme_probe/observer_mock.h", "benchmarks/win98se-ko-oem-native-exports-v1.json")


class StartupError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise StartupError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def safe(path, *, exists=True):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts and
            not any(c in str(path) for c in ("\x00", "\r", "\n", ",")), "Unsafe absolute path")
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), "Symlink path component")
    if exists:
        require(path.exists(), "Required path absent")
    return path


def bounded(path, limit):
    path = safe(path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, "Unbounded/nonregular input")
    data = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "Input changed during read")
    return data


def write_new(path, data):
    safe(path, exists=False)
    with Path(path).open("xb") as stream:
        stream.write(data)


def write_json_new(path, value):
    write_new(path, (json.dumps(value, indent=2) + "\n").encode())


def insert_empty_run(data, executable=STARTUP_EXE):
    """Byte-preserving, conservative INI edit; never parse/re-encode ANSI text."""
    require(executable == STARTUP_EXE, "Only the argument-free owned bootstrap is allowed")
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_INI, "INI must be bounded bytes")
    require(not any(c in data for c in (b"\x00", b"\x1a")) and not data.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")),
            "INI encoding/EOF markers are ambiguous")
    require(not re.search(rb"\r(?!\n)", data), "Lone CR in INI")
    section = None
    windows = 0
    insertions = []
    offset = 0
    for line in data.splitlines(keepends=True):
        body = line.rstrip(b"\r\n")
        stripped = body.strip(b" \t")
        if stripped.startswith(b";") or not stripped:
            offset += len(line)
            continue
        if stripped.startswith(b"["):
            match = re.fullmatch(rb"\[([^\[\]]+)\]", stripped)
            require(match is not None, "Ambiguous INI section header")
            section = match[1].strip(b" \t").lower()
            if section == b"windows":
                windows += 1
        elif section == b"windows":
            left, separator, right = body.partition(b"=")
            if left.strip(b" \t").lower() == b"run":
                require(separator and not right.strip(b" \t"), "Existing run= is absent or nonempty")
                insertions.append(offset + len(left) + 1)
        offset += len(line)
    require(windows == 1 and len(insertions) == 1, "Exactly one [windows] and one active empty run= required")
    at = insertions[0]
    result = data[:at] + executable.encode("ascii") + data[at:]
    require(result[:at] == data[:at] and result[at + len(executable):] == data[at:], "Unrelated INI bytes changed")
    return result, {"insertion_offset": at, "inserted_ascii": executable,
                    "before_bytes": len(data), "after_bytes": len(result),
                    "other_bytes_preserved": True}


def command(argv):
    completed = subprocess.run([str(x) for x in argv], capture_output=True, timeout=120)
    if completed.returncode:
        raise StartupError(f"Command failed ({completed.returncode}): {completed.stderr.decode(errors='replace')[:512]}")
    return completed.stdout


def output_command(argv, *, cwd=None, timeout=120, limit=OUTPUT_LIMIT):
    """Bound a host readback child, without altering this process or the VM."""
    def file_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    completed = subprocess.run([str(x) for x in argv], cwd=cwd, capture_output=True,
                               text=True, timeout=timeout, preexec_fn=file_limit)
    require(completed.returncode == 0, "Bounded output copy failed: " + completed.stderr[:512])
    return completed.stdout


def timeout_adaptation(source, *, canonical):
    """Parent explicitly authorized 1200s; alter only the private parser bound."""
    old = (b"not 10 <= args.timeout <= 900" if canonical else
           b"not 1 <= args.timeout <= 900")
    new = old.replace(b"900", b"1200")
    require(source.count(old) == 1, "Private timeout adaptation anchor changed")
    return source.replace(old, new)


def absence(spec, name):
    completed = subprocess.run(["mdir", "-i", spec, "::/VXDLAB/" + name], capture_output=True, timeout=30)
    require(completed.returncode != 0, "Startup output already exists: " + name)
    require(completed.returncode == 1 and b"not found" in completed.stderr.lower(),
            "Output absence could not be proved: " + name)


def sectors(disk, partition):
    with Path(disk).open("rb") as stream:
        mbr = stream.read(512)
        stream.seek(partition["start_lba"] * 512)
        boot = stream.read(512)
    require(len(mbr) == len(boot) == 512, "Incomplete boot sector read")
    value = {"mbr_sha256": hashlib.sha256(mbr).hexdigest(),
             "boot_sector_sha256": hashlib.sha256(boot).hexdigest()}
    require(all(value[k] == partition[k] for k in value), "Legacy boot sectors changed")
    return value


def identity(path):
    info = safe(path).stat()
    require(stat.S_ISREG(info.st_mode), "Disk must be regular")
    return info.st_dev, info.st_ino, info.st_size


def source_guard(plan):
    for item in plan["immutable_sources"]:
        require(sha(safe(item["path"])) == item["sha256"], "Frozen startup source changed: " + item["path"])
    build = json.loads(bounded(plan["theme_build_receipt"], 1024 * 1024))
    require(build["status"] == "PASS", "Frozen theme build not passing")
    for name, digest in build["source_hashes"].items():
        require(sha(safe(Path(build["source_root"]) / name)) == digest, "Frozen observer/theme source changed")


def validate_manifest(plan):
    path = safe(plan["guest_manifest"])
    require(sha(path) == plan["guest_manifest_sha256"], "Guest manifest changed")
    manifest = json.loads(bounded(path, 64 * 1024))
    require(manifest.get("schema") == 1 and manifest.get("kind") == "isolated-guest-file-inputs", "Manifest kind")
    inputs = manifest["inputs"]
    wanted = {GUEST_DIR + name for name in NAMES}
    require(len(inputs) == len(wanted) and {x["guest"] for x in inputs} == wanted, "Startup inputs exceed exact scope")
    require(manifest["outputs"] == [GUEST_DIR + name for name in OUTPUTS] and
            manifest["backups"] == [r"C:\WINDOWS\WIN.INI"], "Exact startup outputs/INI backup required")
    for item in inputs:
        source = safe(item["source"])
        require(source.parent == path.parent and source.name == item["guest"].rsplit("\\", 1)[1] and
                0 < item["bytes"] <= 1024**2 and source.stat().st_size == item["bytes"] and
                sha(source) == item["sha256"], "Startup artifact path/size/hash mismatch")
    nonce = bounded(path.parent / "THNONCE.TXT", 32)
    require(nonce == plan["nonce"].encode() and re.fullmatch(rb"[0-9a-f]{32}", nonce), "Exact challenge mismatch")
    require(plan["observer_command"] == OBSERVER + " --nonce=" + plan["nonce"] and
            plan["startup_executable"] == STARTUP_EXE, "Startup command/path mismatch")
    return manifest


def apply_startup(disk, run_dir, partition, args, plan, cow, ensure_unopened, *, provenance):
    """Called after unchanged canonical input preparation, before QEMU launch."""
    run_dir = safe(run_dir)
    disk = safe(disk)
    require(run_dir == safe(plan["run_directory"]) and disk == run_dir / "windows-uefi.raw", "Owned run/disk path mismatch")
    base = safe(plan["base_disk"])
    before_identity = identity(disk)
    require(before_identity != identity(base) and disk.stat().st_nlink == 1 and
            before_identity[0] == identity(base)[0] and before_identity[2] == identity(base)[2], "Clone has no exclusive private inode")
    require(provenance.get("source_run") == str(base.parent) and
            provenance.get("source_disk_sha256") == plan["base_disk_sha256"] and
            provenance.get("copy_mode", "").startswith("cp --reflink=always"), "Canonical private clone provenance mismatch")
    require(args.reserve_gib == 20 and getattr(args, "replace_installed_gop", False) is False,
            "Startup trial reserve/driver scope changed")
    ensure_unopened(disk)
    require(shutil.disk_usage(run_dir).free >= RESERVE + QUOTA + 2 * MAX_INI, "Startup preparation reserve floor")
    source_guard(plan)
    manifest = validate_manifest(plan)
    require(args.guest_files_manifest_sha == plan["guest_manifest_sha256"] and
            Path(args.guest_files_manifest) == Path(plan["guest_manifest"]), "Canonical manifest differs from startup plan")
    require(partition["start_lba"] == plan["partition"]["start_lba"] and
            all(partition[k] == plan["partition"][k] for k in ("mbr_sha256", "boot_sector_sha256")), "Partition plan differs")
    spec = str(disk) + "@@" + str(partition["start_lba"] * 512)
    for name in OUTPUTS:
        absence(spec, name)
    for item in manifest["inputs"]:
        target = run_dir / ("startup-input-" + Path(item["source"]).name)
        require(not target.exists(), "Startup readback path is stale")
        command(["mcopy", "-i", spec, "::/VXDLAB/" + Path(item["source"]).name, target])
        require(sha(target) == item["sha256"], "Prepared startup artifact differs")
    original = run_dir / "startup-before-WIN.INI"
    replacement = run_dir / "startup-edited-WIN.INI"
    readback = run_dir / "startup-readback-WIN.INI"
    receipt_path = run_dir / "automatic-startup-preparation.json"
    require(not any(x.exists() for x in (original, replacement, readback, receipt_path)), "Startup preparation evidence already exists")
    sectors(disk, partition)
    command(["mcopy", "-i", spec, GUEST_INI, original])
    data = bounded(original, MAX_INI)
    require(sha(original) == plan["source_win_ini_sha256"] and
            sha(run_dir / "before-install-WIN.INI") == sha(original), "Original INI differs from plan/canonical backup")
    patched, edit = insert_empty_run(data)
    require(hashlib.sha256(patched).hexdigest() == plan["edited_win_ini_sha256"], "Planned INI patch differs")
    attributes = command(["mattrib", "-i", spec, GUEST_INI])
    require(re.fullmatch(rb"\s*A\s+::/WINDOWS/WIN.INI\r?\n", attributes) is not None,
            "Only the verified archive-only writable INI attribute is supported")
    baseline = cow.observe_allocations(disk)
    require(baseline.shared_bytes > 0, "Private COW observation has no shared source extents")
    write_new(replacement, patched)
    record = {"schema": 1, "status": "FAIL", "scope": "one empty WIN.INI run value on new private COW clone before launch",
              "native_execution": "NOT-VERIFIED", "nonce": plan["nonce"], "startup_executable": STARTUP_EXE,
              "observer_command": plan["observer_command"], "original": str(original), "original_sha256": sha(original),
              "canonical_backup": str(run_dir / "before-install-WIN.INI"), "edit": edit,
              "modified_guest_files": [r"C:\WINDOWS\WIN.INI"], "output_baseline": "four logs absent before automatic startup",
              "boot_sectors_before": sectors(disk, partition), "write_attempted": False}
    try:
        require(identity(disk) == before_identity, "Owned disk identity changed before write")
        record["write_attempted"] = True
        command(["mcopy", "-o", "-i", spec, replacement, GUEST_INI])
        command(["mcopy", "-i", spec, GUEST_INI, readback])
        require(bounded(readback, MAX_INI) == patched, "INI readback differs from exact planned bytes")
        require(command(["mattrib", "-i", spec, GUEST_INI]) == attributes, "INI attributes changed")
        record["boot_sectors_after"] = sectors(disk, partition)
        after = cow.observe_allocations(disk)
        growth = cow.net_exclusive_growth_bytes(baseline, after)
        free = shutil.disk_usage(run_dir).free
        require(growth <= QUOTA and free >= RESERVE + QUOTA, "INI preparation COW/space bound exceeded")
        require(identity(disk) == before_identity, "Owned disk identity changed after write")
        source_guard(plan)
        record.update(status="PREPARED-NATIVE-UNVERIFIED", readback=str(readback), readback_sha256=sha(readback),
                      attributes_preserved=True, boot_sectors_preserved=True,
                      cow_net_exclusive_growth_bytes=growth, cow_quota_bytes=QUOTA, free_bytes=free,
                      reserve_bytes=RESERVE, cow_baseline=baseline.to_dict(), cow_after=after.to_dict(),
                      allocation_scope="separate stopped prelaunch INI change; native VM COW baseline/guard remain unchanged")
    except BaseException as error:
        record["error"] = str(error)
        if record["write_attempted"] and identity(disk) == before_identity:
            try:
                command(["mcopy", "-o", "-i", spec, original, GUEST_INI])
                rollback = run_dir / "startup-rollback-WIN.INI"
                command(["mcopy", "-i", spec, GUEST_INI, rollback])
                record["INI_rollback_matches_original"] = bounded(rollback, MAX_INI) == data
            except Exception as rollback_error:
                record["rollback_error"] = str(rollback_error)
        write_json_new(receipt_path, record)
        raise
    write_json_new(receipt_path, record)
    return record


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def build_bootstrap(root):
    build = root / "build" / ("theme-startup-bootstrap-" + uuid.uuid4().hex[:12])
    build.mkdir()
    sources = {name: sha(root / name) for name in SOURCE_FILES}
    compilers = {}
    commands = []
    for name in ("clang", "i686-w64-mingw32-gcc"):
        resolved = Path(shutil.which(name)).resolve(strict=True)
        compilers[name] = {"path": str(resolved), "sha256": sha(resolved),
                           "version": command([resolved, "--version"]).decode().splitlines()[0]}

    def build_command(argv):
        result = command(argv)
        commands.append([str(x) for x in argv])
        return result
    host_results = {}
    for name, flags in (("host", []), ("sanitizer", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
        artifact = build / ("bootstrap-" + name)
        build_command(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", *flags,
                 root / "ntwddm/win98/theme_startup/launcher_mock_test.c", "-o", artifact])
        host_results[name] = build_command([artifact]).decode().strip()
        require(re.fullmatch(r"PASS: \d+ startup bootstrap ownership, exact-command, exit and IO assertions", host_results[name]), "Bootstrap test result")
    output = build / "NTTHBOOT.EXE"
    build_command(["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror", "-march=i486",
             "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float", "-fno-builtin", "-fno-stack-protector",
             "-mno-stack-arg-probe", "-nostdlib", "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4",
             "-Wl,--minor-os-version,10", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
             "-Wl,--no-insert-timestamp", "-Wl,--entry,_mainCRTStartup", root / "ntwddm/win98/theme_startup/launcher.c",
             "-lkernel32", "-o", output])
    gate = load_module(root / "ntwddm/win98/theme_probe/build.py", "theme_startup_existing_native_gate").gate(output, False)
    require(set(gate["imports"]) == {"KERNEL32.DLL"}, "Bootstrap imports exceed native Kernel32")
    require(all(sha(root / name) == digest for name, digest in sources.items()), "Bootstrap sources changed during build")
    result = {"schema": 1, "status": "PASS", "source_root": str(root), "source_hashes": sources,
              "artifact": {"path": str(output), "sha256": sha(output), "bytes": output.stat().st_size, "pe98_gate": gate},
              "host_results": host_results, "compilers": compilers, "commands": commands,
              "native_win98": "NOT-TESTED", "automatic_startup": "NOT-VERIFIED",
              "scope": "argument-free bootstrap; unchanged observer/child/theme acceptance remains separate"}
    write_json_new(build / "result.json", result)
    return build, result


def prepare(args):
    root = safe(ROOT)
    old = safe(args.frozen_theme_stage)
    base = safe(args.base_run)
    peer = safe(args.peer_root)
    stage = safe(args.stage_dir, exists=False)
    consumer_dir = safe(args.consumer_dir, exists=False)
    require(base.is_relative_to(peer / "build/shizukudos/csm") and stage.is_relative_to(peer / "build") and
            stage.name.startswith("theme-entry6970-autostart-") and not stage.exists(), "Fresh owned stage/base scope")
    require(consumer_dir.is_relative_to(root / "build") and not consumer_dir.exists(), "Fresh owned consumer required")
    require(re.fullmatch(r"win98-gop-theme-6970-autostart-[A-Za-z0-9_-]+", args.run_name), "Fresh owned run name")
    run_dir = root / "build/theme-native-runs" / args.run_name
    require(not run_dir.exists(), "Owned automatic run already exists")
    consumer_source = root / "tools/theme_native_runner.py"
    consumer = load_module(consumer_source, "theme_startup_consumer_prepare")
    consumer.ensure_unopened(base / "windows-uefi.raw")
    prior = json.loads(bounded(base / "result.json", 8 * 1024**2))
    require(prior.get("status") in ("PASS", "NEEDS-VISUAL-REVIEW") and prior.get("qemu_exit_code") == 0 and
            prior.get("originals_unchanged") is True, "Base lacks intact stopped native receipt")
    require(sha(base / "windows-uefi.raw") == prior["owned_disk_sha256_after_run"], "Base raw differs from its retained receipt")
    original_build = json.loads(bounded(old / "build-result.json", 1024**2))
    require(original_build["status"] == "PASS", "Theme receipt not passing")
    for name, digest in original_build["source_hashes"].items():
        require(sha(Path(original_build["source_root"]) / name) == digest, "Frozen theme source differs")
    old_manifest = json.loads(bounded(old / "guest-files.json", 64 * 1024))
    for name in NAMES[:-1]:
        item = next(x for x in old_manifest["inputs"] if Path(x["source"]).name == name)
        require(sha(old / name) == item["sha256"], "Frozen theme artifact differs")
    build_dir, bootstrap = build_bootstrap(root)
    require(shutil.disk_usage(root / "build").free >= RESERVE + QUOTA, "Preparation reserve floor")
    stage.mkdir(mode=0o700)
    ini = stage / "source-WIN.INI"
    command(["mcopy", "-i", str(base / "windows-uefi.raw") + "@@" + str(prior["partition"]["start_lba"] * 512), GUEST_INI, ini])
    patched, edit = insert_empty_run(bounded(ini, MAX_INI))
    write_new(stage / "expected-WIN.INI", patched)
    nonce = secrets.token_hex(16)
    for name in NAMES[:3]:
        shutil.copyfile(old / name, stage / name)
    write_new(stage / "THNONCE.TXT", nonce.encode())
    shutil.copyfile(build_dir / "NTTHBOOT.EXE", stage / "NTTHBOOT.EXE")
    shutil.copyfile(old / "build-result.json", stage / "build-result.json")
    shutil.copyfile(build_dir / "result.json", stage / "bootstrap-build-result.json")
    write_new(stage / "consumer-source.py", timeout_adaptation(bounded(consumer_source, 2 * 1024**2), canonical=False))
    shutil.copyfile(Path(__file__), stage / "startup-source.py")
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs",
                "inputs": [{"source": str(stage / name), "guest": GUEST_DIR + name,
                            "bytes": (stage / name).stat().st_size, "sha256": sha(stage / name)} for name in NAMES],
                "outputs": [GUEST_DIR + name for name in OUTPUTS], "backups": [r"C:\WINDOWS\WIN.INI"],
                "source_receipts": [{"path": str(stage / name), "sha256": sha(stage / name)}
                                    for name in ("build-result.json", "bootstrap-build-result.json")],
                "nonce": nonce, "command": OBSERVER + " --nonce=" + nonce,
                "guest_execution": "NOT-VERIFIED", "network_required": False}
    write_json_new(stage / "guest-files.json", manifest)
    sources = [{"path": str(root / name), "sha256": sha(root / name)} for name in SOURCE_FILES]
    sources += [{"path": str(stage / name), "sha256": sha(stage / name)} for name in
                ("consumer-source.py", "startup-source.py", "build-result.json", "bootstrap-build-result.json")]
    peer_sources = {name: {"path": str(peer / relative), "sha256": sha(peer / relative)}
                    for name, relative in consumer.SOURCE_FILES.items()}
    sources += list(peer_sources.values())
    sources.append({"path": str(consumer_source), "sha256": sha(consumer_source)})
    functions = consumer.reviewed_functions(bounded(peer / consumer.SOURCE_FILES["adapter"], 2 * 1024**2))
    private_sha = hashlib.sha256(timeout_adaptation(functions["private_reflink_runner"](
        bounded(peer / consumer.SOURCE_FILES["canonical"], 2 * 1024**2)), canonical=True)).hexdigest()
    native = ["--archive", str(args.archive), "--checkpoint-record", str(args.checkpoint_record), "--snapshot", "windows98-clean-installed",
              "--resume-owned-run", str(base), "--csm-dir", str(args.csm_dir), "--run-name", args.run_name,
              "--replace-csmwrap", "--firmware-gop", "--qemu", str(args.qemu), "--firmware-code", str(args.firmware_code),
              "--firmware-vars", str(args.firmware_vars), "--timeout", "1200", "--capture-interval", "5", "--reserve-gib", "20",
              "--manual-gui", "--manual-purpose", "diagnostic", "--smp", "2", "--memory", "128",
              "--guest-files-manifest", str(stage / "guest-files.json"), "--guest-files-manifest-sha", sha(stage / "guest-files.json")]
    consumer_args = ["--peer-root", str(peer), "--consumer-dir", str(consumer_dir)]
    for name in ("canonical", "adapter", "cow"):
        consumer_args += ["--" + name + "-sha256", peer_sources[name]["sha256"]]
    consumer_args += ["--lock-wait-seconds", "1200", "--", *native]
    plan = {"schema": 1, "kind": "native-theme-empty-winini-run-on-owned-cow-v1", "owner_root": str(root),
            "run_directory": str(run_dir), "consumer_directory": str(consumer_dir), "peer_root": str(peer),
            "base_disk": str(base / "windows-uefi.raw"), "base_disk_sha256": prior["owned_disk_sha256_after_run"],
            "base_receipt": str(base / "result.json"), "base_receipt_sha256": sha(base / "result.json"),
            "partition": prior["partition"], "source_win_ini_sha256": sha(ini),
            "edited_win_ini_sha256": hashlib.sha256(patched).hexdigest(), "edit": edit,
            "nonce": nonce, "startup_executable": STARTUP_EXE, "observer_command": OBSERVER + " --nonce=" + nonce,
            "guest_manifest": str(stage / "guest-files.json"), "guest_manifest_sha256": sha(stage / "guest-files.json"),
            "theme_build_receipt": str(stage / "build-result.json"), "immutable_sources": sources,
            "peer_sources": peer_sources, "private_runner_sha256": private_sha,
            "consumer_source": str(stage / "consumer-source.py"), "consumer_arguments": consumer_args,
            "reserve_bytes": RESERVE, "cow_quota_bytes": QUOTA, "runtime_bound_seconds": 1200,
            "output_limit_bytes": OUTPUT_LIMIT,
            "private_timeout_adaptation": "Only the two privately frozen parser upper bounds change from 900 to explicitly authorized 1200 seconds; shared source and all other guards unchanged",
            "vm_started": False, "startup_execution": "NOT-VERIFIED",
            "scope": "additional one-value WIN.INI mutation only on fresh owned COW clone; observer/child/style gates unchanged",
            "startup_semantics_sources": ["https://learn.microsoft.com/en-us/intune/configmgr/develop/reference/core/clients/client-classes/sms_autostartsoftware-client-wmi-class",
                                          "https://www.pcjs.org/documents/books/mspl13/win/w3sdkart/"],
            "startup_semantics_limit": "Only an executable path is inserted. Bootstrap creates the exact argument-bearing observer command; native startup is not yet verified."}
    write_json_new(stage / "startup-plan.json", plan)
    source_guard(plan)
    validate_manifest(plan)
    for path in stage.iterdir():
        path.chmod(0o444)
    stage.chmod(0o555)
    print(json.dumps({"status": "PREPARED-NATIVE-UNVERIFIED", "vm_started": False, "nonce": nonce,
                      "manifest": str(stage / "guest-files.json"), "manifest_sha256": sha(stage / "guest-files.json"),
                      "plan": str(stage / "startup-plan.json"), "plan_sha256": sha(stage / "startup-plan.json"),
                      "bootstrap_receipt": str(build_dir / "result.json")}, indent=2))


def execute_plan(path, selected_sha):
    path = safe(path)
    require(re.fullmatch(r"[0-9a-f]{64}", selected_sha) and sha(path) == selected_sha, "Selected startup plan SHA mismatch")
    plan = json.loads(bounded(path, 128 * 1024))
    require(plan.get("schema") == 1 and plan.get("kind") == "native-theme-empty-winini-run-on-owned-cow-v1" and
            plan.get("reserve_bytes") == RESERVE and plan.get("cow_quota_bytes") == QUOTA and
            plan.get("runtime_bound_seconds") == 1200 and plan.get("output_limit_bytes") == OUTPUT_LIMIT,
            "Startup plan kind/bounds changed")
    root = safe(plan["owner_root"])
    require(safe(plan["run_directory"], exists=False).parent == root / "build/theme-native-runs" and
            re.fullmatch(r"win98-gop-theme-6970-autostart-[A-Za-z0-9_-]+", Path(plan["run_directory"]).name), "Run ownership scope")
    require(not Path(plan["run_directory"]).exists() and not Path(plan["consumer_directory"]).exists(), "Startup consumer/run is stale")
    source_guard(plan)
    validate_manifest(plan)
    require(sha(plan["base_receipt"]) == plan["base_receipt_sha256"], "Base receipt changed")
    consumer = load_module(safe(plan["consumer_source"]), "theme_startup_pinned_consumer")
    consumer.ROOT = root
    consumer.OUTPUT_ROOT = root / "build/theme-native-runs"
    original_configure = consumer.configure_runner
    original_reviewed = consumer.reviewed_functions
    startup_state = {}

    def reviewed(source):
        functions = original_reviewed(source)
        original_reflink = functions["private_reflink_runner"]
        functions["private_reflink_runner"] = lambda value: timeout_adaptation(original_reflink(value), canonical=True)
        return functions

    def configure(private, cow_path, functions, peer):
        runner, cow, state = original_configure(private, cow_path, functions, peer)
        require(sha(private) == plan["private_runner_sha256"], "Private canonical runner changed")
        original_reuse, original_prepare = runner.reuse_prepared, runner.prepare_guest_files
        original_command = runner.command

        def guarded_command(argv, cwd=None, timeout=120):
            target = Path(argv[-1]) if argv else Path("/")
            allowed = {"guest-output-" + name for name in OUTPUTS}
            if argv and str(argv[0]) == "mcopy" and target.parent == Path(plan["run_directory"]) and target.name in allowed:
                return output_command(argv, cwd=cwd, timeout=timeout)
            return original_command(argv, cwd=cwd, timeout=timeout)

        def reuse(*positional, **keywords):
            partition, provenance = original_reuse(*positional, **keywords)
            startup_state["provenance"] = provenance
            return partition, provenance

        def prepare_files(disk, run, partition, args):
            require("child" not in state, "Startup preparation attempted after QEMU launch")
            source_guard(plan)
            value = original_prepare(disk, run, partition, args)
            startup = apply_startup(disk, run, partition, args, plan, cow, consumer.ensure_unopened,
                                    provenance=startup_state.get("provenance", {}))
            value["automatic_startup"] = startup
            value["immutable_sources"].update({item["path"]: item["sha256"] for item in plan["immutable_sources"]})
            value["immutable_sources"][str(path)] = selected_sha
            return value

        runner.reuse_prepared, runner.prepare_guest_files = reuse, prepare_files
        runner.command = guarded_command
        return runner, cow, state

    consumer.configure_runner = configure
    consumer.reviewed_functions = reviewed
    args = plan["consumer_arguments"][:]
    require("--execute" not in args, "Ambiguous execution flag in plan")
    args.insert(args.index("--"), "--execute")
    code = consumer.main(args)
    final = {"schema": 1, "status": "FAIL", "native_acceptance": "NOT-ESTABLISHED",
             "selected_plan": str(path), "selected_plan_sha256": selected_sha,
             "consumer_exit_code": code, "output_limit_bytes": OUTPUT_LIMIT,
             "runtime_bound_seconds": 1200, "reserve_bytes": RESERVE, "cow_quota_bytes": QUOTA}
    try:
        source_guard(plan)
        require(sha(path) == selected_sha, "Startup plan changed during trial")
        record = Path(plan["run_directory"]) / "automatic-startup-preparation.json"
        final.update(source_guards_unchanged=True, automatic_preparation=str(record),
                     automatic_preparation_sha256=sha(record) if record.exists() else None,
                     status="NEEDS-NATIVE-AND-VISUAL-REVIEW" if code == 0 else "FAIL")
    except Exception as error:
        code = 1
        final["error"] = str(error)
    write_json_new(Path(plan["consumer_directory"]) / "startup-trial-result.json", final)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="mode", required=True)
    preparation = sub.add_parser("prepare", allow_abbrev=False)
    for name in ("frozen-theme-stage", "base-run", "peer-root", "stage-dir", "consumer-dir", "archive", "checkpoint-record",
                 "csm-dir", "qemu", "firmware-code", "firmware-vars"):
        preparation.add_argument("--" + name, required=True, type=Path)
    preparation.add_argument("--run-name", required=True)
    execution = sub.add_parser("execute", allow_abbrev=False)
    execution.add_argument("--plan", required=True, type=Path)
    execution.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args)
        return 0
    return execute_plan(args.plan, args.plan_sha256)


if __name__ == "__main__":
    raise SystemExit(main())
