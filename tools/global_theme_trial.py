#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Source-bound OEM Win98 palette control: one COW, two cold hardware epochs.

Run with python -B. Prepare never boots. Execute requires an exact selected
plan and real passing selector/observer PE build receipts. No old startup plan,
base writes, saved CPU/RAM state, disk-copy fallback, network or VNC is used.
Verify is a separate read-only evidence gate. Observer self logs cannot prove
their own exit, and sampled resources are not an atomic filesystem quota.
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
import selectors
import shutil
import stat
import struct
import subprocess
import sys
import time
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
PEER = Path("/root/Win98-Modern-boot")
KIND = "native-win98-global-selector-two-cold-boots-v1"
BASE = PEER / "build/shizukudos/csm/run-win98-gop-theme-5abe-native-v1/windows-uefi.raw"
BASE_SHA = "828080b6bc04dfdeafaa8cded0e3e5c7c6698bb38b6c21d094b5cf38ed1e5b05"
BASE_RECEIPT_SHA = "28328280a25dad4996616bf105a63e00ed1f6e16c70f4a64142a62a2d095761b"
RESERVE = 20 * 1024**3
QUOTA = 256 * 1024**2
HOST_LIMIT = 16 * 1024**2
STARTUP = r"C:\VXDLAB\SHZOBS.EXE"
RUN_COMMAND = b'"C:\\VXDLAB\\SHZTHEME.EXE" /restore\0'
SELECTOR_COMMAND = '"C:\\VXDLAB\\SHZTHEME.EXE"'
ROLES = ("stage", "consumer", "run", "bootstrap")
INPUTS = ("SHZTHEME.EXE", "SHZOBS.EXE", "SHZCASE.TXT")
LOGS = ("SHZGLOB1.LOG", "SHZGLOB2.LOG")
SNAPSHOT_FIELDS = ("PROFILE_TYPE", "PROFILE_BYTES", "PROFILE_RAW", "RUN_TYPE", "RUN_BYTES", "RUN_RAW")
# Independently specified legacy COLORREF contract; no product/provider imports.
SHIZOS = (0xcfcfcf, 0x452e13, 0xd77800, 0x888078, 0xf0f0f0,
          0xffffff, 0x605040, 0, 0, 0xffffff, 0xa0a0a0, 0xc0c0c0,
          0xa0a0a0, 0xd77800, 0xffffff, 0xf0f0f0, 0xa0a0a0,
          0x808080, 0, 0xf0f0f0, 0xffffff, 0x606060, 0xe0e0e0, 0, 0xe1ffff)
OWN_SOURCES = ("tools/global_theme_trial.py", "tests/test_global_theme_trial.py",
               "tools/theme_native_runner.py", "tools/theme_startup_trial.py")
PEER_SOURCES = {"canonical": "shizukudos/csm/test_win98_uefi.py",
                "adapter": "shizukudos/iosys_uefi/boot.py",
                "cow": "shizukudos/iosys_uefi/cow_accounting.py",
                "qemu_helper": "shizukudos/tools/qemu.py",
                "shzlib": "shizukudos/tools/shzlib.py"}


class TrialError(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise TrialError(message)


def safe_path(value, *, exists=True):
    path = Path(value)
    need(path.is_absolute() and ".." not in path.parts and
         not any(c in str(path) for c in ("\0", "\r", "\n", ",")), "Unsafe absolute path")
    for component in (path, *path.parents):
        try:
            need(not stat.S_ISLNK(component.lstat().st_mode), "Symlink path component")
        except FileNotFoundError:
            pass
    if exists:
        need(path.exists(), "Required path is absent")
    return path


def metadata(path):
    value = safe_path(path).stat()
    need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1, "Unaliased regular input required")
    return {"device": value.st_dev, "inode": value.st_ino, "bytes": value.st_size,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns}


def sha(path):
    path = safe_path(path)
    before = metadata(path)
    need(0 < before["bytes"] <= 8 * 1024**3, "Input exceeds hash bound")
    value = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev, opened.st_ino, opened.st_size) ==
             (before["device"], before["inode"], before["bytes"]), "Input inode changed")
        while block := stream.read(1024**2):
            value.update(block)
    need(metadata(path) == before, "Input changed while hashing")
    return value.hexdigest()


def bounded(path, limit):
    path = safe_path(path)
    before = metadata(path)
    need(0 < before["bytes"] <= limit, "Input length exceeds bound")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        actual = os.fstat(stream.fileno())
        need((actual.st_dev, actual.st_ino) == (before["device"], before["inode"]), "Read inode changed")
        data = stream.read(limit + 1)
    need(metadata(path) == before and len(data) == before["bytes"], "Readback changed or exceeds bound")
    return data


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def read_json(path, limit=1024**2):
    return json.loads(bounded(path, limit), object_pairs_hook=pairs)


def new_file(path, data):
    path = safe_path(path, exists=False)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def new_json(path, value):
    new_file(path, (json.dumps(value, indent=2) + "\n").encode())


def case_bytes(nonce, phase):
    need(isinstance(nonce, str) and re.fullmatch("[0-9a-f]{32}", nonce) and type(phase) is int
         and phase in (1, 2), "Case nonce/phase mismatch")
    return ("SHZGCASE1\r\nnonce=" + nonce + "\r\nphase=" + str(phase) + "\r\n").encode("ascii")


def patch_empty_run(data):
    """Insert only fixed ASCII in one empty run; preserve every other ANSI byte."""
    need(isinstance(data, bytes) and 0 < len(data) <= 65536, "Bounded byte INI required")
    need(b"\0" not in data and b"\x1a" not in data and not data.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf"))
         and not re.search(rb"\r(?!\n)", data), "Ambiguous INI encoding or CR")
    offset, windows, locations, section = 0, 0, [], None
    for line in data.splitlines(keepends=True):
        body = line.rstrip(b"\r\n")
        stripped = body.strip(b" \t")
        if stripped and not stripped.startswith(b";"):
            if stripped.startswith(b"["):
                match = re.fullmatch(rb"\[([^\[\]]+)\]", stripped)
                need(match is not None, "Ambiguous section header")
                section = match[1].strip(b" \t").lower()
                windows += section == b"windows"
            elif section == b"windows":
                left, sep, right = body.partition(b"=")
                if left.strip(b" \t").lower() == b"run":
                    need(sep and not right.strip(b" \t"), "Existing run is nonempty")
                    locations.append(offset + len(left) + 1)
        offset += len(line)
    need(windows == 1 and len(locations) == 1, "Exactly one empty Windows run required")
    at = locations[0]
    inserted = STARTUP.encode("ascii")
    return data[:at] + inserted + data[at:], {"insertion_offset": at, "inserted_ascii": STARTUP,
                                          "other_bytes_preserved": True}


def cumulative_growth(baseline, current):
    """One original baseline across injection and both epochs; not write volume."""
    for key in ("device", "inode", "file_bytes"):
        need(type(baseline.get(key)) is int and baseline[key] == current.get(key), "COW baseline inode changed")
    for item in (baseline, current):
        need(type(item.get("exclusive_bytes")) is int and item["exclusive_bytes"] >= 0, "COW observation malformed")
    growth = current["exclusive_bytes"] - baseline["exclusive_bytes"]
    need(growth <= QUOTA, "Original cumulative COW budget exceeded")
    return growth


def validate_plan_shape(plan, owner_root=ROOT):
    need(plan.get("schema") == 1 and plan.get("kind") == KIND, "Old or unsupported plan kind")
    owner = safe_path(plan.get("owner_root", ""))
    need(owner == safe_path(owner_root), "Plan belongs to another source checkout")
    need(plan.get("cow_quota_bytes") == QUOTA and plan.get("runtime_bound_seconds") == 900
         and plan.get("two_cold_epochs") == 2 and plan.get("startup_executable") == STARTUP
         and plan.get("machine_profile") == "q35-kvm-qemu64-2cpu-128m-gop-offline"
         and plan.get("scope") == "OEM_WIN98_CONTROL_NOT_SHIZUKUDOS_REPLACEMENT", "Plan bounds/profile changed")
    case_bytes(plan.get("nonce"), 1)
    roots = plan.get("roots", {})
    need(set(roots) == set(ROLES), "Exactly four named output roots required")
    paths = [safe_path(roots[role], exists=False) for role in ROLES]
    need(len(set(paths)) == 4 and all(p.parent == owner / "build" and
         re.fullmatch("global-theme-6970-" + role + "-[a-z0-9]+", p.name)
         for role, p in zip(ROLES, paths)), "Output ownership/prefix differs")
    expected = {"schema": 1, "roots": [str(p) for p in paths],
                "excluded_private_cow": str(paths[2] / "windows-uefi.raw"),
                "limit_bytes": HOST_LIMIT, "reserve_bytes": RESERVE}
    need(plan.get("host_output_budget") == expected, "Exact host-output exclusion/budget required")
    need(all(len(os.fsencode(paths[2] / ("e" + str(i)) / "q.sock")) < 108 for i in (1, 2)), "QMP socket exceeds Unix bound")
    return paths


def require_fresh_roots(plan, owner_root=ROOT):
    for path in validate_plan_shape(plan, owner_root):
        need(not path.exists(), "Output root is stale")


def colors_from_hex(value):
    need(re.fullmatch("[0-9a-f]{200}", value) is not None, "Exactly25 lowercase colors required")
    colors = struct.unpack("<25I", bytes.fromhex(value))
    need(all(x <= 0xffffff for x in colors), "Color high byte differs")
    return colors


def profile_from_hex(value, baseline, style):
    need(re.fullmatch("[0-9a-f]{448}", value) is not None, "224-byte profile required")
    data = bytes.fromhex(value)
    need(data[:8] == b"SHZCLR1\0" and struct.unpack_from("<4I", data, 8) == (1, 224, style, 25)
         and struct.unpack_from("<25I", data, 24) == baseline
         and struct.unpack_from("<25I", data, 124) == (SHIZOS if style else baseline), "Profile contract differs")
    return data


def parse_observer_log(data, nonce, phase, first=None):
    """Strict ordered protocol, including all snapshot groups; self exit stays unknown."""
    case_bytes(nonce, phase)
    need(isinstance(data, bytes) and 0 < len(data) <= 32768 and data.endswith(b"\r\n"), "Incomplete/bounded observer log")
    need(not re.search(rb"[^\x20-\x7e\r\n]", data) and not re.search(rb"(?<!\r)\n|\r(?!\n)", data), "Observer ASCII/CRLF malformed")
    lines = data[:-2].decode("ascii").split("\r\n")
    rows = []
    for line in lines:
        key, sep, value = line.partition("=")
        need(sep and re.fullmatch("[A-Z0-9_]+", key) and key not in ("RESULT", "FAIL_STAGE", "FAIL_ERROR", "CHILD_EXTERNAL_EXIT"), "Observer failure/invalid record")
        rows.append((key, value))
    index = 0

    def take(key, wanted=None):
        nonlocal index
        need(index < len(rows) and rows[index][0] == key, "Missing, duplicate or out-of-order " + key)
        value = rows[index][1]; index += 1
        need(wanted is None or value == wanted, "Incorrect observer " + key)
        return value

    def number(key, wanted=None):
        text = take(key)
        need(re.fullmatch("0|[1-9][0-9]{0,9}", text) is not None, "Invalid observer integer")
        value = int(text)
        need(value <= 0xffffffff and (wanted is None or value == wanted), "Incorrect observer integer")
        return value

    take("HEADER", "SHZGLOB%d_V1" % phase); take("NONCE", nonce); number("PHASE", phase)
    take("OBSERVER_ROLE", "INDEPENDENT_NATIVE_READ_ONLY_THEME_OBSERVER")
    take("PROCESS_SELF_LOG_IS_NOT", "EXTERNAL_EXIT_OR_BOOT_OR_SOURCE_PROOF")
    number("OS_PLATFORM", 1); number("OS_MAJOR", 4); number("OS_MINOR", 10)
    raw_build = number("OS_BUILD_RAW"); number("OS_BUILD_LOW_WORD", raw_build & 65535)
    if phase == 1:
        number("INITIAL_PROFILE_PRESENT", 0); number("INITIAL_RUN_PRESENT", 0)
    else:
        need(first is not None and first.get("phase") == 1 and first.get("nonce") == nonce, "Second boot lacks bound phase1")
        take("RESTORE_PROCESS_EXTERNAL_EXIT", "NOT_OBSERVED_NO_PROCESS_HANDLE")
        take("COLD_BOOT_IDENTITY", "REQUIRES_EXTERNAL_SAME_COW_SECOND_EPOCH_RECEIPT")
    baseline = colors_from_hex(take("BASELINE"))
    need(baseline != SHIZOS and (first is None or baseline == tuple(first["baseline"])), "Baseline changed or already ShizukuOS")
    stages, observations = [], []

    def snapshot(style=None):
        if style is None:
            for key, value in zip(SNAPSHOT_FIELDS, ("0", "0", "", "0", "0", "")):
                take(key, value)
            return None
        number("PROFILE_TYPE", 3); number("PROFILE_BYTES", 224)
        profile = profile_from_hex(take("PROFILE_RAW"), baseline, style)
        number("RUN_TYPE", 1); number("RUN_BYTES", len(RUN_COMMAND))
        take("RUN_RAW", RUN_COMMAND.hex())
        return profile

    def witness(name, style, transition):
        take("STAGE", name)
        n = number("WITNESS_COLORCHANGE_COUNT"); p = number("WITNESS_PAINT_COUNT")
        pixel = number("WITNESS_NATIVE_PIXEL")
        actual = colors_from_hex(take("ACTUAL_COLORS"))
        need(actual == (SHIZOS if style else baseline) and pixel == actual[15] and p > 0, "Palette/native witness pixel differs")
        if transition:
            need(observations and n > observations[-1]["notifications"] and p > observations[-1]["paints"], "Cross-process notification/repaint missing")
        stages.append(name); observations.append({"stage": name, "notifications": n, "paints": p, "pixel": pixel})

    def child():
        take("CHILD_COMMAND", SELECTOR_COMMAND)
        pid = number("CHILD_PID"); need(pid > 0, "Owned child PID missing")
        take("CHILD_NATIVE_GUI_CONTROLS", "CLASS_PID_101_102_ENABLED")
        return pid

    if phase == 1:
        snapshot(); witness("INITIAL_BASELINE", 0, False); pid = child()
        saved = None
        for name, style in (("SHIZOS_FIRST", 1), ("CLASSIC_ORIGINAL_BASELINE", 0), ("SHIZOS_SAVED", 1)):
            take("AWAITING_TRANSITION", name); witness(name, style, True); saved = snapshot(style)
        take("SEQUENCE", "BASELINE_SHIZOS_CLASSIC_SHIZOS")
    else:
        witness("COLD_BOOT_AUTOMATIC_SHIZOS_BEFORE_CHILD", 1, False)
        saved = snapshot(1)
        need(saved.hex() == first["final_profile"], "Saved profile changed across cold boots")
        pid = child(); take("AWAITING_TRANSITION", "COLD_BOOT_CLASSIC_RETURN")
        witness("COLD_BOOT_CLASSIC_RETURN", 0, True); snapshot(0)
        take("SEQUENCE", "AUTOMATIC_SHIZOS_BEFORE_CHILD_CLASSIC_RETURN")
    take("AWAITING", "ACTUAL_CHILD_GUI_CLOSE"); number("CHILD_EXIT_OBSERVED", 1); number("CHILD_EXIT_CODE", 0)
    take("FINAL_READBACK", "AFTER_NORMAL_CHILD_EXIT")
    final_style = 1 if phase == 1 else 0
    number("FINAL_STYLE", final_style)
    need(colors_from_hex(take("FINAL_COLORS")) == (SHIZOS if final_style else baseline), "Post-exit palette changed")
    number("FINAL_PROFILE_TYPE", 3); number("FINAL_PROFILE_BYTES", 224)
    final_profile = profile_from_hex(take("FINAL_PROFILE"), baseline, final_style)
    if phase == 1:
        need(final_profile == saved, "Post-exit saved profile changed")
    number("FINAL_RUN_TYPE", 1); number("FINAL_RUN_BYTES", len(RUN_COMMAND))
    take("FINAL_RUN_RAW", RUN_COMMAND.hex())
    number("EVIDENCE_COMPLETE_REQUIRES_EXTERNAL_EXIT", 1); number("OBSERVER_REQUESTED_EXIT", 0)
    need(index == len(rows), "Extra observer records")
    return {"phase": phase, "nonce": nonce, "baseline": baseline, "stages": stages,
            "observations": observations, "final_profile": saved.hex(), "child_pid": pid,
            "child_exit_code": 0, "observer_exit": "NOT_OBSERVED_SELF_LOG_ONLY",
            "restore_process_exit": "NOT_OBSERVED_NO_PROCESS_HANDLE" if phase == 2 else "NOT_APPLICABLE"}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, safe_path(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def consumer():
    return load_module("global_theme_guard_" + uuid.uuid4().hex, ROOT / "tools/theme_native_runner.py")


def binding(role, path):
    path = safe_path(path)
    return {"role": role, "path": str(path), "sha256": sha(path), **metadata(path)}


def check_bindings(plan, *, full=True):
    values = plan.get("bindings", [])
    need(15 <= len(values) <= 100 and len({x["role"] for x in values}) == len(values), "Source binding closure malformed")
    for item in values:
        actual = metadata(item["path"])
        need(all(actual[k] == item[k] for k in ("device", "inode", "bytes", "mtime_ns")), "Bound source identity changed: " + item["role"])
        # Reflink can alter source-inode COW metadata; bytes/mtime/full hash remain
        # pinned. Other source inputs require the complete timestamp identity.
        if item["role"] != "base_disk":
            need(actual["ctime_ns"] == item["ctime_ns"], "Bound source timestamp changed")
        if full:
            need(sha(item["path"]) == item["sha256"], "Bound source SHA differs: " + item["role"])


def by_role(plan, role):
    matches = [x for x in plan["bindings"] if x["role"] == role]
    need(len(matches) == 1, "Required binding absent: " + role)
    return matches[0]


def protected_sources_quiet(nr, plan):
    for role in ("base_disk", "archive", "checkpoint"):
        nr.ensure_unopened(by_role(plan, role)["path"])


def command(argv, *, limit=65536, timeout=120):
    """Bound stdout/stderr in memory while owning only this child handle."""
    def limits():
        # mcopy edits a 2GiB existing raw file at arbitrary FAT offsets. An
        # 16MiB RLIMIT_FSIZE would also reject those legitimate private writes.
        # HostOutputGuard separately measures the exact four output roots.
        resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**3, 2 * 1024**3))
    child = subprocess.Popen([str(x) for x in argv], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=limits)
    pieces = {"out": bytearray(), "err": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as events:
            events.register(child.stdout, selectors.EVENT_READ, "out")
            events.register(child.stderr, selectors.EVENT_READ, "err")
            while events.get_map():
                need(time.monotonic() < deadline, "Owned command timeout")
                for key, _ in events.select(0.1):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        events.unregister(key.fileobj); continue
                    pieces[key.data].extend(block)
                    need(len(pieces[key.data]) <= limit, "Owned command diagnostic/readback bound exceeded")
        code = child.wait(timeout=max(0.1, deadline - time.monotonic()))
        need(code == 0, "Owned command failed: " + bytes(pieces["err"]).decode(errors="replace")[:512])
        return bytes(pieces["out"])
    finally:
        if child.poll() is None:
            child.kill(); child.wait(timeout=5)
        child.stdout.close(); child.stderr.close()


def guarded_command(guard, argv, **kwargs):
    guard.check("before-bounded-command", require_cow=True)
    try:
        return command(argv, **kwargs)
    finally:
        guard.check("after-bounded-command", require_cow=True)


def build_input(path, expected_sha, expected_name):
    need(expected_name in {"SHZTHEME.EXE", "SHZOBS.EXE"}, "Unknown native PE input role")
    need(re.fullmatch("[0-9a-f]{64}", expected_sha or "") and sha(path) == expected_sha, "Selected PE build receipt SHA differs")
    data = read_json(path)
    need(isinstance(data, dict) and data.get("status") == "PASS" and
         isinstance(data.get("source_hashes"), dict) and data["source_hashes"] and data.get("source_root"),
         "Actual passing PE/compiler build receipt required")
    if expected_name == "SHZTHEME.EXE":
        versions = data.get("compiler_versions")
        need(isinstance(versions, dict) and all(isinstance(versions.get(name), str) and versions[name].strip()
             for name in ("clang", "i686-w64-mingw32-gcc")), "Product compiler_versions record absent")
        expected_role = "selector"
    else:
        version = data.get("compiler_version")
        need(isinstance(version, str) and version.strip(), "Observer compiler_version record absent")
        expected_role = "observer"
    artifact = data.get("executable", {})
    source = safe_path(artifact.get("path", ""))
    gate = artifact.get("native_gate", {})
    need(source.name == expected_name and source.parent == safe_path(path).parent and
         gate.get("status") == "PASS" and gate.get("role") == expected_role and
         gate.get("native_execution_verified") is False and
         artifact.get("bytes") == source.stat().st_size and 0 < artifact["bytes"] <= 1024**2
         and sha(source) == artifact.get("sha256"), "Actual OEM PE artifact/build gate mismatch")
    if expected_name == "SHZTHEME.EXE":
        need({row.get("kind") for row in data.get("host_tests", [])} >= {"host", "sanitizer"} and
             all(str(row.get("result", "")).startswith("PASS:") for row in data["host_tests"]), "Product host/SAN completed assertions absent")
    commands_path = safe_path(path).parent / "commands.json"
    commands = read_json(commands_path) if commands_path.exists() else data.get("commands")
    need(isinstance(commands, list), "Executed compiler command records absent; hash-only metadata rejected")
    compiled = [row for row in commands if isinstance(row, dict) and isinstance(row.get("argv"), list)
                and "-o" in row["argv"] and row["argv"][row["argv"].index("-o") + 1:] == [str(source)]]
    need(len(compiled) == 1 and compiled[0].get("exit_code") == 0, "Actual native compiler zero exit absent")
    flags = compiled[0]["argv"]
    need(Path(flags[0]).name == "i686-w64-mingw32-gcc" and
         {"-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float", "-nostdlib", "-fno-stack-protector",
          "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
          "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp"} <= set(flags),
         "Actual native compiler legacy flags absent")
    source_root = safe_path(data["source_root"])
    records = []
    if commands_path.exists():
        records.append(binding("pe_commands:" + expected_name, commands_path))
    for name, digest in data["source_hashes"].items():
        relative = Path(name)
        need(not relative.is_absolute() and ".." not in relative.parts, "PE source path unsafe")
        item = binding("pe_source:" + expected_name + ":" + name, source_root / relative)
        need(item["sha256"] == digest, "PE source receipt is stale")
        records.append(item)
    return source, records


def boot_sectors(disk, partition):
    with safe_path(disk).open("rb") as stream:
        mbr = stream.read(512); stream.seek(partition["start_lba"] * 512); boot = stream.read(512)
    need(len(mbr) == len(boot) == 512 and hashlib.sha256(mbr).hexdigest() == partition["mbr_sha256"]
         and hashlib.sha256(boot).hexdigest() == partition["boot_sector_sha256"], "Protected MBR/VBR differ")
    return {"mbr_sha256": partition["mbr_sha256"], "boot_sector_sha256": partition["boot_sector_sha256"]}


def private_identity(path):
    item = metadata(path)
    return {k: item[k] for k in ("device", "inode", "bytes")}


def assert_private(plan):
    disk = Path(plan["roots"]["run"]) / "windows-uefi.raw"
    identity = private_identity(disk)
    need(identity == plan["private_cow_identity"] and identity["bytes"] <= 2 * 1024**3
         and identity["inode"] != by_role(plan, "base_disk")["inode"]
         and identity["device"] == by_role(plan, "base_disk")["device"], "Private COW inode changed or aliases base")
    return disk


def guest_spec(plan):
    return str(assert_private(plan)) + "@@" + str(plan["partition"]["start_lba"] * 512)


def mtype(plan, guard, guest, limit):
    return guarded_command(guard, [by_role(plan, "mtype")["path"], "-i", guest_spec(plan), guest], limit=limit)


def absent(plan, guard, guest):
    # Directory listing successful without the requested name is proof of
    # absence; a failed tool call is not interpreted as a missing guest file.
    listing = guarded_command(guard, [by_role(plan, "mdir")["path"], "-b", "-i", guest_spec(plan), "::/VXDLAB"])
    names = {row.decode("ascii").rsplit("/", 1)[-1].upper() for row in listing.splitlines()}
    need(guest.upper() not in names, "New guest input/output is stale: " + guest)


def guest_readback_inputs(plan, epoch):
    """Bind stopped guest inputs to independent stage/build/source identities."""
    need(epoch in (1, 2), "Stopped readback epoch invalid")
    stage, bootstrap = (Path(plan["roots"][name]) for name in ("stage", "bootstrap"))
    files, payloads = {}, {}
    for role, name in (("selector", "SHZTHEME.EXE"), ("observer", "SHZOBS.EXE")):
        payload = bounded(stage / name, 1024**2)
        artifact = by_role(plan, role)
        digest = hashlib.sha256(payload).hexdigest()
        need(digest == plan["stage_hashes"][name] == artifact["sha256"] and len(payload) == artifact["bytes"]
             and payload == bounded(artifact["path"], 1024**2), "Stopped staged/built PE bytes differ")
        prefix = "pe_source:" + name + ":"
        sources = [row for row in plan["bindings"] if row["role"].startswith(prefix)]
        source_hashes = {row["role"][len(prefix):]: row["sha256"] for row in sources}
        need(source_hashes and len(source_hashes) == len(sources) and
             all(re.fullmatch("[0-9a-f]{64}", value) for value in source_hashes.values()), "Stopped PE source closure absent")
        files[name] = {"guest_path": "::/VXDLAB/" + name, "bytes": len(payload), "sha256": digest,
            "stage_sha256": plan["stage_hashes"][name], "artifact_sha256": artifact["sha256"],
            "build_receipt_sha256": by_role(plan, role + "_receipt")["sha256"],
            "source_hashes": source_hashes, "read_limit_bytes": 1024**2}
        payloads[name] = payload
    case_name, case_root = ("SHZCASE.TXT", stage) if epoch == 1 else ("SHZCASE2.TXT", bootstrap)
    case_hashes = plan["stage_hashes"] if epoch == 1 else plan["bootstrap_hashes"]
    case = bounded(case_root / case_name, 60)
    digest = hashlib.sha256(case).hexdigest()
    need(case == case_bytes(plan["nonce"], epoch) and digest == case_hashes[case_name], "Stopped case source phase/hash differs")
    files["SHZCASE.TXT"] = {"guest_path": "::/VXDLAB/SHZCASE.TXT", "bytes": 60, "sha256": digest,
        "input_root": "stage" if epoch == 1 else "bootstrap", "input_name": case_name,
        "input_sha256": case_hashes[case_name], "phase": epoch, "read_limit_bytes": 60}
    payloads["SHZCASE.TXT"] = case
    ini = bounded(bootstrap / "WININI-AFTER", 65536)
    digest = hashlib.sha256(ini).hexdigest()
    need(digest == plan["bootstrap_hashes"]["WININI-AFTER"] == plan["preparation"]["winini_after_sha256"],
         "Stopped WIN.INI source/hash differs")
    files["WIN.INI"] = {"guest_path": "::/WINDOWS/WIN.INI", "bytes": len(ini), "sha256": digest,
        "input_root": "bootstrap", "input_name": "WININI-AFTER", "input_sha256": digest,
        "attributes_hex": plan["preparation"]["winini_attributes_hex"], "read_limit_bytes": 65536}
    payloads["WIN.INI"] = ini
    return {"schema": 1, "status": "PASS", "epoch": epoch, "nonce": plan["nonce"],
            "private_cow_identity": plan["private_cow_identity"], "files": files}, payloads


def stopped_guest_readback(plan, guard, epoch):
    """Called only after owned QEMU reaping and independent FD/maps quiet gates."""
    evidence, payloads = guest_readback_inputs(plan, epoch)
    for name, expected in payloads.items():
        item = evidence["files"][name]
        actual = mtype(plan, guard, item["guest_path"], item["read_limit_bytes"])
        need(actual == expected and hashlib.sha256(actual).hexdigest() == item["sha256"],
             "Stopped guest byte/hash readback differs: " + name)
    attributes = guarded_command(guard, [by_role(plan, "mattrib")["path"], "-i", guest_spec(plan), "::/WINDOWS/WIN.INI"])
    need(attributes.hex() == evidence["files"]["WIN.INI"]["attributes_hex"], "Stopped WIN.INI FAT attributes differ")
    return evidence


def allocation(plan, cow, guard, *, baseline=None):
    guard.check("before-stopped-allocation", require_cow=True)
    disk = assert_private(plan)
    observation = cow.observe_allocations(disk)
    original = baseline or plan["cow_baseline_before_injection"]
    growth = cumulative_growth(original, observation.to_dict())
    need(cow.net_exclusive_growth_bytes(cow.AllocationObservation(**original), observation) == growth,
         "Reviewed FIEMAP baseline/helper differs")
    need(shutil.disk_usage(disk.parent).free >= RESERVE, "Stopped COW free-space floor")
    guard.check("after-stopped-allocation", require_cow=True)
    return {"observation": observation.to_dict(), "net_exclusive_growth_bytes": growth,
            "quota_bytes": QUOTA, "original_baseline_used": True, "status": "PASS"}


def prepare(args):
    need(sys.dont_write_bytecode, "Use python -B; cache writes outside four roots are forbidden")
    need(shutil.disk_usage(ROOT).free >= RESERVE + QUOTA + HOST_LIMIT + 4 * 1024**2, "Full COW/output admission above20GiB required")
    nr = consumer()
    base_receipt = BASE.parent / "result.json"
    need(sha(BASE) == BASE_SHA and sha(base_receipt) == BASE_RECEIPT_SHA, "Protected base hash differs")
    base = read_json(base_receipt)
    need(base.get("profile") == "actual-win98-uefi-csmwrap" and base.get("snapshot") == "windows98-clean-installed"
         and base.get("originals_unchanged") is True and base.get("owned_disk_sha256_after_run") == BASE_SHA
         and base["partition"]["firmware_gop_opt_in"] is True, "Installed OEM/GOP base provenance mismatch")
    selector, product_sources = build_input(args.selector_receipt, args.selector_receipt_sha, "SHZTHEME.EXE")
    observer, observer_sources = build_input(args.observer_receipt, args.observer_receipt_sha, "SHZOBS.EXE")
    token = uuid.uuid4().hex[:12]
    roots = {role: str(ROOT / "build" / ("global-theme-6970-" + role + "-" + token)) for role in ROLES}
    plan = {"schema": 1, "kind": KIND, "owner_root": str(ROOT), "peer_root": str(PEER),
            "nonce": uuid.uuid4().hex, "roots": roots, "cow_quota_bytes": QUOTA,
            "runtime_bound_seconds": 900, "two_cold_epochs": 2, "startup_executable": STARTUP,
            "machine_profile": "q35-kvm-qemu64-2cpu-128m-gop-offline",
            "scope": "OEM_WIN98_CONTROL_NOT_SHIZUKUDOS_REPLACEMENT", "partition": base["partition"],
            "snapshot": "windows98-clean-installed", "base_disk_sha256": BASE_SHA,
            "host_output_budget": {"schema": 1, "roots": [roots[r] for r in ROLES],
                "excluded_private_cow": roots["run"] + "/windows-uefi.raw", "limit_bytes": HOST_LIMIT, "reserve_bytes": RESERVE}}
    require_fresh_roots(plan)
    artifacts = [binding("base_disk", BASE), binding("base_receipt", base_receipt)]
    need(base.get("immutable_sources") == {base["archive"]: sha(base["archive"]), base["checkpoint_record"]: sha(base["checkpoint_record"])}, "Archive/checkpoint changed")
    artifacts += [binding("archive", base["archive"]), binding("checkpoint", base["checkpoint_record"]),
                  binding("selector_receipt", args.selector_receipt), binding("observer_receipt", args.observer_receipt),
                  binding("selector", selector), binding("observer", observer)] + product_sources + observer_sources
    for name in OWN_SOURCES:
        artifacts.append(binding("own:" + name, ROOT / name))
    for role, name in PEER_SOURCES.items():
        artifacts.append(binding(role, PEER / name))
    for role, value in (("qemu", args.qemu), ("ovmf_code", args.firmware_code), ("ovmf_vars", args.firmware_vars),
                        ("vga_rom", args.vga_rom)):
        artifacts.append(binding(role, value))
    anchor = safe_path(args.csm_dir)
    for role, name in (("csm_efi", "CSMWRAP.EFI"), ("csm16", "Csm16.bin"), ("csm_vga", "vgabios.bin"), ("gop_receipt", "build-result.json")):
        artifacts.append(binding(role, anchor / name))
    need(by_role({"bindings": artifacts}, "csm_efi")["sha256"] == base["csmwrap"]["sha256"], "GOP/CSMWrap differs from retained base")
    for role in ("cp", "mcopy", "mtype", "mdir", "mattrib"):
        found = shutil.which(role); need(found is not None, "Required host tool missing")
        artifacts.append(binding(role, Path(found).resolve(strict=True)))
    plan["bindings"] = artifacts
    for role in ("base_disk", "archive", "checkpoint"):
        nr.ensure_unopened(by_role(plan, role)["path"])
    check_bindings(plan)
    guard = nr.HostOutputGuard([Path(roots[r]) for r in ROLES], Path(roots["run"]) / "windows-uefi.raw")
    for path in validate_plan_shape(plan):
        path.mkdir(mode=0o700)
    guard.check("fresh-four-roots")
    run, stage, frozen, bootstrap = (Path(roots[r]) for r in ("run", "stage", "consumer", "bootstrap"))
    # Preserve exact reviewed helper sources; execute no IO.SYS wrapper imports.
    for role in PEER_SOURCES:
        new_file(frozen / (role + ".py"), bounded(by_role(plan, role)["path"], 2 * 1024**2))
    new_file(frozen / "guard.py", bounded(ROOT / "tools/theme_native_runner.py", 2 * 1024**2))
    plan["frozen_helpers"] = {p.name: sha(p) for p in frozen.iterdir()}
    new_file(bootstrap / "SHZCASE2.TXT", case_bytes(plan["nonce"], 2))
    for path, name in ((selector, "SHZTHEME.EXE"), (observer, "SHZOBS.EXE")):
        new_file(stage / name, bounded(path, 1024**2))
    new_file(stage / "SHZCASE.TXT", case_bytes(plan["nonce"], 1))
    guard.check("before-private-reflink")
    disk = run / "windows-uefi.raw"
    command([by_role(plan, "cp")["path"], "--reflink=always", "--sparse=auto", "--", BASE, disk], timeout=300)
    plan["private_cow_identity"] = private_identity(disk)
    assert_private(plan)
    need(sha(disk) == BASE_SHA and sha(BASE) == BASE_SHA, "Reflink full readback differs")
    nr.ensure_unopened(disk)
    cow = load_module("global_theme_cow_" + token, frozen / "cow.py")
    baseline = cow.observe_allocations(disk)
    need(baseline.shared_bytes > 0, "Reflink lacks shared extents; no disk-copy fallback")
    plan["cow_baseline_before_injection"] = baseline.to_dict()
    guard.check("pre-injection-original-baseline", require_cow=True)
    spec = guest_spec(plan)
    for name in INPUTS + LOGS:
        absent(plan, guard, name)
    boot_sectors(disk, plan["partition"])
    original = mtype(plan, guard, "::/WINDOWS/WIN.INI", 65536)
    patched, edit = patch_empty_run(original)
    attributes = guarded_command(guard, [by_role(plan, "mattrib")["path"], "-i", spec, "::/WINDOWS/WIN.INI"])
    need(re.fullmatch(rb"\s*A\s+::/WINDOWS/WIN.INI\r?\n", attributes), "Unsupported WIN.INI attributes")
    new_file(bootstrap / "WININI-BEFORE", original); new_file(bootstrap / "WININI-AFTER", patched)
    for name in INPUTS:
        guarded_command(guard, [by_role(plan, "mcopy")["path"], "-i", spec, stage / name, "::/VXDLAB/" + name])
        need(mtype(plan, guard, "::/VXDLAB/" + name, 1024**2) == bounded(stage / name, 1024**2), "Guest input readback differs")
    guarded_command(guard, [by_role(plan, "mcopy")["path"], "-o", "-i", spec, bootstrap / "WININI-AFTER", "::/WINDOWS/WIN.INI"])
    need(mtype(plan, guard, "::/WINDOWS/WIN.INI", 65536) == patched and
         guarded_command(guard, [by_role(plan, "mattrib")["path"], "-i", spec, "::/WINDOWS/WIN.INI"]) == attributes, "WIN.INI readback/attributes differ")
    boot_sectors(disk, plan["partition"])
    plan["preparation"] = {"status": "PREPARED_NATIVE_UNVERIFIED", "copy_mode": "cp --reflink=always --sparse=auto",
        "no_cpu_or_ram_state": True, "winini_before_sha256": hashlib.sha256(original).hexdigest(),
        "winini_after_sha256": hashlib.sha256(patched).hexdigest(), "winini_attributes_hex": attributes.hex(),
        "ini_edit": edit, "boot_sectors_preserved": True,
        "cow": allocation(plan, cow, guard), "private_disk_sha256": sha(disk)}
    plan["stage_hashes"] = {name: sha(stage / name) for name in INPUTS}
    plan["bootstrap_hashes"] = {p.name: sha(p) for p in bootstrap.iterdir()}
    plan["root_identities"] = {r: {"device": Path(roots[r]).stat().st_dev, "inode": Path(roots[r]).stat().st_ino} for r in ROLES}
    check_bindings(plan)
    nr.ensure_unopened(BASE)
    guard.write_receipt(bootstrap / "preparation-result.json", {"status": "PREPARED_NATIVE_UNVERIFIED", "preparation": plan["preparation"]}, "final-preparation")
    path = stage / "global-theme-plan.json"
    new_json(path, plan)
    guard.check("plan-including-own-bytes", require_cow=True)
    return {"status": "PREPARED_NATIVE_UNVERIFIED", "plan": str(path), "sha256": sha(path)}


def load_plan(path, selected_sha, *, full_bindings=True):
    need(re.fullmatch("[0-9a-f]{64}", selected_sha or "") and sha(path) == selected_sha, "Selected plan SHA differs")
    plan = read_json(path, 256 * 1024)
    validate_plan_shape(plan)
    need(plan.get("peer_root") == str(PEER) and plan.get("snapshot") == "windows98-clean-installed"
         and by_role(plan, "base_disk")["path"] == str(BASE)
         and by_role(plan, "base_disk")["sha256"] == BASE_SHA
         and by_role(plan, "base_receipt")["sha256"] == BASE_RECEIPT_SHA,
         "Protected base/checkpoint source selection differs")
    for name in OWN_SOURCES:
        need(by_role(plan, "own:" + name)["path"] == str(ROOT / name), "Current runtime source binding absent")
    for role, name in PEER_SOURCES.items():
        need(by_role(plan, role)["path"] == str(PEER / name), "Reviewed peer helper binding differs")
    need(safe_path(path).parent == Path(plan["roots"]["stage"]) and Path(path).name == "global-theme-plan.json", "Plan outside exact owned stage")
    for role in ROLES:
        root = safe_path(plan["roots"][role]); info = root.stat()
        need(stat.S_ISDIR(info.st_mode) and plan["root_identities"][role] == {"device": info.st_dev, "inode": info.st_ino}, "Owned root replaced")
    for category, names in (("stage", plan["stage_hashes"]), ("bootstrap", plan["bootstrap_hashes"]), ("consumer", plan["frozen_helpers"])):
        for name, digest in names.items():
            need(Path(name).name == name and sha(Path(plan["roots"][category]) / name) == digest, "Frozen runtime input changed")
    assert_private(plan)
    check_bindings(plan, full=full_bindings)
    return plan


def output_guard(plan):
    nr = load_module("global_frozen_guard_" + uuid.uuid4().hex, Path(plan["roots"]["consumer"]) / "guard.py")
    guard = nr.HostOutputGuard([Path(plan["roots"][r]) for r in ROLES], Path(plan["roots"]["run"]) / "windows-uefi.raw")
    for role, identity in plan["root_identities"].items():
        guard.identities[Path(plan["roots"][role])] = (identity["device"], identity["inode"])
    guard.cow_identity = tuple(plan["private_cow_identity"][k] for k in ("device", "inode"))
    return nr, guard


def qemu_arguments(plan, epoch):
    disk = assert_private(plan)
    root = Path(plan["roots"]["run"]) / ("e" + str(epoch))
    socket = root / "q.sock"
    need(epoch in (1, 2) and len(os.fsencode(socket)) < 108, "Invalid cold epoch/socket")
    return [by_role(plan, "qemu")["path"], "-name", "shz-own-global-theme-epoch-" + str(epoch),
        "-machine", "q35,hpet=off", "-accel", "kvm", "-cpu", "qemu64", "-smp", "2", "-m", "128",
        "-nodefaults", "-nic", "none", "-display", "none", "-device", "VGA,romfile=" + by_role(plan, "vga_rom")["path"],
        "-drive", "if=pflash,unit=0,format=raw,readonly=on,file=" + by_role(plan, "ovmf_code")["path"],
        "-drive", "if=pflash,unit=1,format=raw,file=" + str(root / "OVMF_VARS.fd"),
        "-drive", "file=" + str(disk) + ",format=raw,if=none,id=win98",
        "-device", "ide-hd,drive=win98,bus=ide.0,bootindex=1", "-serial", "file:" + str(root / "serial.log"),
        "-qmp", "unix:" + str(socket) + ",server=on,wait=off", "-no-reboot"]


def input_action(action):
    need(isinstance(action, dict) and action.get("kind") in ("key", "click", "capture", "stop"), "Unsupported manual input")
    kind = action["kind"]
    if kind == "key":
        need(set(action) == {"kind", "keys"} and isinstance(action["keys"], list) and 1 <= len(action["keys"]) <= 4
             and all(isinstance(k, str) and re.fullmatch("[a-z0-9_]{1,16}", k) for k in action["keys"]), "Invalid QMP key chord")
    elif kind == "click":
        need(set(action) == {"kind", "x", "y"} and all(type(action[k]) is int and 0 <= action[k] <= 32767 for k in ("x", "y")), "Invalid absolute mouse input")
    else:
        need(set(action) == {"kind"}, "Extra manual-action fields")
    return action


def absolute_pointer_device(devices):
    need(isinstance(devices, list) and len(devices) <= 16, "Bounded QMP pointer query required")
    current = [item for item in devices if isinstance(item, dict) and item.get("current") is True]
    need(len(current) == 1, "Exactly one current native pointer required for absolute click")
    item = current[0]
    need(item.get("absolute") is True and type(item.get("index")) is int and item["index"] >= 0
         and isinstance(item.get("name"), str) and 0 < len(item["name"]) <= 256,
         "Absolute click unsupported by current native pointer; use keyboard")
    return {key: item[key] for key in ("name", "index", "current", "absolute")}


def native_image_kind(data):
    need(isinstance(data, bytes) and 0 < len(data) <= 4 * 1024**2, "Bounded native image required")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        offset, header, ended, idat_seen, idat_closed = 8, None, False, False, False
        compressed = bytearray()
        while offset < len(data):
            need(offset + 12 <= len(data), "Native PNG chunk header truncated")
            length = struct.unpack_from(">I", data, offset)[0]
            kind = data[offset + 4:offset + 8]
            stop = offset + 12 + length
            need(stop <= len(data) and re.fullmatch(rb"[A-Za-z]{4}", kind), "Native PNG chunk bounds/type invalid")
            payload = data[offset + 8:stop - 4]
            need((zlib.crc32(kind + payload) & 0xffffffff) == struct.unpack_from(">I", data, stop - 4)[0],
                 "Native PNG chunk CRC differs")
            if header is None:
                need(offset == 8 and kind == b"IHDR" and length == 13, "Native PNG first IHDR incomplete")
                width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
                need(0 < width <= 4096 and 0 < height <= 4096 and depth == 8 and color in (2, 6)
                     and (compression, filtering, interlace) == (0, 0, 0), "Unsupported native PNG dimensions/encoding")
                stride = width * (3 if color == 2 else 4) + 1
                need(stride * height <= 4 * 1024**2, "Native PNG decompressed raster exceeds bound")
                header = (stride, height)
            elif kind == b"IDAT":
                need(not idat_closed and not ended, "Native PNG IDAT order invalid")
                idat_seen = True
                compressed.extend(payload)
            elif kind == b"IEND":
                need(length == 0 and compressed and stop == len(data), "Native PNG IEND/raster/trailing bytes invalid")
                ended = True
            else:
                need(kind != b"IHDR" and kind[0] & 0x20, "Unsupported native PNG critical chunk")
                if idat_seen:
                    idat_closed = True
            offset = stop
        need(header is not None and ended and compressed, "Native PNG complete raster/IEND absent")
        stride, height = header
        decoder = zlib.decompressobj()
        try:
            raster = decoder.decompress(bytes(compressed), stride * height + 1)
        except zlib.error as error:
            raise TrialError("Native PNG compressed raster corrupt") from error
        need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
             and len(raster) == stride * height and all(raster[row * stride] <= 4 for row in range(height)),
             "Native PNG raster truncated/extra/filter invalid")
        return "native-QMP-PNG"
    match = re.match(rb"P6\n([1-9][0-9]{0,3}) ([1-9][0-9]{0,3})\n255\n", data)
    need(match is not None, "Native PPM header invalid")
    width, height = (int(value) for value in match.groups())
    need(width <= 4096 and height <= 4096 and len(data) == match.end() + width * height * 3,
         "Native PPM raster truncated/extra")
    return "native-QMP-PPM"


def queue_input(path, selected_sha, epoch, sequence, action):
    need(sys.dont_write_bytecode, "Use python -B")
    plan = load_plan(path, selected_sha, full_bindings=False)
    need(epoch in (1, 2) and type(sequence) is int and 1 <= sequence <= 64, "Manual input sequence/epoch invalid")
    input_action(action)
    nr, guard = output_guard(plan)
    guard.check("before-queued-manual-input", require_cow=True)
    root = Path(plan["roots"]["run"]) / ("e" + str(epoch))
    state = read_json(root / "active.json", 4096)
    need(state.get("nonce") == plan["nonce"] and state.get("epoch") == epoch
         and state.get("plan_sha256") == selected_sha and state.get("status") == "ACTIVE", "Epoch is not the selected active owner")
    new_json(root / ("input-%03d.json" % sequence), {"schema": 1, "nonce": plan["nonce"], "epoch": epoch,
             "sequence": sequence, "plan_sha256": selected_sha, "action": action})
    guard.check("after-queued-manual-input", require_cow=True)


def epoch_run(plan, plan_path, selected_sha, epoch, nr, guard, cow, sample, qemu):
    root = Path(plan["roots"]["run"]) / ("e" + str(epoch))
    need(not root.exists(), "Cold epoch output is stale")
    nr.ensure_unopened(assert_private(plan)); protected_sources_quiet(nr, plan)
    check_bindings(plan)
    guard.check("before-cold-epoch", require_cow=True)
    used_cow = allocation(plan, cow, guard)["net_exclusive_growth_bytes"]
    need(shutil.disk_usage(ROOT).free >= RESERVE + max(0, QUOTA - used_cow)
         + max(0, HOST_LIMIT - guard.used) + 4 * 1024**2, "Remaining COW/output admission above reserve")
    root.mkdir(mode=0o700)
    new_file(root / "OVMF_VARS.fd", bounded(by_role(plan, "ovmf_vars")["path"], 8 * 1024**2))
    argv = qemu_arguments(plan, epoch)
    report = {"schema": 1, "status": "FAIL", "epoch": epoch, "nonce": plan["nonce"],
        "plan_sha256": selected_sha, "cold_hardware": True, "cpu_ram_snapshot_loaded": False,
        "private_cow_identity": plan["private_cow_identity"], "original_baseline": plan["cow_baseline_before_injection"],
        "fresh_vars_sha256": sha(root / "OVMF_VARS.fd"), "argv": argv, "inputs": [], "captures": [],
        "qemu_child_reaped": False, "observer_external_exit": "NOT_OBSERVED", "raw_full_framebuffer": "NOT_COLLECTED"}
    baseline = cow.AllocationObservation(**plan["cow_baseline_before_injection"])
    child, monitor = None, None
    try:
        guard.check("before-QEMU-launch", require_cow=True)
        def limit_files():
            # The single excluded raw inode is 2GiB and is writable. Do not
            # incorrectly impose the host-log byte cap on guest disk offsets.
            resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**3, 2 * 1024**3))
        with (root / "qemu.stderr").open("xb") as stderr:
            child = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=stderr, preexec_fn=limit_files)
        report["owned_qemu_pid"] = child.pid
        need(sha(plan_path) == selected_sha, "Selected plan changed before VM")
        guard.check("after-QEMU-launch", require_cow=True)
        monitor = qemu.QMP(root / "q.sock")
        active = {"status": "ACTIVE", "epoch": epoch, "nonce": plan["nonce"], "plan_sha256": selected_sha,
                  "owned_qemu_pid": child.pid}
        guard.write_owned_json(root / "active.json", active)
        started, next_sample, sequence = time.monotonic(), 0.0, 1
        capture_count = 0
        while child.poll() is None:
            now = time.monotonic()
            need(now - started <= 900, "Cold epoch timeout; missing observer/GUI completion")
            guard.check("live-cold-epoch-poll", require_cow=True)
            check_bindings(plan, full=False)
            if now >= next_sample:
                need(sha(plan_path) == selected_sha, "Selected plan changed during owned VM")
                observation, growth, seconds = sample(assert_private(plan), monitor, cow, baseline, QUOTA, RESERVE)
                need(cumulative_growth(plan["cow_baseline_before_injection"], observation.to_dict()) == growth, "Cumulative baseline was reset")
                report["cow_peak_growth_bytes"] = max(report.get("cow_peak_growth_bytes", 0), growth)
                report["cow_latest"] = observation.to_dict(); report["cow_maximum_sampling_seconds"] = max(seconds, report.get("cow_maximum_sampling_seconds", 0))
                next_sample = now + 5
            queued = root / ("input-%03d.json" % sequence)
            if queued.exists():
                need(sequence <= 64, "Manual input queue exceeded64 actions")
                item = read_json(queued, 4096)
                need(set(item) == {"schema", "nonce", "epoch", "sequence", "plan_sha256", "action"}
                     and item["schema"] == 1 and item["nonce"] == plan["nonce"] and item["epoch"] == epoch
                     and item["sequence"] == sequence and item["plan_sha256"] == selected_sha, "Stale or reordered manual input")
                action = input_action(item["action"])
                audit = {**item, "input_sha256": sha(queued), "elapsed_seconds": now - started}
                if action["kind"] == "key":
                    monitor.call("send-key", {"keys": [{"type": "qcode", "data": key} for key in action["keys"]], "hold-time": 100})
                elif action["kind"] == "click":
                    audit["absolute_pointer_device"] = absolute_pointer_device(monitor.call("query-mice"))
                    monitor.call("input-send-event", {"events": [{"type": "abs", "data": {"axis": axis, "value": action[axis]}} for axis in ("x", "y")]})
                    monitor.call("input-send-event", {"events": [{"type": "btn", "data": {"button": "left", "down": True}}]})
                    monitor.call("input-send-event", {"events": [{"type": "btn", "data": {"button": "left", "down": False}}]})
                elif action["kind"] == "capture":
                    need(capture_count < 2 and guard.limit - guard.used >= 4 * 1024**2, "Limited native capture budget unavailable")
                    # Native default PPM avoids retrying an arbitrary QMP
                    # error as a presumed unsupported-PNG reply. Every failed
                    # screendump aborts; complete raster bytes are checked.
                    image = root / ("native-%d.ppm" % capture_count)
                    monitor.call("screendump", {"filename": str(image)})
                    kind = native_image_kind(bounded(image, 4 * 1024**2))
                    report["captures"].append({"path": str(image), "sha256": sha(image), "format": kind, "visual_verdict": "NOT_REVIEWED"})
                    capture_count += 1
                else:
                    monitor.call("quit")
                    audit["stop_method"] = "owned-QMP-quit; not proof of normal Windows shutdown"
                report["inputs"].append(audit)
                guard.write_owned_json(root / "manual-input-audit.json", {"schema": 1, "nonce": plan["nonce"], "inputs": report["inputs"]})
                guard.check("after-owned-manual-action", require_cow=True)
                sequence += 1
                if action["kind"] == "stop":
                    child.wait(timeout=10); break
            time.sleep(0.1)
        need(child.returncode == 0, "Owned QEMU exited nonzero")
        report["qemu_exit_code"] = child.returncode
        report["qemu_child_reaped"] = True
        nr.ensure_unopened(assert_private(plan))
        protected_sources_quiet(nr, plan)
        check_bindings(plan)
        report["protected_source_fd_maps_quiet"] = True
        report["stopped_cow"] = allocation(plan, cow, guard)
        boot_sectors(assert_private(plan), plan["partition"])
        report["stopped_guest_inputs"] = stopped_guest_readback(plan, guard, epoch)
        data = mtype(plan, guard, "::/VXDLAB/" + LOGS[epoch - 1], 32768)
        first = None
        if epoch == 2:
            first_bytes = bounded(Path(plan["roots"]["run"]) / "e1" / LOGS[0], 32768)
            need(mtype(plan, guard, "::/VXDLAB/" + LOGS[0], 32768) == first_bytes, "Phase1 guest log changed across boot2")
            first = parse_observer_log(first_bytes, plan["nonce"], 1)
        report["observer"] = parse_observer_log(data, plan["nonce"], epoch, first)
        new_file(root / LOGS[epoch - 1], data)
        report["observer_log_sha256"] = sha(root / LOGS[epoch - 1])
        report["private_disk_sha256_after_stop"] = sha(assert_private(plan))
        report["status"] = "NATIVE_EVIDENCE_COLLECTED_EXTERNAL_EXIT_VISUAL_PENDING"
    except BaseException as error:
        report["error"] = str(error)
        raise
    finally:
        if child is not None and child.poll() is None:
            child.kill(); child.wait(timeout=5)
            report["owned_abort"] = True
        if child is not None:
            report["qemu_child_reaped"] = child.poll() is not None
            report["qemu_exit_code"] = child.returncode
        if monitor is not None:
            monitor.close()
        active = {"status": "STOPPED", "epoch": epoch, "nonce": plan["nonce"], "plan_sha256": selected_sha}
        guard.write_owned_json(root / "active.json", active)
        guard.write_receipt(root / "epoch-result.json", report, "cold-epoch-final-self-inclusive")
    return report


def execute(path, selected_sha, lock_wait=0):
    need(sys.dont_write_bytecode, "Use python -B")
    plan = load_plan(path, selected_sha)
    nr, guard = output_guard(plan)
    guard.check("before-two-epoch-admission", require_cow=True)
    run = Path(plan["roots"]["run"])
    need(not any((run / name).exists() for name in ("execute.claim", "e1", "e2", "trial-result.json")), "Execution outputs are stale; never reuse old v15 or prior epochs")
    need(sha(assert_private(plan)) == plan["preparation"]["private_disk_sha256"], "Prepared COW was changed before launch")
    frozen = Path(plan["roots"]["consumer"])
    cow = load_module("global_epoch_cow_" + uuid.uuid4().hex, frozen / "cow.py")
    qemu = load_module("global_epoch_qemu_" + uuid.uuid4().hex, frozen / "qemu_helper.py")
    functions = nr.reviewed_functions(bounded(frozen / "adapter.py", 2 * 1024**2))
    lock = safe_path(PEER / "build/modern-app-native-guest.lock")
    need(stat.S_ISREG(lock.stat().st_mode), "Existing shared native lock required")
    report = {"schema": 1, "kind": KIND, "status": "FAIL", "plan": str(path), "plan_sha256": selected_sha,
              "nonce": plan["nonce"], "epochs": [], "scope": plan["scope"], "shizukudos_replacement_verified": False,
              "all_requested_modern_features_verified": False, "observer_process_exit": "NOT_OBSERVED",
              "automatic_restore_process_exit": "NOT_OBSERVED_NO_PROCESS_HANDLE", "full_framebuffer_gate": "NOT_COLLECTED",
              "visual_review": "REQUIRED"}
    with lock.open("rb") as lease:
        nr.acquire_native_lock(lease, lock_wait)
        guard.check("shared-lock-held-for-both-boots", require_cow=True)
        new_json(run / "execute.claim", {"nonce": plan["nonce"], "plan_sha256": selected_sha, "owner_pid": os.getpid()})
        try:
            for epoch in (1, 2):
                if epoch == 2:
                    nr.ensure_unopened(assert_private(plan)); protected_sources_quiet(nr, plan)
                    need(report["epochs"][0]["qemu_child_reaped"] is True, "Previous QEMU still active")
                    allocation(plan, cow, guard)
                    need(mtype(plan, guard, "::/VXDLAB/SHZCASE.TXT", 60) == case_bytes(plan["nonce"], 1), "Phase file is stale")
                    attrs = guarded_command(guard, [by_role(plan, "mattrib")["path"], "-i", guest_spec(plan), "::/VXDLAB/SHZCASE.TXT"])
                    before_ini = mtype(plan, guard, "::/WINDOWS/WIN.INI", 65536)
                    need(hashlib.sha256(before_ini).hexdigest() == plan["preparation"]["winini_after_sha256"], "WIN.INI changed between epochs")
                    absent(plan, guard, LOGS[1])
                    guarded_command(guard, [by_role(plan, "mcopy")["path"], "-o", "-i", guest_spec(plan),
                                            Path(plan["roots"]["bootstrap"]) / "SHZCASE2.TXT", "::/VXDLAB/SHZCASE.TXT"])
                    need(mtype(plan, guard, "::/VXDLAB/SHZCASE.TXT", 60) == case_bytes(plan["nonce"], 2) and
                         mtype(plan, guard, "::/WINDOWS/WIN.INI", 65536) == before_ini and
                         guarded_command(guard, [by_role(plan, "mattrib")["path"], "-i", guest_spec(plan), "::/VXDLAB/SHZCASE.TXT"]) == attrs, "Only stopped case phase may change")
                    boot_sectors(assert_private(plan), plan["partition"])
                    allocation(plan, cow, guard)
                    check_bindings(plan)
                report["epochs"].append(epoch_run(plan, path, selected_sha, epoch, nr, guard, cow,
                                                  functions["quiescent_cow_observation"], qemu))
            report["source_bindings_unchanged"] = True
            check_bindings(plan); protected_sources_quiet(nr, plan)
            report["status"] = "NEEDS_VISUAL_REVIEW"
        except BaseException as error:
            report["error"] = str(error)
            raise
        finally:
            guard.write_receipt(run / "trial-result.json", report, "two-cold-boots-final-self-inclusive")
    return verify(path, selected_sha)


def verify(path, selected_sha):
    """Read-only recheck; missing machine evidence is FAIL, never a visual waiver."""
    need(sys.dont_write_bytecode, "Use python -B for the read-only verifier")
    plan = load_plan(path, selected_sha)
    nr, guard = output_guard(plan)
    guard.check("independent-verifier", require_cow=True)
    run = Path(plan["roots"]["run"])
    disk = assert_private(plan); nr.ensure_unopened(disk); protected_sources_quiet(nr, plan)
    report = read_json(run / "trial-result.json")
    need(report.get("status") == "NEEDS_VISUAL_REVIEW" and report.get("kind") == KIND and
         report.get("plan_sha256") == selected_sha and report.get("nonce") == plan["nonce"] and
         report.get("source_bindings_unchanged") is True and len(report.get("epochs", [])) == 2,
         "Missing, failed or partial trial evidence")
    need(report.get("host_output_budget", {}).get("status") == "PASS", "Final host-output guard failed")
    first, pids = None, []
    for epoch in (1, 2):
        item = read_json(run / ("e" + str(epoch)) / "epoch-result.json")
        need(item == report["epochs"][epoch - 1] and item.get("status") == "NATIVE_EVIDENCE_COLLECTED_EXTERNAL_EXIT_VISUAL_PENDING"
             and item.get("epoch") == epoch and item.get("nonce") == plan["nonce"]
             and item.get("plan_sha256") == selected_sha and item.get("cold_hardware") is True
             and item.get("cpu_ram_snapshot_loaded") is False and item.get("qemu_child_reaped") is True
             and item.get("qemu_exit_code") == 0 and item.get("private_cow_identity") == plan["private_cow_identity"]
             and item.get("protected_source_fd_maps_quiet") is True
             and item.get("original_baseline") == plan["cow_baseline_before_injection"]
             and item.get("fresh_vars_sha256") == by_role(plan, "ovmf_vars")["sha256"]
             and item.get("argv") == qemu_arguments(plan, epoch)
             and item.get("host_output_budget", {}).get("status") == "PASS", "Cold epoch/source/resource evidence differs")
        pids.append(item["owned_qemu_pid"])
        cumulative_growth(plan["cow_baseline_before_injection"], item["stopped_cow"]["observation"])
        need(item["stopped_cow"]["status"] == "PASS" and item.get("cow_peak_growth_bytes", QUOTA + 1) <= QUOTA,
             "Cumulative resource evidence failed")
        expected_readback, _ = guest_readback_inputs(plan, epoch)
        need(item.get("stopped_guest_inputs") == expected_readback, "Stopped guest executable/case/INI source evidence differs")
        log_path = run / ("e" + str(epoch)) / LOGS[epoch - 1]
        need(sha(log_path) == item["observer_log_sha256"], "Collected observer log changed")
        observed = parse_observer_log(bounded(log_path, 32768), plan["nonce"], epoch, first)
        need(observed == {**item["observer"], "baseline": tuple(item["observer"]["baseline"])}, "Observer decoder disagrees")
        if epoch == 1:
            first = observed
        for capture in item["captures"]:
            image = safe_path(capture["path"])
            need(image.parent == run / ("e" + str(epoch)) and sha(image) == capture["sha256"], "Native capture changed/foreign")
            need(native_image_kind(bounded(image, 4 * 1024**2)) == capture["format"], "Native capture format changed")
        need(len(item["captures"]) <= 2 and len(item["inputs"]) <= 64, "Manual/capture evidence exceeds bound")
        for sequence, audit in enumerate(item["inputs"], 1):
            queued = run / ("e" + str(epoch)) / ("input-%03d.json" % sequence)
            need(audit.get("sequence") == sequence and audit.get("nonce") == plan["nonce"]
                 and audit.get("epoch") == epoch and audit.get("plan_sha256") == selected_sha
                 and sha(queued) == audit.get("input_sha256"), "Manual input audit changed/reordered")
            queued_record = read_json(queued, 4096)
            need(queued_record == {k: audit[k] for k in ("schema", "nonce", "epoch", "sequence", "plan_sha256", "action")}, "Queued action/audit disagree")
            input_action(audit["action"])
            if audit["action"]["kind"] == "click":
                need(absolute_pointer_device([audit.get("absolute_pointer_device")]) == audit["absolute_pointer_device"],
                     "Absolute pointer support was not recorded before click")
    need(len(set(pids)) == 2, "Two distinct fully stopped QEMU hardware epochs required")
    cow = load_module("global_verify_cow_" + uuid.uuid4().hex, Path(plan["roots"]["consumer"]) / "cow.py")
    final = allocation(plan, cow, guard)
    boot_sectors(disk, plan["partition"])
    need(sha(disk) == report["epochs"][1]["private_disk_sha256_after_stop"], "Final private disk changed")
    need(stopped_guest_readback(plan, guard, 2) == report["epochs"][1]["stopped_guest_inputs"],
         "Independent final guest binary/case/INI readback differs")
    return {"status": "NEEDS_VISUAL_REVIEW", "kind": KIND, "selected_plan_sha256": selected_sha,
        "gates": {"observer_log_protocol": "PASS", "native_os_identity": "PASS_OEM_CONTROL",
            "palette_profile_run_readback": "PASS", "cross_process_notification_repaint_native_pixel": "PASS",
            "owned_selector_gui_child_exit": "PASS", "same_cow_two_cold_hardware_epochs": "PASS",
            "stopped_guest_executable_case_ini_source_readback": "PASS",
            "cold_boot_saved_palette_restore": "PASS", "source_and_resource_guards": "PASS",
            "observer_process_exit": "NOT_OBSERVED", "automatic_restore_process_exit": "NOT_OBSERVED_NO_PROCESS_HANDLE",
            "full_framebuffer_gate": "NOT_COLLECTED", "visual_review": "REQUIRED",
            "shizukudos_windows98_replacement": "NOT_VERIFIED", "all_modern_features": "NOT_VERIFIED"},
        "final_cow": final, "host_output_budget": guard.to_dict()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="action", required=True)
    prep = sub.add_parser("prepare", allow_abbrev=False)
    for name in ("selector-receipt", "selector-receipt-sha", "observer-receipt", "observer-receipt-sha",
                 "qemu", "firmware-code", "firmware-vars", "vga-rom", "csm-dir"):
        prep.add_argument("--" + name, required=True)
    for name in ("execute", "verify", "queue"):
        item = sub.add_parser(name, allow_abbrev=False)
        item.add_argument("--plan", type=Path, required=True); item.add_argument("--plan-sha", required=True)
        if name == "execute": item.add_argument("--lock-wait", type=int, default=0)
        if name == "queue":
            item.add_argument("--epoch", type=int, required=True); item.add_argument("--sequence", type=int, required=True)
            item.add_argument("--input-json", required=True, help="bounded key/click/capture/stop JSON object")
    args = parser.parse_args()
    try:
        if args.action == "prepare": result = prepare(args)
        elif args.action == "execute": result = execute(args.plan, args.plan_sha, args.lock_wait)
        elif args.action == "verify": result = verify(args.plan, args.plan_sha)
        else:
            need(len(args.input_json) <= 2048, "Manual input JSON too large")
            queue_input(args.plan, args.plan_sha, args.epoch, args.sequence, json.loads(args.input_json, object_pairs_hook=pairs))
            result = {"status": "QUEUED_NATIVE_ACTION_NOT_YET_OBSERVED"}
        print(json.dumps(result, indent=2))
        return 0
    except Exception as error:
        print(json.dumps({"status": "FAIL", "kind": KIND, "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
