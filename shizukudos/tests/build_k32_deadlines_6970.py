#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Guarded hosted freestanding K32 build; no guest, VM or Windows proof.

Calls the unchanged kbuild build_kernel twice and its K32 Multiboot stub
builder. All objects, compiler temporaries, captures and the receipt share
one NEW 8 MiB root, admitted above 20 GiB. Never builds Kernel64, downloads
inputs, installs packages or publishes binaries. This runner is Linux-only.
"""
import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
SHZ = ROOT / "shizukudos"
LIMIT = 8 * 1024 * 1024
RESERVE = 20 * 1024 * 1024 * 1024
CAPTURE_LIMIT = 512 * 1024
RECEIPT_LIMIT = 128 * 1024
PENDING = 2 * CAPTURE_LIMIT + RECEIPT_LIMIT + 64 * 1024
TOOL_NAMES = ("nasm", "gcc", "ld", "nm", "objcopy", "objdump")
STUB = SHZ / "kernel64/standalone"
FROZEN_GUARD = SHZ / "tests/test_sched_deadlines_k32.py"
FROZEN_GUARD_SHA256 = "8b7d3c6d3d5bacdebc54412dbe9bb8b744d5c3df4701556b787ca9bab98a97db"
SOURCE_SUFFIXES = {".c", ".h", ".asm", ".inc", ".ld", ".lds"}


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def source_bytes(path):
    """Read one bounded regular source inode; bind exactly the executed bytes."""
    safe_components(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 2 * 1024 * 1024:
            raise RuntimeError("unbounded/nonregular source input")
        data = bytearray()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            data.extend(block)
            if len(data) > 2 * 1024 * 1024:
                raise RuntimeError("source grew beyond its bounded read")
        after = os.fstat(fd)
        if (file_identity(before) != file_identity(after) or len(data) != after.st_size
                or file_identity(after) != file_identity(path.lstat())):
            raise RuntimeError("source inode/bytes changed during read")
        return bytes(data), {"sha256": hashlib.sha256(data).hexdigest(),
                             "identity": list(file_identity(after))}
    finally:
        os.close(fd)


def load_source_module(name, path, expected):
    data, binding = source_bytes(path)
    if binding != expected:
        raise RuntimeError("source module differs from its before-load binding")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("source module unavailable")
    module = importlib.util.module_from_spec(spec)
    # Do not let SourceFileLoader reread another inode or adopt cached bytecode.
    exec(compile(data, str(path), "exec", dont_inherit=True), module.__dict__)
    if Path(module.__file__).resolve() != path:
        raise RuntimeError("loaded module identity differs from the source closure")
    if source_bytes(path)[1] != expected:
        raise RuntimeError("source module changed while its bound buffer executed")
    return module


def safe_components(path):
    for component in (path, *path.parents):
        if component.is_symlink():
            raise RuntimeError("symlinked source/output path refused")


def admission():
    available = shutil.disk_usage(ROOT).free
    if available < RESERVE + LIMIT:
        raise RuntimeError(f"BLOCKED: available={available}, required={RESERVE + LIMIT}")
    return available


def source_paths():
    """Discover the actual build inputs again, including newly added sources."""
    paths = {SHZ / "kbuild.py", SHZ / "tools/shzlib.py", FROZEN_GUARD,
             Path(__file__).resolve(), STUB / "boot32.c", STUB / "boot_pm.asm",
             STUB / "boot.ld", STUB / "memholes.h"}
    for base in (SHZ / "kernel32", SHZ / "kcommon", SHZ / "abi"):
        safe_components(base)
        if not stat.S_ISDIR(base.lstat().st_mode):
            raise RuntimeError("required source directory unavailable")
        for directory, subdirs, files in os.walk(base, followlinks=False):
            for name in subdirs:
                path = Path(directory) / name
                if path.is_symlink():
                    raise RuntimeError("symlinked source directory refused")
            for name in files:
                path = Path(directory) / name
                if path.suffix.lower() in SOURCE_SUFFIXES:
                    paths.add(path)
    if len(paths) > 256:
        raise RuntimeError("source closure exceeded the bounded file count")
    return sorted(paths)


def snapshot():
    paths = source_paths()
    for path in paths:
        safe_components(path)
        if not path.is_relative_to(ROOT):
            raise RuntimeError("source closure escaped the own worktree")
    return {str(path.relative_to(ROOT)): source_bytes(path)[1]
            for path in paths}


class OutputChurn(RuntimeError):
    """Retry only ordinary directory-membership churn, never safety failures."""


class RecursiveGuard:
    """Latched recursive output accounting with held directory/regular FDs."""
    def __init__(self, output):
        self.output = output
        self.root_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root = os.fstat(self.root_fd)
        self.root_identity = (root.st_dev, root.st_ino)
        self.identities = {".": self.root_identity}
        self.failure = None
        self.minimum_free = shutil.disk_usage(ROOT).free
        self.peak = 0

    def close(self):
        os.close(self.root_fd)

    def pin(self, relative, info):
        # GCC may unlink and later reuse an ordinary temporary filename. Its
        # name/FD/type/nlink are checked in every sample, but that temporary
        # identity is not an artifact whose lifetime is pinned across samples.
        if relative.startswith("tmp/"):
            return
        inode = (info.st_dev, info.st_ino)
        old = self.identities.setdefault(relative, inode)
        if old != inode:
            raise RuntimeError("owned output path inode was replaced")

    def count(self):
        for attempt in range(4):
            available = shutil.disk_usage(ROOT).free
            self.minimum_free = min(self.minimum_free, available)
            if available < RESERVE:
                raise RuntimeError("20 GiB reserve crossed during recursive resnapshot")
            try:
                return self.stable_count()
            except OutputChurn:
                if attempt == 3:
                    raise RuntimeError("bounded stable output resnapshot exhausted")

    def stable_count(self):
        safe_components(self.output)
        named = self.output.lstat()
        held = os.fstat(self.root_fd)
        if (not stat.S_ISDIR(named.st_mode)
                or (named.st_dev, named.st_ino) != self.root_identity
                or (held.st_dev, held.st_ino) != self.root_identity):
            raise RuntimeError("owned build root/FD identity changed")
        total = 0
        entries = 0

        def walk(fd, relative, depth):
            nonlocal total, entries
            if depth > 8:
                raise RuntimeError("unexpected build output nesting")
            before_dir = os.fstat(fd)
            names = os.listdir(fd)
            for name in sorted(names):
                entries += 1
                if entries > 1024:
                    raise RuntimeError("bounded build output entry count exceeded")
                key = name if not relative else relative + "/" + name
                try:
                    named_entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError as error:
                    if key.startswith("tmp/"):
                        raise OutputChurn("ordinary compiler temporary disappeared") from error
                    raise
                if stat.S_ISDIR(named_entry.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        info = os.fstat(child)
                        if (info.st_dev, info.st_ino) != (named_entry.st_dev, named_entry.st_ino):
                            raise RuntimeError("output directory name/FD identity changed")
                        self.pin(key, info)
                        walk(child, key, depth + 1)
                        final = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if (final.st_dev, final.st_ino) != (info.st_dev, info.st_ino):
                            raise RuntimeError("output directory replaced during accounting")
                    finally:
                        os.close(child)
                elif stat.S_ISREG(named_entry.st_mode) and named_entry.st_nlink == 1:
                    try:
                        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    except FileNotFoundError as error:
                        if key.startswith("tmp/"):
                            raise OutputChurn("ordinary compiler temporary disappeared before open") from error
                        raise
                    try:
                        info = os.fstat(child)
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise RuntimeError("output regular-file name/FD identity changed")
                        if (info.st_dev, info.st_ino) != (named_entry.st_dev, named_entry.st_ino):
                            if key.startswith("tmp/"):
                                raise OutputChurn("ordinary temporary was replaced before open")
                            raise RuntimeError("output artifact name/FD identity changed")
                        self.pin(key, info)
                        total += info.st_size
                        self.peak = max(self.peak, total)
                        if total > LIMIT:
                            raise RuntimeError("aggregate sampled build output exceeded 8 MiB")
                        try:
                            final = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        except FileNotFoundError as error:
                            if key.startswith("tmp/"):
                                raise OutputChurn("ordinary compiler temporary disappeared after read") from error
                            raise
                        if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
                            raise RuntimeError("output file aliased/changed type during accounting")
                        if ((final.st_dev, final.st_ino) != (info.st_dev, info.st_ino)
                                or not stat.S_ISREG(final.st_mode) or final.st_nlink != 1):
                            if key.startswith("tmp/"):
                                raise OutputChurn("ordinary temporary replaced after read")
                            raise RuntimeError("output file replaced/aliased during accounting")
                    finally:
                        os.close(child)
                else:
                    raise RuntimeError("nonregular/symlink/hardlinked build output refused")
            after_dir = os.fstat(fd)
            if (after_dir.st_dev, after_dir.st_ino) != (before_dir.st_dev, before_dir.st_ino):
                raise RuntimeError("output directory FD identity changed during accounting")
            if (after_dir.st_mtime_ns != before_dir.st_mtime_ns
                    or after_dir.st_ctime_ns != before_dir.st_ctime_ns):
                raise OutputChurn("ordinary output membership changed during accounting")

        walk(self.root_fd, "", 0)
        if (self.output.lstat().st_dev, self.output.lstat().st_ino) != self.root_identity:
            raise RuntimeError("owned root replaced during recursive accounting")
        self.peak = max(self.peak, total)
        if total > LIMIT:
            raise RuntimeError("aggregate build output exceeded 8 MiB")
        return total

    def check(self, extra=0):
        try:
            available = shutil.disk_usage(ROOT).free
            self.minimum_free = min(self.minimum_free, available)
            if available < RESERVE:
                raise RuntimeError(f"20 GiB reserve crossed: available={available}")
            if self.count() + extra > LIMIT:
                raise RuntimeError("aggregate output plus pending write exceeded 8 MiB")
            if self.failure:
                raise RuntimeError(self.failure)
        except (OSError, RuntimeError) as error:
            self.failure = self.failure or str(error)
            raise

    def write(self, path, data):
        if path.parent != self.output:
            raise RuntimeError("capture write escaped the owned root")
        self.check(len(data))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise RuntimeError("unsafe capture FD")
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
            after = os.fstat(fd)
            named = path.lstat()
            if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                    or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino)
                    or after.st_nlink != 1 or named.st_nlink != 1 or after.st_size != len(data)):
                raise RuntimeError("capture FD/path changed during write")
            self.pin(path.name, after)
        finally:
            os.close(fd)
        self.check()


def read_owned(path, output, proof):
    if not path.is_relative_to(output):
        raise RuntimeError("artifact escaped the owned build root")
    safe_components(path)
    artifact = proof.hash_regular(path, maximum=LIMIT)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > LIMIT:
            raise RuntimeError("unsafe/unbounded actual build artifact")
        data = bytearray()
        while len(data) <= LIMIT:
            block = os.read(fd, min(65536, LIMIT + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if (len(data) != info.st_size or len(data) > LIMIT
                or hashlib.sha256(data).hexdigest() != artifact["sha256"]
                or proof.identity(info) != tuple(artifact["identity"])
                or proof.identity(os.fstat(fd)) != proof.identity(info)
                or proof.identity(path.lstat()) != proof.identity(info)):
            raise RuntimeError("actual build artifact changed during validation")
        return bytes(data), {"path": str(path), "bytes": len(data), **artifact}
    finally:
        os.close(fd)


def validate_elf32(data, *, multiboot=False):
    if len(data) < 52:
        raise RuntimeError("truncated ELF32 build artifact")
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
    if (ident[:7] != b"\x7fELF\x01\x01\x01" or kind != 2 or machine != 3
            or version != 1 or ehsize != 52 or phsize != 32 or not 1 <= phnum <= 128
            or phoff < ehsize or phoff + phsize * phnum > len(data)):
        raise RuntimeError("artifact is not a bounded little-endian i386 executable ELF32")
    if (shnum and (shsize != 40 or shoff < ehsize or shoff + shsize * shnum > len(data)
                   or shstr >= shnum)):
        raise RuntimeError("invalid ELF32 section table")
    executable_entry = False
    loads = 0
    for index in range(phnum):
        ptype, offset, vaddr, paddr, filesz, memsz, pflags, align = struct.unpack_from("<IIIIIIII", data, phoff + index * phsize)
        if ptype in (2, 3):
            raise RuntimeError("freestanding ELF unexpectedly needs a dynamic loader")
        if ptype == 1:
            loads += 1
            if (filesz > memsz or offset + filesz > len(data)
                    or vaddr + memsz > 1 << 32 or paddr + memsz > 1 << 32):
                raise RuntimeError("invalid ELF32 load segment")
            if pflags & 1 and vaddr <= entry < vaddr + filesz:
                executable_entry = True
    if not loads or not executable_entry:
        raise RuntimeError("ELF32 entry is not backed by an executable file segment")
    result = {"class": "ELF32", "machine": "EM_386", "type": "ET_EXEC",
              "entry": entry, "load_segments": loads, "dynamic_loader": False}
    if multiboot:
        matches = []
        for offset in range(0, min(len(data), 8192) - 11, 4):
            magic, mbflags, checksum = struct.unpack_from("<III", data, offset)
            if magic == 0x1BADB002 and mbflags == 3 and (magic + mbflags + checksum) & 0xffffffff == 0:
                matches.append(offset)
        if len(matches) != 1:
            raise RuntimeError("K32 stub lacks one valid aligned Multiboot 1 header in the first 8 KiB")
        result.update(multiboot_header_offset=matches[0], multiboot_flags=3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_root
    allowed = ROOT / "build/k32-build-6970"
    if (not output.is_absolute() or output.parent != allowed or output.exists()
            or output.name in ("", ".", "..") or output != Path(os.path.normpath(output))):
        raise SystemExit("output must be one NEW canonical absolute direct child of build/k32-build-6970")
    safe_components(output)
    if ROOT != ROOT.resolve() or sys.flags.optimize:
        raise SystemExit("canonical source root and non-optimized Python required")
    if not all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
        raise SystemExit("Linux nonreaping owned process-group observation required")
    try:
        available = admission()   # before mkdir, importing build modules or tool commands
    except RuntimeError as error:
        print(json.dumps({"result": "BLOCKED_NOT_RUN", "reason": str(error)}))
        return 3
    before = snapshot()
    guard_binding = before[str(FROZEN_GUARD.relative_to(ROOT))]
    if guard_binding["sha256"] != FROZEN_GUARD_SHA256:
        raise SystemExit("reviewed frozen HOST guard source hash changed")
    proof = load_source_module("k32_deadline_frozen_guard_6970", FROZEN_GUARD, guard_binding)
    # Reuse the reviewed self-inclusive writer, with this source-bound envelope's
    # explicit larger bounded metadata budget. Its source file stays unchanged.
    proof.RECEIPT_LIMIT = RECEIPT_LIMIT
    if snapshot() != before:
        raise SystemExit("source closure changed before output admission")
    admission()
    output.mkdir(parents=True, exist_ok=False)
    guard = RecursiveGuard(output)
    receipt = {"schema": "kernel32-freestanding-host-build-6970-v1", "result": "NOT_COMPLETED",
               "output_root": str(output), "reserve_bytes": RESERVE, "output_limit_bytes": LIMIT,
               "capture_limit_per_command_bytes": CAPTURE_LIMIT, "receipt_limit_bytes": RECEIPT_LIMIT,
               "available_before_bytes": available, "source_inputs": before,
               "source_hashes": {key: value["sha256"] for key, value in before.items()},
               "commands": [], "native_execution_verified": False,
               "windows98_integration_verified": False, "hardware_context_switch_verified": False,
               "deadline_behavior_verified": False, "guest_boot_verified": False,
               "scope": "actual unchanged kbuild K32 supervisor/standalone compilation and K32 Multiboot stub structure only"}
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
           "TMPDIR": str(output / "tmp"), "TMP": str(output / "tmp"),
           "TEMP": str(output / "tmp"), "PYTHONDONTWRITEBYTECODE": "1"}
    tools = {}
    tool_fds = {}
    nm_results = {}

    def tool_identity(name):
        info = tools[name]
        fd = tool_fds[name]
        held = os.fstat(fd)
        named = Path(info["path"]).lstat()
        if (not stat.S_ISREG(held.st_mode) or proof.identity(held) != tuple(info["identity"])
                or proof.identity(named) != proof.identity(held)):
            raise RuntimeError("pinned build tool FD/path identity changed")
        if proof.hash_regular(Path(info["path"])) != {"sha256": info["sha256"], "identity": info["identity"]}:
            raise RuntimeError("pinned actual build tool bytes changed")

    def run(command, cwd=None, env=None, timeout=300, capture=False, check=True):
        """kbuild-compatible capture; execute only six pinned tool roles."""
        original = [str(value) for value in command]
        if not original or original[0] not in TOOL_NAMES or original[0] not in tools:
            raise RuntimeError("unsupported tool dispatch from unchanged kbuild")
        if cwd is not None and Path(cwd) != ROOT:
            raise RuntimeError("build command cwd escaped the own source root")
        if env is not None or not check or not 0 < timeout <= 300:
            raise RuntimeError("unsupported kbuild environment/check/deadline override")
        name = original[0]
        tool_identity(name)
        admission()
        guard.check(PENDING)
        budget = LIMIT - guard.count() - PENDING
        argv = [tools[name]["path"], *original[1:]]
        label = f"command-{len(receipt['commands']):03d}-{name}"

        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (budget, budget))

        start = time.monotonic()
        child = subprocess.Popen(argv, executable=f"/proc/self/fd/{tool_fds[name]}",
                                 pass_fds=(tool_fds[name],), cwd=ROOT, env=clean_env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True, preexec_fn=limits)
        selector = selectors.DefaultSelector()
        chunks = {"stdout": bytearray(), "stderr": bytearray()}
        aborted = None
        group_kill = "NOT_REQUESTED"
        observed = False
        try:
            selector.register(child.stdout, selectors.EVENT_READ, "stdout")
            selector.register(child.stderr, selectors.EVENT_READ, "stderr")
            while True:
                status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                observed = bool(status and status.si_pid == child.pid)
                if observed and not selector.get_map():
                    break
                guard.check(PENDING)
                if time.monotonic() - start > timeout:
                    raise RuntimeError("bounded build subprocess timeout")
                for key, _ in selector.select(0.05):
                    block = os.read(key.fileobj.fileno(), 16384)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        chunks[key.data].extend(block)
                        if sum(map(len, chunks.values())) > CAPTURE_LIMIT:
                            raise RuntimeError("bounded build stdout/stderr capture exceeded")
            # Keep the leader unreaped while any abort could require killpg.
            guard.check(PENDING)
            child.wait(timeout=5)
        except BaseException as error:
            aborted = str(error)[:2048]
            try:
                os.killpg(child.pid, signal.SIGKILL)
                group_kill = "SIGKILL_SENT_TO_OWNED_GROUP"
            except ProcessLookupError:
                group_kill = "OWNED_GROUP_ALREADY_ABSENT"
            except OSError as kill_error:
                group_kill = "FAILED: " + str(kill_error)[:512]
            child.wait(timeout=5)
            if group_kill.startswith("FAILED:"):
                raise RuntimeError("owned build process-group teardown failed") from error
            raise
        finally:
            selector.close()
            child.stdout.close()
            child.stderr.close()
            receipt["commands"].append({"label": label, "argv": argv, "original_argv": original,
                                        "tool": name, "executable_binding": "OWN_READONLY_FD",
                                        "exit_code": child.returncode, "owned_pid": child.pid,
                                        "direct_child_reaped": child.returncode is not None,
                                        "nonreaping_exit_observed": observed, "owned_group_kill": group_kill,
                                        "aborted": aborted, "elapsed_seconds": time.monotonic() - start})
        guard.write(output / (label + ".stdout"), bytes(chunks["stdout"]))
        guard.write(output / (label + ".stderr"), bytes(chunks["stderr"]))
        tool_identity(name)
        if child.returncode:
            raise RuntimeError(f"actual {name} command failed: exit={child.returncode}, capture={label}")
        stdout = chunks["stdout"].decode("utf-8", errors="strict")
        stderr = chunks["stderr"].decode("utf-8", errors="strict")
        if name == "nm" and original[1:2] == ["-u"]:
            if stdout.strip() or stderr.strip():
                raise RuntimeError("actual nm -u did not prove absence of undefined symbols")
            nm_results[original[-1]] = {"command_label": label, "exit_code": 0,
                                        "undefined_symbols": [], "stderr_empty": True}
        # kbuild writes objdump stdout directly as disasm.txt next. Reserve the
        # extra copy as well as captures, then measure it after the build call.
        guard.check(len(chunks["stdout"]) + RECEIPT_LIMIT)
        return subprocess.CompletedProcess(argv, child.returncode,
                                           stdout if capture else None, stderr if capture else None)

    clean_env = env
    try:
        (output / "tmp").mkdir()
        guard.check(PENDING)
        for name in TOOL_NAMES:
            found = shutil.which(name, path=clean_env["PATH"])
            if not found:
                raise RuntimeError("required actual build tool unavailable: " + name)
            path = Path(found).resolve(strict=True)
            safe_components(path)
            info = proof.hash_regular(path)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            tool_fds[name] = fd
            if proof.identity(os.fstat(fd)) != tuple(info["identity"]):
                raise RuntimeError("build tool changed before its FD was pinned")
            tools[name] = {"path": str(path), **info}
            version = run([name, "--version"], timeout=20, capture=True)
            lines = version.stdout.splitlines()
            if not lines or not lines[0].strip():
                raise RuntimeError("actual build tool version query yielded no version")
            tools[name]["version"] = lines[0][:1024]
        receipt["tools"] = tools
        if "shzlib" in sys.modules:
            raise RuntimeError("stale preimported shzlib dependency refused")
        shzlib_path = SHZ / "tools/shzlib.py"
        shzlib = load_source_module("shzlib", shzlib_path, before[str(shzlib_path.relative_to(ROOT))])
        sys.modules["shzlib"] = shzlib
        kbuild_path = SHZ / "kbuild.py"
        kbuild = load_source_module("k32_deadlines_actual_kbuild_6970", kbuild_path,
                                    before[str(kbuild_path.relative_to(ROOT))])
        if (kbuild.REPO != ROOT or kbuild.SHZ != SHZ
                or Path(kbuild.shzlib.__file__).resolve() != SHZ / "tools/shzlib.py"):
            raise RuntimeError("actual kbuild/shzlib roots differ from frozen closure")
        if kbuild.shzlib is not shzlib or snapshot() != before:
            raise RuntimeError("source closure changed before actual builds")
        kbuild.BUILD = output
        kbuild.run = run

        def artifact_sha(path):
            guard.check()
            if not Path(path).is_relative_to(output):
                raise RuntimeError("kbuild hash request escaped the owned root")
            safe_components(Path(path))
            return proof.hash_regular(Path(path), maximum=LIMIT)["sha256"]

        kbuild.sha256_file = artifact_sha
        built = {}
        built["kernel32"] = kbuild.build_kernel("kernel32", "kernel32", kbuild.K32_FLAGS,
                                               "elf32", "elf_i386", "KERNEL32.BIN")
        guard.check(PENDING)
        if snapshot() != before:
            raise RuntimeError("source closure changed during supervisor K32 build")
        built["kernel32s"] = kbuild.build_kernel("kernel32s", "kernel32", kbuild.K32_FLAGS + ["-DSHZ_STANDALONE"],
                                                "elf32", "elf_i386", "KERNEL32S.BIN",
                                                extra_c=[SHZ / "kernel32/standalone/standalone32.c"])
        guard.check(PENDING)
        if snapshot() != before:
            raise RuntimeError("source closure changed during standalone K32 build")
        stub = kbuild.build_standalone_stub(k32=True)
        guard.check(PENDING)
        artifacts = {}
        for name, result in built.items():
            data, elf = read_owned(result["elf"], output, proof)
            elf["validation"] = validate_elf32(data)
            if str(result["elf"]) not in nm_results:
                raise RuntimeError("ELF lacks its actual successful nm -u proof")
            elf["nm_u"] = nm_results[str(result["elf"])]
            flat, binary = read_owned(result["bin"], output, proof)
            if (not flat or binary["bytes"] != result["bytes"]
                    or binary["sha256"] != result["sha256"] or elf["sha256"] != result["elf_sha256"]):
                raise RuntimeError("actual K32 artifact differs from kbuild result")
            artifacts[name] = {"elf": elf, "binary": binary}
        data, elf = read_owned(stub["elf"], output, proof)
        elf["validation"] = validate_elf32(data, multiboot=True)
        if (str(stub["elf"]) not in nm_results or elf["sha256"] != stub["sha256"]
                or elf["bytes"] != stub["bytes"]):
            raise RuntimeError("actual K32 stub lacks its bound build/nm proof")
        elf["nm_u"] = nm_results[str(stub["elf"])]
        artifacts["kernel32_multiboot_stub"] = {"elf": elf}
        receipt["artifacts"] = artifacts
        after = snapshot()
        receipt["source_inputs_after"] = after
        if before != after:
            raise RuntimeError("full recursive source closure changed during build proof")
        for name in tools:
            tool_identity(name)
        guard.check(RECEIPT_LIMIT)
        receipt["result"] = "PASS_FREESTANDING_K32_BUILD_ONLY"
    except BaseException as error:
        receipt.update(result="FAIL", error=str(error)[:4096])
        raise
    finally:
        try:
            proof.write_receipt(output, receipt, guard)
        finally:
            for fd in tool_fds.values():
                os.close(fd)
            guard.close()
    print(json.dumps({"result": receipt["result"], "receipt": str(output / "result.json")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
