#!/usr/bin/env python3
"""Execute host helper modules from their already verified source snapshots.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
This loader writes no bytecode or files and starts no subprocess. Standalone
engine tools use one bundle; modules are replaced only in their own process.
"""
import hashlib
import os
from pathlib import Path
import stat
import sys
import types

HERE = Path(__file__).resolve().parent
LIMIT = 1024 * 1024


def capture(path):
    path = Path(os.path.abspath(path))
    if path.resolve(strict=True) != path:
        raise ValueError("Helper source must not traverse symlinks: " + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= LIMIT:
            raise ValueError("Helper source is not a bounded regular file: " + str(path))
        pieces = []
        while True:
            piece = os.read(descriptor, 65536)
            if not piece:
                break
            pieces.append(piece)
            if sum(map(len, pieces)) > LIMIT:
                raise ValueError("Helper source exceeded its snapshot bound")
        after = os.fstat(descriptor)
        named = path.stat(follow_symlinks=False)
    finally:
        os.close(descriptor)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    if identity(before) != identity(after) or identity(named) != identity(after):
        raise ValueError("Helper source changed while being captured: " + str(path))
    data = b"".join(pieces)
    if len(data) != before.st_size:
        raise ValueError("Helper source snapshot length changed")
    return data, {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
                  "bytes": len(data)}, identity(after)


class ToolBundle:
    def __init__(self, sources):
        self.snapshots = {}
        self.modules = {}
        for name, path in sources:
            if name in self.snapshots:
                raise ValueError("Helper module name is ambiguous: " + name)
            self.snapshots[name] = capture(path)
        self.verify()

    @property
    def inputs(self):
        return [self.snapshots[name][1] for name in sorted(self.snapshots)]

    def verify(self):
        for name, module in self.modules.items():
            if sys.modules.get(name) is not module:
                raise ValueError("Loaded helper module identity changed: " + name)
        for data, row, identity in self.snapshots.values():
            current, pin, token = capture(Path(row["path"]))
            if current != data or pin != row or token != identity:
                raise ValueError("Loaded helper source changed: " + row["path"])

    def load(self, name):
        if name in self.modules:
            return self.modules[name]
        data, row, _ = self.snapshots[name]
        module = types.ModuleType(name)
        module.__file__ = row["path"]
        module.__package__ = ""
        # Every executed byte belongs to the earlier snapshot, even when a
        # Python module with this name was cached before this bundle existed.
        sys.modules[name] = module
        exec(compile(data, row["path"], "exec"), module.__dict__)
        self.modules[name] = module
        return module

    def load_all(self):
        for name in self.snapshots:
            self.load(name)
        if "app_preflight" in self.modules:
            # Preserve the real preparer's source and behavior while replacing
            # its late file reread with a fresh module from the pinned bytes.
            def load_preparer():
                data, row, _ = self.snapshots["app_preflight_ntw_prepare"]
                module = types.ModuleType("app_preflight_ntw_prepare")
                module.__file__ = row["path"]
                module.__package__ = ""
                exec(compile(data, row["path"], "exec"), module.__dict__)
                return module
            self.modules["app_preflight"]._load_preparer = load_preparer
        self.verify()
        return self.modules


def engine_bundle(*, builder=False, driver=False):
    # This order satisfies all local top-level imports. Dynamic profile and
    # audit imports subsequently resolve to these exact loaded module objects.
    sources = [
        ("core_tool_snapshot", HERE / "core_tool_snapshot.py"),
        ("scan_imports", HERE.parent / "scan_imports.py"),
        ("measure_pe_coverage", HERE.parent / "measure_pe_coverage.py"),
        ("app_preflight_ntw_prepare", HERE.parents[1] / "ntwin32/prepare.py"),
        ("app_preflight", HERE.parent / "app_preflight.py"),
        ("iewebkit_build_win98", HERE.parent / "iewebkit_build_win98.py"),
        ("core_archive_receipt", HERE / "core_archive_receipt.py"),
        ("core_jsc_profile_gate", HERE / "core_jsc_profile_gate.py"),
        ("core_link_wtf", HERE / "core_link_wtf.py"),
    ]
    if builder:
        sources.append(("core_build", HERE / "core_build.py"))
    if driver:
        sources.append(("core_link_driver_inputs", HERE / "core_link_driver_inputs.py"))
    bundle = ToolBundle(sources)
    bundle.load_all()
    return bundle
