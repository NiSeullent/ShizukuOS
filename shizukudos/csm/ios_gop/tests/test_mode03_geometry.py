#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Host-only tests of the optional patch against pinned open-source fixtures.

Requires a host C compiler and git. All patch application, compiler outputs,
and test execution are confined to a TemporaryDirectory; no guest, firmware
build, source checkout change, network, or privileged device access occurs.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1]
PATCH = MODULE / "patches/0001-legacy-gop-mode03-text-geometry.patch"
FIXTURES = MODULE / "tests/fixtures"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(source, name):
    """Select a complete actual fixture function, keeping its existing body."""
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", source)
    if not match:
        raise AssertionError(f"missing source function {name}")
    depth = 0
    for end in range(match.end() - 1, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if depth == 0:
            return source[match.start():end + 1]
    raise AssertionError(f"unclosed source function {name}")


class Mode03HostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="shz-mode03-host-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.tree = cls.work / "upstream"
        shutil.copytree(FIXTURES, cls.tree)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or not shutil.which(compiler[0]) or not shutil.which("git"):
            raise RuntimeError("host C compiler (CC) and git are required; no test was performed")
        for command in (["git", "apply", "--check", str(PATCH)], ["git", "apply", str(PATCH)]):
            result = subprocess.run(command, cwd=cls.tree, capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(f"host fixture patch application failed: {result.stdout}{result.stderr}")
        cls.compiler = compiler

    def test_patch_and_open_source_fixtures_match_the_recorded_lineage(self):
        manifest = json.loads((MODULE / "source-lineage.json").read_text())
        self.assertEqual(manifest["csmwrap_commit"], "7f30b740c352ee952eb596bf10ae263a8a5da4c7")
        self.assertEqual(sha(PATCH), manifest["patch_sha256"])
        self.assertEqual(sha(MODULE / "legacy_text_geometry.h"), manifest["helper_sha256"])
        for relative, expected in manifest["host_fixture_sha256"].items():
            with self.subTest(fixture=relative):
                self.assertEqual(sha(MODULE / relative), expected)
        self.assertEqual((self.tree / "seabios/vgasrc/shz_legacy_text_geometry.h").read_bytes(),
                         (MODULE / "legacy_text_geometry.h").read_bytes())

    def test_actual_patched_functions_preserve_native_mode_and_fix_legacy_mode03(self):
        cb = (self.tree / "seabios/vgasrc/cbvga.c").read_text()
        vg = (self.tree / "seabios/vgasrc/vgabios.c").read_text()
        pieces = [
            "int\n" + function(cb, "shz_cbvga_is_legacy_text_mode"),
            "struct vgamode_s *\n" + function(cb, "cbvga_find_mode"),
            "int\n" + function(cb, "cbvga_set_mode"),
            "void\n" + function(cb, "cbvga_setup_modes"),
            "int\n" + function(cb, "cbvga_setup"),
            "u16\n" + function(vg, "calc_page_size"),
            "int\n" + function(vg, "vga_set_mode"),
            "static void\n" + function(vg, "handle_100f"),
        ]
        (self.work / "mode03-functions.inc").write_text("\n\n".join(pieces) + "\n")
        output = self.work / "mode03-host"
        compile_result = subprocess.run([
            *self.compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-Wno-pointer-to-int-cast", "-I", str(self.work), "-I", str(self.tree / "seabios/vgasrc"),
            str(MODULE / "tests/test_mode03_host.c"), "-o", str(output),
        ], capture_output=True, text=True, timeout=60)
        self.assertEqual(compile_result.returncode, 0, compile_result.stdout + compile_result.stderr)
        result = subprocess.run([str(output)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: geometry bounds, patched mode03/BDA", result.stdout)

    def test_patch_does_not_change_native_vbe_geometry_or_framebuffer_storage(self):
        before = (FIXTURES / "seabios/vgasrc/cbvga.c").read_text()
        after = (self.tree / "seabios/vgasrc/cbvga.c").read_text()
        # Native mode creation owns address, memory size, pitch and VBE list.
        # Keep that entire production function byte-identical in this patch.
        self.assertEqual(function(before, "cbvga_setup_modes"), function(after, "cbvga_setup_modes"))
        self.assertEqual(function(before, "cbvga_find_mode"), function(after, "cbvga_find_mode"))
        self.assertEqual(function(before, "cbvga_set_mode"), function(after, "cbvga_set_mode"))


if __name__ == "__main__":
    unittest.main()
