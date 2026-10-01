#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual builder and GNU make/Watcom/NASM contract; no full kernel or VM."""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
BUILDER = Path(os.environ.get("SHZ_DOS_BUILDER", HERE / "source/shizukudos/dos16/build.py"))
WATCOM = Path(os.environ.get("SHZ_TEST_WATCOM", HERE / "watcom"))
CONFIG = "XNASM=nasm\nundefine XUPX\nALLCFLAGS=-DWIN31SUPPORT\nNASMFLAGS=-DWIN31SUPPORT\n"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def production_functions():
    pins = json.loads((HERE / "inputs.json").read_text())
    raw = BUILDER.read_bytes()
    assert hashlib.sha256(raw).hexdigest() in {pins["builder_sha256"], pins["candidate_builder_sha256"]}, "unreviewed builder source"
    tree = ast.parse(raw)
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"build_kernel", "main"}]
    assert len(functions) == 2
    namespace = {"__doc__": "bounded builder contract"}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(BUILDER), "exec"), namespace)
    return namespace


def compile_probe(tree, configuration):
    """The genuine parent makefile exports config into genuine Watcom rules."""
    for relative in json.loads((HERE / "inputs.json").read_text())["upstream_sha256"]:
        pins = json.loads((HERE / "inputs.json").read_text())["upstream_sha256"]
        assert sha(HERE / "upstream" / relative) == pins[relative], "changed upstream source"
        dst = tree / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(HERE / "upstream" / relative, dst)
    (tree / "config.mak").write_text(configuration)
    (tree / "shz-parent.mak").write_text("shz-contract:\n\tcd kernel && $(MAKE) -f shz-contract.mak shz-contract\n")
    (tree / "kernel/shz-contract.mak").write_text(
        '!include "../mkfiles/generic.mak"\n'
        'shz-contract:\n'
        '\t$(CC) $(CFLAGS) contract-c.c\n'
        '\t$(NASM) -D$(COMPILER) -f obj $(NASMFLAGS) contract-asm.asm\n'
    )
    (tree / "kernel/contract-c.c").write_text(
        '#include "portab.h"\n#include "win.h"\n'
        'typedef char startup_size_22[(sizeof(struct WinStartupInfo) == 22) ? 1 : -1];\n'
        'typedef char patch_size_14[(sizeof(struct WinPatchTable) == 14) ? 1 : -1];\n'
        'struct WinStartupInfo shz_contract_startup;\n'
    )
    text = (tree / "kernel/kernel.asm").read_text()
    start = text.index("%IFDEF WIN31SUPPORT")
    end = text.index("%ENDIF ; WIN31SUPPORT", start) + len("%ENDIF ; WIN31SUPPORT")
    excerpt = text[start:end]
    (tree / "kernel/contract-asm.asm").write_text(
        'segment _DATA public class=DATA use16\n'
        'extern _DATASTART, _markEndInstanceData, save_DS, save_BX\n'
        'extern _InDOS, _MachineId, _CritPatch, _uppermem_root\n'
        '%ifndef WIN31SUPPORT\n%error Missing_assembly_Windows_hooks\n%endif\n'
        + excerpt + '\n'
    )
    env = {"PATH": str(WATCOM / "binl64") + ":/usr/bin:/bin", "WATCOM": str(WATCOM), "LC_ALL": "C"}
    result = subprocess.run(["/usr/bin/make", "-f", "makefile", "-f", "shz-parent.mak", "shz-contract", "XCPU=386", "XFAT=32"],
                            cwd=tree, env=env, capture_output=True, text=True, timeout=30)
    for relative, digest in json.loads((HERE / "inputs.json").read_text())["upstream_sha256"].items():
        assert sha(tree / relative) == digest, "consumed source changed"
    return result


class BuilderContract(unittest.TestCase):
    def setUp(self):
        if shutil.disk_usage(HERE).free < 17 * 1024**3 + 4 * 1024**2:
            self.fail("17GiB floor unavailable")
        self.temp = tempfile.TemporaryDirectory(prefix="fixture-", dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tree = self.root / "freedos-kernel"
        (self.tree / "bin").mkdir(parents=True)
        (self.tree / "boot").mkdir()
        # Image boundaries are test doubles, not actual kernel outputs.
        for rel in ("bin/kernel.sys", "bin/sys.com", "boot/fat16com.bin"):
            (self.tree / rel).write_bytes(b"fixture-only")
        self.commands = []
        self.ns = production_functions()
        self.ns.update({"fresh_copy": lambda name: self.tree,
                        "PATCHES": [], "REPO": self.root, "sha256_file": sha,
                        "run": self.record})

    def record(self, command, **kwargs):
        self.commands.append((command, kwargs))

    def test_default_both_flags_and_actual_configuration_pin(self):
        result = self.ns["build_kernel"]({"fixture": "environment"})
        self.assertEqual((self.tree / "config.mak").read_text(), CONFIG)
        self.assertEqual(result.get("make_config"), {
            "text": CONFIG, "sha256": sha(self.tree / "config.mak"),
            "c_defines": ["WIN31SUPPORT"], "nasm_defines": ["WIN31SUPPORT"]})
        self.assertEqual(self.commands[0][0], ["make", "all", "XCPU=386", "XFAT=32"])
        self.assertEqual(self.commands[0][1]["env"], {"fixture": "environment"})

    def test_actual_default_config_reaches_real_watcom_and_nasm(self):
        self.ns["build_kernel"]({})
        result = compile_probe(self.tree, (self.tree / "config.mak").read_text())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("-DWIN31SUPPORT"), 2, result.stdout)
        self.assertIn("wcc", result.stdout)
        self.assertIn("nasm", result.stdout)
        self.assertIn("_winStartupInfo", (self.tree / "kernel/contract-asm.obj").read_bytes().decode("latin1"))
        self.assertIn("shz_contract_startup", (self.tree / "kernel/contract-c.obj").read_bytes().decode("latin1"))

    def test_missing_c_definition_is_rejected_by_real_header_compilation(self):
        result = compile_probe(self.tree, CONFIG.replace("ALLCFLAGS=-DWIN31SUPPORT\n", ""))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("WinStartupInfo", result.stdout + result.stderr)

    def test_missing_assembly_definition_is_rejected_by_real_nasm(self):
        result = compile_probe(self.tree, CONFIG.replace("NASMFLAGS=-DWIN31SUPPORT\n", ""))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Missing_assembly_Windows_hooks", result.stdout + result.stderr)

    def test_compilation_configuration_drift_is_rejected(self):
        def mutate(command, **kwargs):
            (self.tree / "config.mak").write_text("XNASM=nasm\n")
        self.ns["run"] = mutate
        with self.assertRaisesRegex(RuntimeError, "configuration changed"):
            self.ns["build_kernel"]({})

    def test_production_main_copies_exact_kernel_provenance_into_receipt(self):
        kernel = self.ns["build_kernel"]({})
        file = self.tree / "bin/kernel.sys"
        saved = []
        shz = SimpleNamespace(ow_env=lambda: {}, open_watcom_snapshot=lambda: ("snapshot", "snapshot"),
            load_manifest=lambda: {"upstreams": {}}, utc_now=lambda: "fixture", git_state=lambda: {},
            tool_version=lambda *a: "fixture", write_json=lambda path, value: saved.append(value))
        self.ns.update({"OUT": self.root / "out", "shzlib": shz,
            "argparse": SimpleNamespace(ArgumentParser=lambda **kwargs: SimpleNamespace(parse_args=lambda: None)),
            "build_kernel": lambda env: kernel, "build_freecom": lambda env: {"command": file, "patches": [], "commands": []},
            "build_tests": lambda env: ({}, []), "assemble_image": lambda *a: file,
            "ensure_csmwrap": lambda: (file, {"upstream": {"csmwrap": {"commit": "fixture"}}}),
            "assemble_dual": lambda *a: file, "assemble_user": lambda *a: (file, {"commands": []}),
            "shutil": shutil, "json": json,
            "fatimg": SimpleNamespace(partition_spec=lambda a: a, listing=lambda *a: "fixture")})
        with contextlib.redirect_stdout(io.StringIO()):
            self.ns["main"]()
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0].get("kernel_make_config"), kernel.get("make_config"))
        self.assertIsNotNone(saved[0].get("kernel_make_config"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
