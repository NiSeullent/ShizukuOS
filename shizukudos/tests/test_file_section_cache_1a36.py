#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual section/cache/view bodies; no kernel image, app, or guest."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "shizukudos/kernel64/ipc_section.c"
FIXTURE = Path(__file__).with_suffix(".c")
OUTPUT_LIMIT = 16 << 20

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_union(paths):
    """Pin local quoted includes without executing a project build script."""
    found = set()
    pending = list(paths)
    while pending:
        path = pending.pop().resolve()
        if path in found:
            continue
        if not path.is_relative_to(ROOT) or not path.is_file():
            raise ValueError("source pin must be a repository file")
        found.add(path)
        if path.suffix not in (".c", ".h"):
            continue
        for name in re.findall(r'^\s*#include\s+"([^"\n]+)"', path.read_text(), re.MULTILINE):
            choices = [path.parent / name, ROOT / "shizukudos" / name,
                       ROOT / "shizukudos/kernel64" / name, ROOT / name]
            header = next((p for p in choices if p.is_file()), None)
            if header is None:
                raise ValueError("quoted include absent: " + name)
            pending.append(header)
    return sorted(found)

def extract(source):
    declarations = source[source.index("typedef struct {"):source.index("static int section_security_read")]
    pages = source[source.index("/* ---------------------------------------------------------------- section pages"):source.index("/* ---------------------------------------------------------------- views")]
    views = source[source.index("/* ---------------------------------------------------------------- views"):source.index("/* Process teardown:")]
    return declarations + pages + views

def run(command, out, label, env=None):
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT // 2, OUTPUT_LIMIT // 2))
    log = out / (label + ".log")
    with log.open("wb") as stream:
        result = subprocess.run([str(p) for p in command], stdout=stream, stderr=subprocess.STDOUT,
                                timeout=60, env=env, preexec_fn=limits)
    data = log.read_bytes()
    if sum(p.stat().st_size for p in out.iterdir() if p.is_file()) > OUTPUT_LIMIT:
        raise RuntimeError("owned host output exceeds 16 MiB budget")
    return {"command": [str(p) for p in command], "returncode": result.returncode,
            "log_sha256": hashlib.sha256(data).hexdigest(), "summary": data.decode(errors="replace").splitlines()[-1:]}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--expect-red", action="store_true")
    parser.add_argument("--compile-unit", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "build") or out.exists():
        parser.error("new owned repository build output required")
    out.mkdir(parents=True)
    paths = source_union([args.source.resolve(), FIXTURE, Path(__file__).resolve(), ROOT / "shizukudos/kbuild.py"])
    before = {str(p.relative_to(ROOT)): digest(p) for p in paths}
    source = args.source.read_text()
    (out / "production-bodies.c").write_text(extract(source))
    combined = FIXTURE.read_text().replace("/* PRODUCTION_BODIES */", extract(source))
    (out / "fixture.c").write_text(combined)
    actions = []
    for compiler, flags, name in [("gcc", [], "gcc"), ("clang", [], "clang"),
                                  ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"], "clang-sanitized")]:
        binary = out / name
        action = run([compiler, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-pthread", *flags,
                      out / "fixture.c", "-o", binary], out, name + "-compile")
        actions.append(action)
        if action["returncode"]:
            break
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
        actions.append(run([binary], out, name + "-run", env))
    if args.compile_unit:
        tree = ast.parse((ROOT / "shizukudos/kbuild.py").read_text())
        flags = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == "K64_FLAGS" for t in node.targets))
        for compiler in ("gcc", "clang"):
            selected = [f for f in flags if compiler != "clang" or f != "-fno-tree-loop-distribute-patterns"]
            for profile, extra in [("supervisor", []), ("standalone", ["-DSHZ_STANDALONE"] )]:
                actions.append(run([compiler, *selected, *extra, "-I", ROOT / "shizukudos", "-I", ROOT / "shizukudos/kernel64",
                                    "-MMD", "-MF", out / (compiler + "-" + profile + ".d"),
                                    "-c", args.source.resolve(), "-o", out / (compiler + "-" + profile + ".o")],
                                   out, compiler + "-" + profile))
        for deps in out.glob("*.d"):
            dependencies = deps.read_text().replace("\\\n", " ").split(":", 1)[1].split()
            if any(Path(p).resolve() not in paths for p in dependencies):
                raise RuntimeError("actual compiler dependency outside pinned source union")
    after = {str(p.relative_to(ROOT)): digest(p) for p in paths}
    executions = [a for a in actions if len(a["command"]) == 1]
    compiles = [a for a in actions if len(a["command"]) != 1]
    expected = 1 if args.expect_red else 0
    controlled = len(executions) == 3 and all(a["returncode"] == expected and a["summary"] and
                                               re.fullmatch(r"file-section production: checks=\d+ failures=\d+ reads=\d+ writes=\d+ live_pages=0 live_heap=0", a["summary"][0])
                                               for a in executions)
    success = controlled and all(a["returncode"] == 0 for a in compiles) and before == after
    result = {"status": "EXPECTED_BASELINE_RED" if success and args.expect_red else "PASS" if success else "FAIL",
              "scope": "actual extracted production page/free/view functions; allocator/VFS/object/page-table/IRQ boundaries modeled; no app/kernel/Win98/VM acceptance",
              "source_hashes": before, "sources_stable": before == after, "actions": actions,
              "host_output_bytes": sum(p.stat().st_size for p in out.iterdir() if p.is_file()),
              "guest_executed": False, "app_functionality_verified": False}
    (out / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("status", "sources_stable", "host_output_bytes")}))
    return 0 if success else 1

if __name__ == "__main__":
    raise SystemExit(main())
