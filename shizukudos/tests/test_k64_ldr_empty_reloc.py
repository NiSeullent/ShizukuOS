#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exact loader mapping bodies and real PE parser at controlled host boundaries."""
import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
LDR = REPO / "shizukudos/kernel64/ldr.c"
PE = REPO / "shizukudos/win64/pe_parse.c"
FIXTURE = HERE / "test_k64_ldr_empty_reloc.c"
FUNCTIONS = ("scopy", "fail", "kwrite", "prot_from_section", "census_cb", "boot_base_key", "boot_base_get",
             "boot_base_put", "aslr_pick", "block_cmp_less", "build_reloc_index", "image_orig", "relocate_page",
             "image_metadata_free", "ldr_image_fault", "reloc_page", "map_bytes", "map_range", "map_module")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def extract(source, name):
    match = re.search(r"^(?:static )?[^\n;{}]*\b" + re.escape(name) + r"\([^;]*?\)\s*\{", source, re.M)
    if not match:
        raise ValueError(f"missing production body {name}")
    start = source.index("{", match.start())
    # Ignore braces inside comments and strings while preserving all source bytes.
    tokens = re.finditer(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', source[start:])
    depth = 0
    for token in tokens:
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():start + token.end()] + "\n"
    raise ValueError(f"unterminated production body {name}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    out = args.out.resolve()
    if out.exists():
        ap.error("choose a fresh output directory to preserve earlier evidence")
    out.mkdir(parents=True)
    source_bytes = LDR.read_bytes()
    source = source_bytes.decode()
    bodies = {name: extract(source, name) for name in FUNCTIONS}
    types = source[source.index("typedef struct { uint32_t page, count;"):source.index("static void image_metadata_free")]
    types += source[source.index("typedef struct {\n    int set;"):source.index("static char lower")]
    types += source[source.index("struct reloc_census {"):source.index("static int census_cb")]
    types += source[source.index("#define BOOT_BASES"):source.index("static uint64_t boot_base_key")]
    types += source[source.index("struct page_ctx {"):source.index("static uint8_t *reloc_page")]
    types = "#define PATH_CAP 256\n#define PE_CHAR_RELOCS_STRIPPED 0x0001\n#define PE_CHAR_LARGE_ADDRESS_AWARE 0x0020\n" + types
    generated = {out / "ldr_empty_types.inc": types.encode(),
                 out / "ldr_empty_production.inc": "\n".join(bodies.values()).encode()}
    for path, data in generated.items():
        path.write_bytes(data)
    records, scans, before, after, compilers = [], [], {}, {}, {}
    okay = True
    for name, flags in (("gcc", ["-O2"]), ("clang", ["-O1", "-g", "-fsanitize=address,undefined",
                                                  "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"])):
        cc = shutil.which(name)
        if not cc:
            raise RuntimeError(f"compiler unavailable: {name}")
        cc = str(Path(cc).resolve())
        compilers[name] = {"path": cc, "sha256": sha(Path(cc).read_bytes())}
        common = [cc, *flags, "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-I", str(out)]
        binary = out / f"loader-{name}"

        def snapshot(phase):
            paths = {LDR, Path(__file__).resolve(), *generated}
            for unit in (FIXTURE, PE):
                command = [*common, "-MM", "-MT", "loader", str(unit)]
                result = subprocess.run(command, capture_output=True, timeout=60)
                (out / f"dependencies-{name}-{unit.stem}-{phase}.log").write_bytes(result.stdout + result.stderr)
                scans.append({"command": command, "exit": result.returncode})
                if result.returncode:
                    raise RuntimeError("dependency discovery failed")
                body = result.stdout.decode().replace("\\\n", "").split(":", 1)[1]
                paths.update(Path(p).resolve() for p in shlex.split(body))
            values = {}
            for path in sorted(paths):
                if not (path.is_relative_to(REPO) or path.is_relative_to(out)):
                    continue
                data = path.read_bytes()
                values[str(path)] = sha(data)
                if phase == "before":
                    relative = path.relative_to(out) if path.is_relative_to(out) else path.relative_to(REPO)
                    saved = out / "source-snapshot" / relative
                    saved.parent.mkdir(parents=True, exist_ok=True)
                    if saved.exists() and saved.read_bytes() != data:
                        raise RuntimeError("source epoch changed between compiler profiles")
                    if not saved.exists():
                        saved.write_bytes(data)
            return values

        before[name] = snapshot("before")
        if before[name][str(LDR)] != sha(source_bytes):
            raise RuntimeError("loader changed after extraction")
        for label, command in (("compile", [*common, str(FIXTURE), str(PE), "-o", str(binary)]),
                               ("run", [str(binary)])):
            if label == "run" and records[-1]["exit"]:
                okay = False
                break
            binary_before = sha(binary.read_bytes()) if label == "run" else None
            try:
                result = subprocess.run(command, capture_output=True, timeout=60)
                row = {"command": command, "exit": result.returncode, "timed_out": False}
                log = result.stdout + result.stderr
            except subprocess.TimeoutExpired as error:
                row = {"command": command, "exit": None, "timed_out": True}
                log = (error.stdout or b"") + (error.stderr or b"")
            (out / f"{name}-{label}.log").write_bytes(log)
            records.append(row)
            okay &= row["exit"] == 0 and not row["timed_out"]
            print(log.decode(errors="replace"), end="")
            if label == "run" and binary.is_file():
                row["binary_sha256"] = binary_before
                row["binary_sha256_after"] = sha(binary.read_bytes())
                row["binary_stable"] = row["binary_sha256"] == row["binary_sha256_after"]
                okay &= row["binary_stable"]
        after[name] = snapshot("after")
        okay &= before[name] == after[name] and sha(Path(cc).read_bytes()) == compilers[name]["sha256"]
    okay &= before["gcc"] == before["clang"]
    receipt = {"status": "PASS" if okay else "FAIL", "scope": "host production mapping/parser; no guest, VM or Windows VMM proof",
               "production_ldr_sha256": sha(source_bytes), "production_body_sha256": {k: sha(v.encode()) for k, v in bodies.items()},
               "sources_sha256": before, "sources_sha256_after": after, "compilers": compilers,
               "dependency_scans": scans, "commands": records, "qemu_used": False}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(receipt["status"])
    return 0 if okay else 1


if __name__ == "__main__":
    raise SystemExit(main())
