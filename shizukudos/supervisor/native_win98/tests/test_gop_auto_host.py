#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile verbatim production loader bodies with EFI/boot boundary doubles.

The complete EFI entry, Kernel64 boot/refusal/release functions, preparation
reset and GOP selection block come from loader.c at run time. No fallback
decision is recreated here. Generated files, binary, logs and receipt remain
under the ignored build directory; no VM, devices or network are used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
LOADER = REPO / "shizukudos/supervisor/loader/loader.c"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def balanced_block(source, start):
    """Locate C braces while respecting comments, character and string literals."""
    depth = 0
    i = start
    quote = None
    while i < len(source):
        c = source[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end < 0:
                raise ValueError("Unterminated C comment")
            i = end + 2
            continue
        elif source.startswith("//", i):
            end = source.find("\n", i + 2)
            i = len(source) if end < 0 else end
            continue
        elif c in ('"', "'"):
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("Unterminated C block")


def function(source, name):
    matches = list(re.finditer(
        r"(?m)^(?:static )?(?:EFI_STATUS EFIAPI|EFI_STATUS|void) " +
        re.escape(name) + r"\([^\n]*\)\n\{", source))
    if len(matches) != 1:
        raise ValueError(f"Expected one complete production body for {name}")
    match = matches[0]
    brace = source.index("{", match.start())
    return source[match.start():balanced_block(source, brace)]


def generate(source, out):
    state = re.findall(r"typedef struct \{[^}]*\} k64_state_t;", source)
    if len(state) != 1:
        raise ValueError("Expected one production Kernel64 state declaration")
    constants = re.findall(r"(?m)^#define (?:K64_[A-Z_]+|GUEST_RAM_MIB) .*$", source)
    (out / "gop_auto_state.inc").write_text(
        "\n".join(constants) + "\n" + state[0] + "\nstatic k64_state_t g_k64;\n")
    # Physical preparation is mocked, but its actual state reset and display
    # block must run so neither setting nor erasing the fatal flag is simulated.
    prepare = function(source, "k64_prepare")
    reset = re.findall(r"(?m)^    zero\(&g_k64, sizeof g_k64\);$", prepare)
    if len(reset) != 1:
        raise ValueError("Expected one production preparation reset")
    (out / "gop_auto_reset.inc").write_text(reset[0] + "\n")
    marker = "    if (!EFI_ERROR(bs->locate_protocol(&gop_guid, 0, (void **)&gop)) && gop) {"
    if prepare.count(marker) != 1:
        raise ValueError("Expected one complete production Kernel64 GOP stage")
    start = prepare.index(marker)
    brace = prepare.index("{", start)
    stage = prepare[start:balanced_block(prepare, brace)]
    wrapper = """static EFI_STATUS prepare_display_stage(EFI_BOOT_SERVICES *bs)
{
    EFI_GOP *gop = 0;
    SD_FRAMEBUFFER fb;
    SD_GOP_SELECTION gop_selection;
    EFI_STATUS status;
    shz_bootinfo_t info = {0}, *bi = &info;
""" + stage + "\n    return EFI_SUCCESS;\n}\n"
    functions = [function(source, name) for name in
                 ("zero", "k64_release", "k64_refuse", "k64_boot", "efi_main")]
    ap_boundary = '''#include "shizukudos/supervisor/loader/ap_prepare.h"
/* These no-VMX AUTO cases must never reach AP allocation/startup. Config
 * validation links its actual production contract; only unused AP firmware
 * preparation is replaced with an explicit unexpected-call failure. */
EFI_STATUS shz_ap_prepare(EFI_BOOT_SERVICES *bs, uint64_t rsdp, const shz_ap_config_t *config,
                           uint64_t *address, uint64_t *bytes)
{
    (void)bs; (void)rsdp; (void)config; (void)address; (void)bytes;
    CHECK(0 && "unexpected AP preparation in no-VMX AUTO case");
    return EFI_ABORTED;
}
'''
    (out / "gop_auto_production.inc").write_text(ap_boundary + "\n\n".join(functions[:-1]) +
                                               "\n\n" + wrapper + "\n" + functions[-1] + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--out", type=Path, default=REPO / "build/pma-fd5c-gop-auto")
    args = parser.parse_args()
    cc = shutil.which(args.cc)
    if cc is None:
        raise SystemExit(f"Existing compiler required: {args.cc}")
    cc = str(Path(cc).resolve())
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    result_path = out / "result.json"
    result_path.unlink(missing_ok=True)
    loader_hash = digest(LOADER)
    generate(LOADER.read_text(), out)
    flags = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fno-omit-frame-pointer", "-I", str(REPO), "-I", str(out)]
    if args.sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    fixture = HERE / "gop_auto_host.c"
    contract = REPO / "shizukudos/supervisor/src/ap_contract.c"
    paths = {LOADER, Path(__file__).resolve()}
    for unit in (fixture, contract):
        dependencies = subprocess.run([cc, *flags, "-MM", "-MT", "fixture", str(unit)],
                                      check=True, capture_output=True, text=True, timeout=60)
        paths.update(Path(token).resolve() for token in
                     shlex.split(dependencies.stdout.replace("\\\n", " ").split(":", 1)[1]))
    before = {str(p.relative_to(REPO)): digest(p) for p in sorted(paths)}
    if digest(LOADER) != loader_hash:
        raise SystemExit("Loader changed during extraction")
    compiler_hash = digest(Path(cc))
    binary = out / "gop-auto-host"
    command = [cc, *flags, str(fixture), str(contract), "-o", str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True, timeout=60)
    log = compiled.stdout + compiled.stderr
    receipt = {"scope": "actual loader AUTO caller with EFI/selector/physical boot boundary mocks; real AP config contract, fail-fast unused AP preparation",
               "pass": False, "compiler": cc, "compiler_sha256": compiler_hash,
               "sanitize": args.sanitize, "compile_command": command,
               "compile_returncode": compiled.returncode, "sources_sha256": before}
    if compiled.returncode == 0:
        receipt["binary_sha256"] = digest(binary)
        tested = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
        log += tested.stdout + tested.stderr
        receipt["test_returncode"] = tested.returncode
        receipt["binary_unchanged"] = digest(binary) == receipt["binary_sha256"]
        receipt["pass"] = tested.returncode == 0 and not tested.stderr and receipt["binary_unchanged"]
    after = {str(p.relative_to(REPO)): digest(p) for p in sorted(paths)}
    receipt["sources_sha256_after"] = after
    receipt["sources_unchanged"] = before == after
    receipt["compiler_unchanged"] = compiler_hash == digest(Path(cc))
    receipt["pass"] &= receipt["sources_unchanged"] and receipt["compiler_unchanged"]
    (out / "host.log").write_text(log)
    result_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(log, end="")
    if not receipt["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
