#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Inspect all PE executable bytes with a fail-closed i486/x87 instruction gate.

The gate covers the linked artifact, including compiler/runtime helpers. It is
not a Windows execution or imported-system-DLL CPU compatibility test.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

import pefile

# Explicit legacy user-mode instruction names; no modern family wildcard.
INTEGER = set("""adc add and bsf bsr bswap bt btc btr bts call cbw cdq clc cld
cmc cmp cmpxchg cwd cwde daa das dec div enter idiv imul inc int int3 into
ja jae jb jbe jcxz je jecxz jg jge jl jle jmp jne jno jnp jns jo jp js
lahf lea leave loop loope loopne mov movsx movzx mul neg nop not or pop
popa popad popf popfd push pusha pushad pushf pushfd rcl rcr ret rol ror
sahf sal sar sbb seta setae setb setbe sete setg setge setl setle setne
setno setnp setns seto setp sets shl shld shr shrd stc std sub test xadd
xchg xlat xor movs cmps lods scas stos movsb movsw movsl cmpsb cmpsw cmpsl lodsb lodsw lodsl
scasb scasw scasl stosb stosw stosl movsbl movsbw movswl movzbl movzbw
movzwl cwtl cltd lret""".split())
FPU = set("""f2xm1 fabs fadd faddp fbld fbstp fchs fclex fcom fcomp fcompp
fcos fdecstp fdiv fdivp fdivr fdivrp ffree fiadd ficom ficomp fidiv fidivr
fild fimul fincstp finit fist fistp fisub fisubr fld fld1 fldcw fldenv
fldl2e fldl2t fldlg2 fldln2 fldpi fldz fmul fmulp fnclex fninit fnop
fnsave fnstcw fnstenv fnstsw fpatan fprem fprem1 fptan frndint frstor
fsave fscale fsin fsincos fsqrt fst fstp fstcw fstenv fstsw fsub fsubp
fsubr fsubrp ftst fucom fucomp fucompp fwait fxam fxch fxtract fyl2x
fyl2xp1 wait""".split())
SIZED = set("""adc add and bsf bsr bt btc btr bts call cmp dec div idiv imul
inc jmp lea mov mul neg not or pop push rcl rcr ret rol ror sal sar sbb
shl shld shr shrd sub test xadd xchg xor""".split())
PREFIXES = {"lock", "rep", "repe", "repz", "repne", "repnz", "data16",
            "addr16", "cs", "ds", "es", "fs", "gs", "ss"}
BYTE_PREFIXES = {0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e,
                 0x26, 0x64, 0x65}
ALLOWED = INTEGER | FPU | {root + suffix for root in SIZED for suffix in "bwl"} | \
    {root + suffix for root in FPU for suffix in ("s", "l", "t", "ll")}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def acceptable(name, operands, raw):
    while name in PREFIXES:
        pieces = operands.split(None, 1)
        if not pieces:
            return False
        name, operands = pieces[0], pieces[1] if len(pieces) == 2 else ""
    legal = name in ALLOWED
    if not legal or re.search(r"%(?:[xyz]mm\d+|mm\d+)\b", operands):
        return False
    opcode = bytes(raw)
    while opcode and opcode[0] in BYTE_PREFIXES:
        opcode = opcode[1:]
    # Multi-byte NOP 0F 1F is P6-era despite objdump calling it "nop".
    if name.startswith("nop") and opcode != b"\x90":
        return False
    return True


def inspect_decode(disassembly, sections):
    offsets = {name: 0 for name in sections}
    seen, errors, bad, count, current = set(), [], [], 0, None
    symbol = None
    if not 0 < len(disassembly) <= 16 * 1024 * 1024:
        raise ValueError("bounded nonempty decode required")
    row_pattern = re.compile(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(\S+)(?:[ \t]+(.*))?")
    for line in disassembly.splitlines():
        header = re.fullmatch(r"Disassembly of section ([^ :\t]+):", line)
        if header:
            current = header[1]
            symbol = None
            if current in seen or current not in sections:
                errors.append("unexpected/duplicate section " + current)
            seen.add(current)
            continue
        label = re.fullmatch(r"[0-9a-f]+ <(.+)>:", line)
        if label:
            symbol = label[1]
            continue
        if not re.match(r"\s*[0-9a-f]+:", line):
            continue
        match = row_pattern.fullmatch(line)
        if not match or current not in sections:
            errors.append("malformed/outside instruction row " + line[:160])
            continue
        address, byte_text, name, operands = match.groups()
        raw = bytes.fromhex(byte_text)
        address = int(address, 16)
        section, offset = sections[current], offsets[current]
        if not 1 <= len(raw) <= 15 or address != section["address"] + offset or \
                section["bytes"][offset:offset + len(raw)] != raw:
            errors.append("byte/address gap or mismatch at " + hex(address))
        offsets[current] += len(raw)
        count += 1
        if not acceptable(name, operands or "", raw):
            bad.append({"section": current, "address": address, "raw": raw.hex(),
                        "mnemonic": name, "operands": operands or "", "symbol": symbol})
    if seen != set(sections) or any(offsets[n] != len(v["bytes"]) for n, v in sections.items()):
        errors.append("incomplete declared executable-section coverage")
    if not count:
        errors.append("no decoded instructions")
    return {"status": "PASS" if not errors and not bad else "FAIL",
            "instructions": count, "coverage_errors": errors[:20],
            "non_i486_instruction_count": len(bad), "non_i486_instructions": bad[:32],
            "sections": {n: {"address": v["address"], "bytes": len(v["bytes"]),
                              "sha256": digest(v["bytes"]), "decoded_bytes": offsets[n]}
                         for n, v in sections.items()}}


def scan(path):
    raw = path.read_bytes()
    if not 0 < len(raw) <= 8 * 1024 * 1024:
        raise ValueError("PE size bound")
    sections = {}
    with pefile.PE(data=raw) as pe:
        if pe.FILE_HEADER.Machine != 0x14c or pe.OPTIONAL_HEADER.Magic != 0x10b:
            raise ValueError("PE32 i386 required")
        for s in pe.sections:
            if s.Characteristics & 0x20000000:
                name = s.Name.rstrip(b"\0").decode("ascii")
                size = s.Misc_VirtualSize
                if name in sections or not 0 < size <= s.SizeOfRawData <= 4 * 1024 * 1024:
                    raise ValueError("executable section extent")
                data = s.get_data()[:size]
                if len(data) != size:
                    raise ValueError("truncated executable section")
                sections[name] = {"address": pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress,
                                  "bytes": data}
    if not sections or sum(len(x["bytes"]) for x in sections.values()) > 4 * 1024 * 1024:
        raise ValueError("executable bytes bound")
    tool = shutil.which("i686-w64-mingw32-objdump")
    if not tool:
        raise ValueError("installed objdump required")
    argv = [tool, "-d", "-z", "--show-raw-insn", "--insn-width=16", str(path)]
    result = subprocess.run(argv, capture_output=True, timeout=60)
    if result.returncode or result.stderr or len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError("objdump failed/diagnosed or decode exceeded bound")
    report = inspect_decode(result.stdout.decode("ascii"), sections)
    if path.read_bytes() != raw:
        raise ValueError("artifact changed during inspection")
    report.update(artifact={"path": str(path), "bytes": len(raw), "sha256": digest(raw)},
                  command=argv, objdump_sha256=digest(Path(tool).read_bytes()),
                  disassembly_sha256=digest(result.stdout),
                  native_execution_verified=False, imported_os_dll_code_verified=False)
    return report, result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("preserve earlier receipts; output must be new")
    root = Path(__file__).resolve().parents[2]
    if not output.resolve().is_relative_to(root / "build"):
        parser.error("own ignored build output required")
    output.mkdir(parents=True, mode=0o700)
    try:
        report, disassembly = scan(args.pe.resolve())
        (output / "disassembly.txt.gz").write_bytes(gzip.compress(disassembly, mtime=0))
    except Exception as error:
        report = {"status": "FAIL", "error": str(error), "native_execution_verified": False}
    report["scanner_sha256"] = digest(Path(__file__).read_bytes())
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report.get(k) for k in
                      ("status", "instructions", "non_i486_instruction_count", "error")}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
