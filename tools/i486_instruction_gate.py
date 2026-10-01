#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed i486/x87 decode with raw executable-section byte coverage."""
import hashlib
import re
import subprocess
from pathlib import Path

import pefile

BASE = set("""aaa aad aam aas adc add and arpl bound bsf bsr bswap bt btc btr bts
call cbw cdq clc cld cli cltd cmc cmp cmps cmpxchg cwd cwde cwtl daa das dec div
enter hlt idiv imul in inc ins int int3 into invd invlpg iret iretw iretd ja jae
jb jbe jc jcxz je jecxz jg jge jl jle jmp jna jnae jnb jnbe jnc jne jng jnge jnl
jnle jno jnp jns jnz jo jp jpe jpo js jz lahf lar lcall lea leave les lds lfs lgs
ljmp lss lgdt lidt lldt lmsw lods loop loope loopne loopnz loopz lret lsl ltr mov
movs mul neg nop not or out outs pop popa popad popf popfd push pusha pushad
pushf pushfd rcl rcr ret rol ror sahf sal sar sbb scas seta setae setb setbe setc
sete setg setge setl setle setna setnae setnb setnbe setnc setne setng setnge setnl
setnle setno setnp setns setnz seto setp setpe setpo sets setz sgdt shl shld shr
shrd sidt sldt smsw stc std sti stos str sub test verr verw wait wbinvd xadd
xchg xlat xor""".split())
X87 = set("""f2xm1 fabs fadd faddp fbld fbstp fchs fclex fcom fcomp fcompp fcos
fdecstp fdiv fdivp fdivr fdivrp ffree fiadd ficom ficomp fidiv fidivr fild fimul
fincstp finit fist fistp fisub fisubr fld fld1 fldcw fldenv fldl2e fldl2t fldlg2
fldln2 fldpi fldz fmul fmulp fnclex fninit fnop fnsave fnstcw fnstenv fnstsw
fpatan fprem fprem1 fptan frndint frstor fsave fscale fsin fsincos fsqrt fst fstp
fstcw fstenv fstsw fsub fsubp fsubr fsubrp ftst fucom fucomp fucompp fwait fxam
fxch fxtract fyl2x fyl2xp1""".split())
PREFIX = {"lock", "rep", "repe", "repz", "repne", "repnz", "data16", "addr16",
          "cs", "ds", "es", "fs", "gs", "ss"}
EXACT = {"movsbl", "movsbw", "movswl", "movzbl", "movzbw", "movzwl"}
SUFFIXABLE = set("""adc add and bsf bsr bt btc btr bts call cmp cmps dec div idiv imul in inc ins jmp lea lods
mov movs mul neg not or out outs pop push rcl rcr ret rol ror sal sar sbb scas
shl shld shr shrd stos sub test xadd xchg xor""".split())


def need(ok, message):
    if not ok:
        raise ValueError(message)


def allowed(mnemonic):
    if mnemonic in BASE | X87 | EXACT:
        return True
    if mnemonic[-1:] in {"b", "w", "l"} and mnemonic[:-1] in SUFFIXABLE:
        return True
    # Binutils AT&T memory forms have size suffixes; ll denotes signed64bit.
    return any(mnemonic == root + suffix for root in X87
               for suffix in ("s", "l", "t", "ll"))


def decode(text, sections=None):
    need(isinstance(text, str) and 0 < len(text) <= 64 * 1024 * 1024,
         "empty/unbounded disassembly")
    rows, current, offsets = [], None, {}
    for line in text.splitlines():
        need(len(line) <= 2048, "unbounded disassembly line")
        header = re.fullmatch(r"Disassembly of section ([^ \t:]+):", line)
        if header:
            current = header[1]
            need(current not in offsets, "duplicate section decode")
            offsets[current] = 0
            if sections is not None:
                need(current in sections, "unexpected executable section")
            continue
        if not re.match(r"^[ \t]*[0-9a-f]+:[ \t]", line):
            continue
        match = re.fullmatch(r"[ \t]*([0-9a-f]+):[ \t]+"
                            r"((?:[0-9a-f]{2}[ \t]+)+)([^ \t]+)(?:[ \t]+(.*))?", line)
        need(match is not None, "unknown/truncated instruction row: " + line)
        address, raw, mnemonic, operands = match.groups()
        data = bytes.fromhex(raw)
        need(1 <= len(data) <= 15, "invalid instruction length")
        operands = operands or ""
        for _ in range(15):
            if mnemonic not in PREFIX:
                break
            more = re.fullmatch(r"([^ \t]+)(?:[ \t]+(.*))?", operands)
            need(more is not None, "prefix without actual instruction")
            mnemonic, operands = more[1], more[2] or ""
        need(mnemonic not in PREFIX and allowed(mnemonic),
             "non-i486/unknown mnemonic: " + mnemonic)
        need(not re.search(r"%(?:[xyz]mm\d+|mm[0-7])\b", operands), "SIMD register")
        need(all(register in {"0", "2", "3"} for register in
                 re.findall(r"%cr([0-9]+)\b", operands)), "non-i486 control register")
        if sections is not None:
            need(current in sections, "instruction outside executable section")
            section = sections[current]
            offset = offsets[current]
            need(int(address, 16) == section["address"] + offset and
                 section["data"][offset:offset + len(data)] == data,
                 "instruction byte/address gap or mismatch")
            offsets[current] += len(data)
        rows.append((current, mnemonic, len(data)))
        need(len(rows) <= 1048576, "instruction count bound")
    need(rows, "no actual instruction rows")
    if sections is not None:
        need(set(offsets) == set(sections) and all(offsets[n] == len(s["data"])
             for n, s in sections.items()), "incomplete executable-section byte coverage")
    return dict(instructions_decoded=len(rows), post_i486_families="absent",
                parser="horizontal-lines-explicit-i486-x87-allowlist-v1",
                executable_sections={n: dict(bytes=len(s["data"]),
                    sha256=hashlib.sha256(s["data"]).hexdigest(),
                    address=s["address"], decoded_bytes=offsets[n])
                    for n, s in (sections or {}).items()})


def scan(path):
    path = Path(path)
    original = path.read_bytes()
    with pefile.PE(data=original) as pe:
        need(pe.FILE_HEADER.Machine == 0x14c and pe.OPTIONAL_HEADER.Magic == 0x10b,
             "PE32 i386 required")
        sections = {}
        for section in pe.sections:
            if not section.Characteristics & 0x20000000:
                continue
            name = section.Name.rstrip(b"\0").decode("ascii")
            size = section.Misc_VirtualSize
            need(name not in sections and 0 < size <= section.SizeOfRawData <= 4 * 1024 * 1024,
                 "unsupported executable-section extent")
            data = section.get_data()[:size]
            need(len(data) == size, "truncated executable section")
            sections[name] = dict(data=data, address=pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress)
        need(sections and sum(len(s["data"]) for s in sections.values()) <= 4 * 1024 * 1024,
             "executable byte bound")
    command = ["i686-w64-mingw32-objdump", "-d", "-z", "--show-raw-insn", "--insn-width=16", str(path)]
    result = subprocess.run(command, capture_output=True, timeout=60)
    need(result.returncode == 0 and not result.stderr, "actual objdump failed/diagnosed")
    decoded = decode(result.stdout.decode("ascii"), sections)
    need(path.read_bytes() == original, "PE changed while decoding")
    decoded.update(artifact_sha256=hashlib.sha256(original).hexdigest(),
                   artifact_bytes=len(original), command=command,
                   disassembly_sha256=hashlib.sha256(result.stdout).hexdigest())
    return decoded, result.stdout
