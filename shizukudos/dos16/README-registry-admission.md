# Read-only DOS registry admission observer

`probes/registry_admission.asm` builds `REGADM.COM` with NASM. It creates
`C:\REGADM.TXT` exclusively and observes the selected `C:\WINDOWS` source.
An existing report causes refusal; it never changes Windows files or starts
Windows. A completed observation is not Windows startup success.

The observer queries DOS versions (INT21 AX3000/3306), the MS-DOS7 shell and
system registry pathname interfaces (INT2F AX1611/1613), file attributes,
readonly opens, handle timestamps, and a bounded 24-byte registry header.
It reports only signature validity and the header status word at offset18;
no registry keys or values are printed. Simultaneous reads use INT21 AH3D
AL20/40 while an AL00 handle remains open. Extended open uses AX6C00,
BX0040 readonly/deny-none and DX0001 open-existing only. Windows writes,
attribute changes, creation, replacement, locking, and repair are absent.

INT2F 1613 receives an 80-byte buffer with both boundary canaries. Only
returned register numbers, bounded pathname length and classification
(0 other, 1 USER.DAT, 2 SYSTEM.DAT) are reported. Unknown pathname text and
shell strings returned through DS are never dereferenced or printed.
The observer restores its own DS/ES after multiplex calls.

Each API row prints AX BX CX DX FLAGS as five hexadecimal words; carry bit0
in FLAGS is meaningful for DOS file calls, and AX contains the DOS error
when carry is set. API errors remain observations. Derived HEADER/MUXPATH
rows use the same numeric layout, but their FLAGS column is not an API
result. COMPLETE means the observer reached its end and report commit;
DOS exit code must also be0. Missing COMPLETE or nonzero exit is incomplete.
A report write failure can leave a partial report, which is not success.

The contract reference is the original author’s [Ralf Brown Interrupt List](https://www.cs.cmu.edu/~ralf/files.html),
release61 [partC](https://www.cs.cmu.edu/~ralf/interrupt-list/inter61c.zip):
AX1611 returns shell parameters, AX1613 returns SYSTEM.DAT pathname.
The current FreeDOS kernel’s [INT2F implementation](https://github.com/FDOS/kernel/blob/master/kernel/inthndlr.c)
is a separate source reference. Unsupported calls are observed rather than
converted into success. No Microsoft executable bytes or disassembly are
included in this source-written probe.

Build: `nasm -f bin -Wall -Werror -o REGADM.COM probes/registry_admission.asm`
from this directory. Tests execute actual compiled COM bytes in Unicorn2.1.4,
with bounded modeled DOS responses, not a Windows guest:
`<isolated-python> tests/test_registry_admission.py`.
Controls cover exact readonly admissions, output refusal, unknown/unsupported
paths, changed DS, unterminated strings, canary corruption, header errors,
sharing/open failures, short report writes, and failed report commit.
Actual guest observations require separately pinned private source disks,
resource admission, sole VM ownership and normal reaping.
