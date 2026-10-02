# Actual DOS execution boundary audit

Read-only audit by the Core Kernel Lead and its child. No DOS code, build,
download, media or VM was changed. Actual Windows 98 remains the product OS.

## Production source and state

`shizukudos/dos16/build.py:87` builds the pinned FreeDOS kernel revision
`5ffb550` with the repository's tracked patches. The clean cache inspected at that audit epoch was
`/root/Win98-Modern/build/upstream/freedos-kernel`; its files were inspected,
not executed. The historical `stage2.asm` INT21 subset is not this production
FreeDOS kernel.

In the pinned FreeDOS source, `kernel/entry.asm:243` dispatches INT21.
Lines 373–425 manage InDOS and the normal return. The optional WIN31SUPPORT
critical-section helpers at 455–477 use the existing INT2Ah protocol but are
disabled in the ordinary build. Enabling them alone would not establish
Windows 98 compatibility.

`kernel/inthndlr.c:1096` handles EXEC and termination. In `kernel/task.c`,
369–394 changes the child PSP/DTA, decrements InDOS and transfers control
through nonreturning exec_user; 609–622 restores the parent's state before
another nonreturning transfer. A lock around int21_service alone therefore
cannot survive the actual EXEC/termination paths correctly.

InDOS is a counter rather than an admission check. Shared term_type/user_r
writes precede its normal increment. INT25/26, INT2F internal services and
fast vector/PSP services bypass the ordinary INT21 path. CriticalError drops
InDOS around INT24 and INT28 has special preservation rules; InDOS zero alone
therefore cannot authorize gateway entry safely.

`kernel/kernel.asm:523` defines SFT state, 533 defines CDS, and 748–760 contain
ErrorMode, InDOS, DTA, cu_psp and the current drive. MCB allocation ownership
uses cu_psp in `kernel/memmgr.c:250` and 371; SFT ownership does so in
`kernel/dosfns.c:534`. These are actual DOS state, not native Kernel64 objects.

## Missing integration

Supervisor dos.c handles device/BIOS/HLT exits; it does not intercept INT21 or
EXEC. kdom.c deliberately leaves DOS16 without an IPC address window. Current
hypercall dispatch has no DOS request executor. The native boot path selects
the Win98 domain or DOS16 rather than supplying a verified gateway between
them. A ticket lock in Kernel64 or the BIOS path cannot serialize these DOS
calls.

The minimum defensible implementation needs a DOS-side executor/admission
boundary, verified native/VMM-safe request delivery, and explicit normal,
EXEC, termination and critical-error completion paths. A returning-service
allowlist can be a first slice once those boundaries are agreed with the
Supervisor/ABI/VxD owners. Native waiters must block until completion, with no
ticket lock held across DOS/VMM entry. Full PSP/MCB/SFT/CDS serialization and
actual Win98-on-replacement-DOS acceptance remain pending.

Existing host tests can inspect a temporary patched copy of the cached pinned
source using SHZ_FREEDOS_SOURCE. The full DOS builder also replaces its upstream
worktree, may fetch tools/source and overwrites standard outputs; it must use a
fresh isolated build lane for future execution. No such execution occurred in
this audit, and no DOS gateway completion is claimed.

## Cross-chat owner acknowledgement

163f assigns the actual executor/VMM callback prerequisite boundary to its
Windows/NT lead, using pinned Win98 declarations and the existing VxD channel.
Canonical replacement-DOS boot remains its master integration lane. This is
recorded in `/srv/shizukudos-session-coordination/MESSAGE-163f-PEERS-DOS-OWNERSHIP.md`.
Assignment is not an implemented or accepted DOS gate; this c957 audit makes no
DOS execution or Windows 98 boot claim.
