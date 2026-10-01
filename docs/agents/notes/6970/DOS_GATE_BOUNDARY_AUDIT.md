# Actual DOS executor boundary audit — 6970

Status: `AUDITED_NO_EXECUTOR_BOUNDARY / NOT_VERIFIED`.
This is a source audit and proposed integration sequence, not DOS execution,
serialized INT21 acceptance or replacement-boot evidence. Canonical master163f
owns integration decisions; this note does not reserve DOS_GATE implementation.
After acknowledging this audit, master163f assigned the actual DOS executor/VMM
callback boundary to its Windows/NT compatibility lead and retained replacement
boot integration. That assignment is not implemented or tested executor evidence.

Windows98 remains the product OS. ShizukuDOS must replace its MS-DOS foundation;
Shizuku Kernel32/64 are backend workers. VMM must schedule Windows/DOS VM work.
A separate FreeDOS VM and a Windows VM booting the original Microsoft DOS do
not establish that replacement. A HOST ticket-lock test cannot establish DOS
InDOS/critical-error/PSP/MCB safety without a real executor and DOS consumer.

## Inspected production boundary

The audit baseline is main `a648e9baa1c57289d50e58d3380827bd9239bc52`.
An independent child agent read the actual sources; root checked all11 source
hashes and inspected the domain/channel and critical-error paths independently.
No compiler, repository script, VM or media execution was performed for this audit.

- Supervisor main.c:64–75 selects native Win98 or DOS16 in an if/else branch.
- kdom.c:171–174 plans a K32↔DOS16 channel, but198–199 skips DOS16 mapping.
  Kernel32 ipc.c:49–51 connects only the Kernel64 peer.
- SHZSTART.BAT provides diagnostic/readiness output, with no Windows startup,
  resident DOS executor or request consumer.
- Supervisor domain.c and bios.c contain hypercall/BIOS dispatch, without a DOS
  service executor. Kernel64 subsys64.c handles current process/console requests.
- Existing NTWRAP9X bridge.c channel2 can connect live Windows98 to Kernel64.
  native.c binds page services and VMCALL; it has no DOS executor or VMM event
  callback. Use that live Windows transport, coordinated with Fada's versioned
  payload/completion work, rather than inventing a parallel DOS scheduling owner.

## DOS and VMM constraints

Pinned FreeDOS `5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3` entry.asm:646–647
increments ErrorMode while decrementing InDOS during critical-error handling.
Therefore InDOS==0 alone cannot permit DOS entry. memmgr.c:250 assigns allocated
MCB ownership to the current cu_psp; execution must preserve the actual DOS
context and PSP lifetime. These are observed source requirements, not a claim
that Windows has booted on this pinned FreeDOS implementation.

The original Microsoft Windows3 DDK describes VMM event rendezvous that waits
for the target VM's interrupts and critical section, plus nested execution and
Exec_VxD_Int. Win98 service IDs, flags and client-state contracts still require
pinned Win98 definitions and real execution; do not copy guessed numbers from
an older DDK. [Microsoft DDK](https://www.pcjs.org/documents/books/mspl13/win/w3ddkvxd/).

AH34 returns ES:BX and must not be treated like AH30's register-only version
query. Exec_VxD_Int restricts selector-changing calls. Cache the DOS pointer
during a safe DOS/V86 startup, or define an appropriate nested/client-state
boundary; do not obtain it repeatedly while DOS is busy. [AH34 contract](https://fd.lod.bz/rbil/interrup/dos_kernel/2134.html).

## Smallest real integration sequence

1. Canonical master owns replacement-boot integration and has assigned the
   actual executor separately from common locks. Confirm the same DOS foundation
   and pinned Win98 callback/client-state declarations before implementation.
2. Reuse the live Win98 VxD channel and Fada payload/completion correlation.
   Schedule DOS work in the correct Windows VM through the real VMM contract;
   never call DOS directly in a native IRQ/CLI or scheduler-lock critical section.
3. First prove a source-bound Kernel64 request → live Win98/VxD callback → real
   AH30 DOS version → completion matching request, generation and endpoints.
   This is transport evidence only, not serialization or DOS replacement.
4. Then prove two backend workers execute actual DOS operations serially;
   include busy/error-state defer or reject, cancellation, stale completion,
   PSP restoration, MCB preservation and owner teardown controls.
5. Finally prove Windows98 boots on ShizukuDOS and retains VMM, USER/GDI,
   Win16/Win32, Explorer and the requested applications. Standalone kernel or
   original-DOS Windows controls do not satisfy this product acceptance.

## Source pins

| Audited file | SHA256 |
| --- | --- |
| supervisor/src/main.c | cc22ef586c6295f85063d4d57dd0bdbe5ed662a3fcfd44e893b998066fc9b88c |
| supervisor/src/kdom.c | cc6e561694aced029469678d8a7079fd8c3263508872c489a2eed48901d5f5e5 |
| kernel32/ipc.c | da1334447456982068591fb7319dd8b0beae88d59cf1b11cb230c702dd187e64 |
| dos16/user/SHZSTART.BAT | 758de84da76fc0394c2ced2bd40544c319c24c69d19cb0ab6418e03d7f8cee3d |
| supervisor/src/domain.c | 5f3ee55b1ddb0460229b22b1039b1f742d81d1fa88f9b42b8be10828d7c9aef4 |
| supervisor/src/bios.c | fd29cd30b5b2d17c24ab980643ffe9127be5b3c406dabfa88e81ef8ea8ce69be |
| kernel64/subsys64.c | ce44ec45ffea336e2594d972b72d3090515d3701552fc10bfe96f1be5683e6d2 |
| ntwrapper/vxd/bridge.c | 5a997c93e256b5d42e32f2b36e1c3158c255dae4225e415d32601921936725bf |
| ntwrapper/vxd/native.c | 4319abffb1c7812557fabe125596437e9ddb3c08e75f276047bd3dc09b231430 |
| upstream FreeDOS kernel/entry.asm | 515f8fb96e63b18a3b139c265ce5b83fdfd51f1b1ada607c9dbe6ffaf2516a4f |
| upstream FreeDOS kernel/memmgr.c | 8918b2cacfa3f4492bfc824ea1150287ab8948f7b0eebb76d6c24fa40bc0d874 |
