# Actual DOS executor / VMM boundary audit

Status: `AUDITED_NO_EXECUTOR_BOUNDARY / NOT_VERIFIED`. Canonical Windows lead
owns this executor boundary; root coordinates the existing Windows boot owner
and Fada transport owner. This turn changes only this audit document. No
production code, repository script, build, guest, media or Git index was changed.

Windows 98 remains the product OS. VMM schedules its Windows/DOS VM work;
Supervisor schedules domains and Kernel64 schedules backend workers. A DOS
executor must rendezvous through VMM, not introduce another DOS scheduler.

## Present source boundary and blocking evidence

The 6970 [prior audit](/root/Win98-Modern-theme-6970/docs/agents/notes/6970/DOS_GATE_BOUNDARY_AUDIT.md)
was checked against integration `bfa6df797c8fa1de3690a16c9830836f1935795c`
and Fada `d4615296c27a0ccb27ce1ab344bbd2ed322ce4c8` separately. Fada's service
was not present in the audited integration `subsys64.c`; its reviewed source
must be imported and retested by root before combined acceptance.

- `native.c:48` binds init/exit and synchronous DIOC only. `control.asm:29`
  dispatches dynamic init/exit and W32_DEVICEIOCONTROL. There is no deferred
  VM-event callback, client-state wrapper or DOS interrupt executor.
- Channel2 already joins Kernel64 and Win98 (`kdom.c:171`). The VxD discovers
  and maps it through existing guarded hypercalls. `bridge.c:430` WAIT only
  acknowledges a doorbell; native code registers neither a Supervisor doorbell
  vector nor a Win98 interrupt handler. A pending doorbell cannot currently
  invoke a DOS callback on its own.
- `bridge.c:392` RECV accepts peer REPLY or ONEWAY inline messages, rejects
  ordinary reverse requests with flags zero, and returns accepted messages to
  the Win32 caller. A Kernel64 DOS command therefore needs a coordinated
  reverse-command envelope/dispatcher; it cannot simply reuse an unmodified
  forward request. A completion also needs an explicit Kernel64 receiver.
- Fada's `shz_vmm_pma.h` and service implement event QUERY/CREATE/WAIT/SIGNAL,
  RESET/CLOSE/CANCEL and caller lifecycle. The 64-byte completion binds sequence,
  domain, PID/TID and lifetime generations. There is no DOS command/result
  payload, Kernel64-to-Win98 DOS executor, callback into DOS, or authoritative
  Windows PID/TID registration. Existing event opcodes must keep their meaning.
- Supervisor still selects a Win98 domain or a DOS16 domain, not both as one
  DOS-to-VMM foundation. DOS16's high shared window is not mapped;
  `SHZSTART.BAT` remains a readiness diagnostic. A separate FreeDOS domain
  cannot be treated as the DOS foundation of the live Windows VM.

## Verified Win98 declarations and remaining contract work

The original Microsoft Win98 DDK files in archive commit
`0c662d32378b9940ed90aee682f4eb5daf816e6a` were read over HTTPS into memory.
These identifiable archived declarations are stronger than importing numeric
values from an older DDK. They were neither incorporated nor compiled here.

The following encoded VMM service values were derived from the pinned
`Begin_Service_Table` ordering and its ordinal macro; no service ID was guessed:

| Declaration | Encoded DWORD |
| --- | --- |
| Get_Cur_VM_Handle / Get_Sys_VM_Handle / Validate_VM_Handle | `00010001` / `00010003` / `00010005` |
| Call_Priority_VM_Event / Cancel_Priority_VM_Event | `00010014` / `00010015` |
| Begin_Nest_V86_Exec / Begin_Nest_Exec / Exec_Int / End_Nest_Exec | `00010082` / `00010083` / `00010084` / `00010086` |
| Save_Client_State / Restore_Client_State / Exec_VxD_Int | `0001008D` / `0001008E` / `0001008F` |

The same header declares VM/client-state structures and event flags, including
wait-for-STI, wait-not-critical and always-schedule. This establishes declarations,
not permission to invoke them from an arbitrary context. [Pinned VMM.INC](https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/VMM.INC).

Two additional Win98-specific constraints matter. `VMM.H:3232` forbids
Simulate_Int/Exec_Int in non-initial threads. `Get_PSP_Segment` is marked
`VMM_ICODE`; it is not a runtime current-PSP API to call after initialization
code is discarded. Appy/worker event restrictions have distinct callback stack
conventions and cannot be combined with other restriction flags. A future
wrapper must preserve the service's actual callback/register convention rather
than repurpose DIOC's ESI descriptor. [Pinned VMM.H](https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/VMM.H).

`DOSMGR.INC`/`.H` declare Get_IndosPtr and Get_DOS_Crit_Status; the former is
pageable. Their declarations alone do not specify which VM is inspected, pointer
mapping/lifetime, critical-state return meaning, or a complete safe entry rule.
Those Win98 service topics must be inspected before implementing the gate.
[Pinned DOSMGR.INC](https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/DOSMGR.INC),
[DOSMGR.H](https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/DOSMGR.H).

The older Microsoft DDK supplies an explanatory candidate: a priority VM event
passes the current VM, reference data and client-register pointer; nested
execution requires saving/restoring client state. Exec_VxD_Int supports a
register-only AH30 query, preserves client state, consumes its interrupt stack
argument, and restricts segment-changing services. AH34 returns ES:BX, so it
must not be treated as the same register-only query. This is older-contract
guidance, not Win98 execution proof. [Microsoft DDK chapters22/26](https://www.pcjs.org/documents/books/mspl13/win/w3ddkvxd/).

The pinned Win98 `WIN98DDK.CHM` and `OTHER.CHM` are available and their bytes
were hashed, but their compressed service topics were not extracted/read this
turn. Reading the exact event, DOSMGR, nested execution and teardown topics is
the next source prerequisite. In particular, verify which event restrictions
select an executable initial-thread context, which restrictions only describe
CPU/VM readiness, and whether Exec_VxD_Int has additional Win98 thread limits.

## InDOS, critical errors and PSP ownership

Pinned FreeDOS entry.asm:646 increments ErrorMode and decrements InDOS before
INT24. Thus InDOS==0 is insufficient while critical-error handling is active.
The matching kernel globals are distinct bytes. Safe execution must establish
both states for the actual DOS instance; never assume an unverified preceding
byte in another DOS implementation is its critical-error flag. Acquire cached
DOS pointers in a verified startup/client-state boundary, validate their VM and
mapping lifetime, and check them at the VMM callback immediately before entry.
A native CLI interval, host ticket lock or VM priority flag does not make DOS
reentrant. If safe state cannot be established, defer boundedly or reject.

FreeDOS memmgr.c:250 assigns MCB ownership to `cu_psp`; inthndlr.c:200 exposes
set/get PSP and dosfns.c associates file state with the same owner. Register an
actual live DOS helper/VM/PSP lifetime through a safe guest boundary. Kernel64
PID/TID numbers are not PSP segments and must never be written into DOS state.
For initial AH30 proof, keep the registered PSP/context unchanged and record
PSP before/after. Later owner-changing operations require verified DOS-mediated
save/set/restore, SFT/CDS/MCB ownership and cancellation/teardown behavior.

## Smallest implementation and acceptance sequence

1. Finish the pinned Win98 topic review above. Document register/stack effects,
   allowed call contexts, callback cancellation race and VM/process teardown.
   Add original assembly thunks and client-state constants only after that
   contract is verified. Static emitted-call/stack/register tests can check the
   wrappers but cannot certify live VMM behavior.
2. Root coordinates the existing boot owner to provide a private reproducible
   Win98 control with live Supervisor and Kernel64/channel2. Record media/OS/DOS
   identity, exact VxD/probe/kernel/Supervisor hashes and actual load/query.
   Original Microsoft DOS is an explicitly labeled control. The final product
   still requires the real same-VM ShizukuDOS-to-WIN.COM/VMM replacement boot.
3. Register one owned DOS VM and PSP with a lifetime token. Choose a source-
   verified initial-thread event callback. A Win32 poll pump may initially
   discover commands via existing RECV and queue that event; it must not call
   DOS inline from an arbitrary DIOC thread. Alternatively wire the existing
   doorbell through a verified Windows interrupt/event boundary. No new DOS
   scheduling authority is needed.
4. Coordinate with Fada a typed reverse-command/result extension over existing
   ABI1.1/channel2. No new opcode number or binary layout is assigned here.
   A bounded queue reserves request/completion capacity before entry, validates
   endpoints/channel epoch/registered VM+PSP lifetime, and dispatches only AH30
   initially. Give each accepted command one correlation identity; retain its
   result through full-ring backpressure. Do not overload event WAIT/SIGNAL.
5. In the actual callback, revalidate lifetime and DOS safe state, execute real
   INT21/AH30 using the verified VMM boundary, capture returned registers, then
   restore client/PSP state before publishing the matching completion. Never
   invoke DOS under native IRQ masking, transport admission or scheduler locks.
   Cancellation before entry can remove pending work; after entry it cannot
   pretend the DOS call did not execute. Deferred results remain owned until
   accepted delivery or a proven teardown/reclamation boundary.
6. Capture guest-generated evidence for Kernel64 request, actual Win98 callback
   VM/thread/PSP, real DOS return and matching request/opcode/endpoints/channel
   and owner generations. Check stale/repeated/cancelled work, full-ring retry,
   owner death/unload, busy InDOS and active critical-error deferral/rejection.
   AH30 is the first transport/executor proof only. Then exercise two real
   workers serially invoking DOS operations with PSP/MCB/SFT/CDS preservation;
   host locks or simulated callbacks cannot satisfy this acceptance.

Blocking prerequisites are concrete: Win98 service-topic contracts are unread;
no native event/interrupt callback exists; no authoritative VM/thread/PSP owner
registry exists; no reverse DOS command/result dispatch exists; and no source-
bound live Win98/channel2 AH30 receipt was supplied. Source inspection can
resolve the first prerequisite next. Boot-owner integration and the coordinated
executor/transport implementation are necessary for the remaining live proof.

## Source pins

| Source | SHA-256 |
| --- | --- |
| integration ntwrapper/vxd/native.c | `4319abffb1c7812557fabe125596437e9ddb3c08e75f276047bd3dc09b231430` |
| integration ntwrapper/vxd/control.asm | `64ac4f94f511448268beb7ed46c81b34e492a05cc9a5b28ade0ca336d65e39ce` |
| integration ntwrapper/vxd/bridge.c | `c7487e39076e65800d8635f89c92fc895ac115c595042a0daddc9134470f03df` |
| integration shizukudos/abi/shz_abi.h | `7d53ebf6c5be271cf8dae5ff18fe1b05d8ba87492fc71f0a447f544c76750682` |
| integration shizukudos/abi/shz_ipc.h | `17c19bcf8295338c02cbcdb83e3ad4c0618e28f78d62ec3568d1ae50b10a2031` |
| integration shizukudos/kernel64/subsys64.c | `ce44ec45ffea336e2594d972b72d3090515d3701552fc10bfe96f1be5683e6d2` |
| integration shizukudos/supervisor/src/kdom.c | `cc6e561694aced029469678d8a7079fd8c3263508872c489a2eed48901d5f5e5` |
| integration shizukudos/supervisor/src/domain.c | `16c372d72071b53c839e901b646d8654c99fffbe1910315111117cc8ab4cf742` |
| Fada shizukudos/abi/shz_vmm_pma.h | `ad7d29d342cba171c4d3ae7374b891f3b3c9df0fc735fcaa719a5b9e2017efd0` |
| Fada shizukudos/kernel64/subsys64.c | `358ff94fcd401f4d1b6d784b2cef5b249bf24a6fe023526ff3d1b918210ef0e9` |
| FreeDOS enabled kernel/entry.asm | `515f8fb96e63b18a3b139c265ce5b83fdfd51f1b1ada607c9dbe6ffaf2516a4f` |
| FreeDOS enabled kernel/memmgr.c | `8918b2cacfa3f4492bfc824ea1150287ab8948f7b0eebb76d6c24fa40bc0d874` |
| FreeDOS enabled kernel/inthndlr.c | `e5d13efa07310d3119d4fbf8af8ff9a78fee034b4e006bb85903e2986123589d` |
| archived Win98 DDK inc/win98/VMM.INC, 88624 bytes | `d640c2994970fabe36c6d4f47ac94b719554d19dc036807c56fe9252ded6d1b2` |
| archived Win98 DDK inc/win98/VMM.H, 181678 bytes | `91c9116a1a29819779818115985d1cb34228b8ef2cd7c0d47cee57078cd559a2` |
| archived Win98 DDK inc/win98/DOSMGR.INC, 1117 bytes | `c040e891d3342284d4bd42ae03f5ac6d0da5d3cdaf9fa7f6ea5ba291e860ecd4` |
| archived Win98 DDK inc/win98/DOSMGR.H, 2110 bytes | `51e80bc561eabde239a67106583e379d69b4ed100844ef9ad8e0631766c46076` |
| archived Win98 DDK help/WIN98DDK.CHM, 1828866 bytes | `95c6cb06cc2b208404d0d0ab399c5157bad82c783c90ba23413e2171c0b46502` |
| archived Win98 DDK help/OTHER.CHM, 4082984 bytes | `25bf75cb60f1545147eb868fd2ab2b2452c3d4d559b5e2f440c07a9db187e127` |

CHM source URLs use the same pinned archive commit and `98DDK/help/` paths.
Local FreeDOS files are the existing enabled startup-contract snapshot; entry
and allocator hashes match 6970's pinned upstream observations. They do not
establish a successful Windows boot on that DOS implementation. Source reads,
hashes and public declaration inspection were the only checks; no execution
acceptance is claimed.
