# Kernel-to-user exception entry dependencies

The pinned [ReactOS `ntoskrnl/ke/i386/exp.c`](https://github.com/reactos/reactos/blob/cae3c053d47024545c773148185319075eae0202/ntoskrnl/ke/i386/exp.c)
contains `KiDispatchException` at lines 795 onward. It constructs a context from
the trap frame, adjusts breakpoint context, separates kernel/user mode and first
versus second chance, consults debugger paths, validates/probes user stack space,
copies exception/context records, sanitizes segments and redirects user EIP to
`KeUserExceptionDispatcher`. Its trap-frame, PRCB/PCR, debugger, NT memory manager,
thread/process and GDT assumptions do not exist merely because this registry now
builds. That kernel file was inspected as a dependency reference, not imported.

The pinned [user i386 dispatcher](https://github.com/reactos/reactos/blob/cae3c053d47024545c773148185319075eae0202/dll/ntdll/dispatch/i386/dispatch.S)
clears DF, takes record/context pointers from the prepared stack and calls
`RtlDispatchException`. A handled result calls `ZwContinue`; an unhandled result
uses `ZwRaiseException` for another chance. Returning failure constructs another
exception. None of those NT system-call entry points can be forwarded by name to
Win98 VMM. This core does not use INT 2Eh or assume an NT trap-frame ABI.

The pinned [RTL i386 dispatcher](https://github.com/reactos/reactos/blob/cae3c053d47024545c773148185319075eae0202/sdk/lib/rtl/i386/except.c)
calls vectored exception handlers before the frame chain. Its handled path calls
vectored continue handlers. The SEH path validates registration-frame bounds,
supports nested frames, rejects forbidden noncontinuable resumption and also
calls continue handlers when appropriate. These dependencies extend beyond
registering functions in a list. Wine's compared user exception path likewise
depends on real `NtContinue`, `NtRaiseException` and SEH dispatch.

Concrete next binding stages, each requiring its own tests:

1. **Prove a loadable native NTWrapper9x bridge.** The current frozen experimental
   VxD returned VXDLDR native AX=0006 (bad-device-file) after byte-exact DOS
   preflight. No new exception hook is installed by this work; driver loading
   remains a prerequisite before using it as kernel-side infrastructure.
2. **Specify the Win98 ingress contract from verified VMM interfaces.** Capture
   the original trap cause, process/thread identity, EIP/ESP/EFLAGS, segment and
   floating-point state at the supported execution mode. Keep hardware faults,
   deliberate software raises, debugger first chance and V86/16-bit cases
   distinct. Determine an authorized user-mode callback path; do not invent a
   CONFIGMG/VMM ordinal or reuse ReactOS NT trap offsets.
3. **Define a checked user record/context adapter.** Validate ABI widths, parameter
   counts, stack bounds/alignment and memory access; copy to owned storage before
   transitioning. Guard-page/stack-overflow handling needs a safe stack strategy.
   Kernel-origin records must not contain unchecked user pointers or permit
   privileged segment/EFLAGS/debug-register changes during resume.
4. **Bind the per-process user dispatcher.** Initialize a process-local registry
   and safe allocation/lock services; call the portable exception list after
   debugger first chance and before SEH unwinding. Add i386 callback ABI wrappers
   preserving required registers/DF. The current C callback with a cookie is
   deliberately not `PVECTORED_EXCEPTION_HANDLER`.
5. **Implement continuation and second chance.** Validate continuability and the
   modified context, then use a verified Win98 transition to resume it. Integrate
   the existing SEH chain and continue notifications with correct ordering.
   An arbitrary handler return of -1 cannot authorize ring-0 context restoration.
6. **Make callback lifetime safe during abnormal control flow.** Handler faults,
   nested exceptions and unwinds that abandon the dispatcher require cleanup of
   every pinned snapshot reference. The present host callbacks return normally;
   an SEH/finally-capable native invocation frame and teardown protocol must be
   added and tested before advertising Win32 VEH compatibility.
7. **Run separate native acceptance.** Test software raise and controlled user
   fault, order/first-last registration, continue notifications, nested handling,
   double/concurrent removal, invalid continuation and DLL retirement in a fresh
   isolated guest. Hash-bind the provider, kernel bridge and probe. A synthetic
   call into `ntwe_dispatch` proves neither fault ingress nor real resumption.

This staged map advances the kernel and application work together while preserving
their boundaries. It does not claim a full NT kernel, Win98 VEH, WDM or WDDM port.
