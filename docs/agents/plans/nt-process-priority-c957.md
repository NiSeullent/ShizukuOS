# Native process priority compatibility slice

User-approved parallel work in an isolated branch based on reviewed `8603a05`.
Actual Windows 98 retains VMM/USER/GDI/Explorer ownership. This is an UP
Kernel64/Win64 compatibility component, with online mask 1 and no AP admission.

1. Preserve current production and capture meaningful failing contracts for
   raw process information class 18, incorrect basic base priority, missing
   getter access checks and inert process background mode.
2. Independently review the two-byte native ABI, separate native ordinals from
   Win32 flags, and verify retained process-object lifetime and existing
   two-pass retargeting before changing code.
3. Add a shared ABI/ordinal helper. Reuse the existing referenced-process
   retarget core from raw NT and private Win32 transports. Support the five
   non-realtime classes with Foreground zero; reject unsupported scheduling
   modes without changing policy or renewing a grant.
4. Add native class 18 query/set routing. Query requires either process QUERY
   or QUERY_LIMITED, uses a held object and an IRQ-protected metadata snapshot,
   and returns exact two-byte information. Both short and oversized class-18
   buffers return INFO_LENGTH_MISMATCH with required length 2; failed return-
   length writes report ACCESS_VIOLATION. Set requires SET. Preserve exited
   process queries while refusing setters during termination/teardown.
5. Route public Get/SetPriorityClass through the native transport. Reject
   process background BEGIN/END until actual resource scheduling exists;
   remove the related DLL-only memory-priority report. Derive the process
   basic base priority from the same existing class mapper.
6. Extend the host fixture with actual production query/set/wrapper bodies
   and process schema, plus a guest probe. Validate ABI, rights, reference
   balance, relative and saturated threads, newly initialized threads, late
   batch rollback, exit/reuse and unchanged queue/grant invariants.
7. Independently review the final source, run fresh GCC and Clang sanitizer
   contracts and real translation-unit compiles, then freeze the complete
   actual C/header closure for fresh component kernels and frontend DLLs.
   Run the bounded actual guest probe against those exact artifacts.
8. Commit only reviewed public source/tests/docs and publish a sealed source
   handoff through shared mailboxes to the other chats. They own integration
   into their newer canonical source epoch and its fresh verification.

The website is already deployed; this lane uses no private media, NAS
allocation, native Windows VM, large remaster or final ISO promotion. Existing
PMA thresholds, original failed receipts and unresolved native acceptance stay
unchanged. Component passes do not establish full modern-app, SMP or Windows
98 replacement-DOS acceptance.

Primary contracts: Microsoft GetPriorityClass and SetPriorityClass; ReactOS
NDK PROCESS_PRIORITY_CLASS and process query implementation; Wine process
wrapper. The selected modern getter subset permits QUERY or QUERY_LIMITED.

Native ordinal 0 is the declared UNKNOWN value; this setter subset rejects
it with INVALID_PARAMETER rather than treating it as a default class.
Existing process information classes retain their prior access/length contract;
only class 18 gains the selected modern query-right alternative in this slice.

Sources: [Microsoft GetPriorityClass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getpriorityclass),
[Microsoft SetPriorityClass](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass),
[ReactOS native ABI](https://raw.githubusercontent.com/reactos/reactos/master/sdk/include/ndk/pstypes.h),
[ReactOS query/set implementation](https://raw.githubusercontent.com/reactos/reactos/master/ntoskrnl/ps/query.c).
