# Held process memory and working-set queries

User-approved continuing parallel Windows 98 integration. ROOT isolated tree
`/root/Win98-Modern-nt-memory-c957-20261002`, base independently reviewed
`372b697aca45b71cd58247dfcd225fce1f916c32`. Its exact eight-path predecessor
is committed/clean and handed off source-only to other chats. The actual
canonical pma-integration tree accepted a read-only applicability check; ROOT
did not apply there. Other chats own native ESP/Win98 boot, Supervisor/AP and
modern-app builds. No ROOT NAS allocation, private media, VM or ISO work.

## Established gaps and selected contract

Q8/K32Q_PROCESS_MEMORY and Q9/K32Q_WORKING_SET_EX currently use raw
proc_of_handle, with no query-access check or held reference. Q8 samples peaks
before its separate snapshot guard, permitting owner departure or slot reuse
in between. Q9 reads a VAD pointer, page tables and vlock state without one
target guard, and ignores ReturnLength copy failure. Actual process_teardown
swaps and frees PML4 while handles may remain open; actual VAD growth replaces
and frees its descriptor array. A reference alone cannot protect these walks.

Use modern Windows rights for the selected existing public consumers:
GetProcessMemoryInfo requires QUERY or LIMITED; QueryWorkingSetEx requires
full QUERY. Neither modern contract adds VM_READ. Q8 also serves
GetProcessInformation(ProcessAppMemoryInfo), whose LIMITED access must remain
supported. XP/Server2003's stricter memory-info QUERY-and-VM_READ contract is
outside this modern personality slice. Do not change existing public formats
or add PMC_EX2, PSAPIv1, invalid-page extensions, AWE/large-page support.

Only production path: `shizukudos/kernel64/sysk32_proc.c`. Preserve Q8's five
uint64 counters/40-byte output and Q9's 16-byte in/out entries, existing page
attributes, peak/accounting providers and per-entry progress. Keep old Q3,
Q5, Q17/Q18, setters, ABI header, frontend wrappers and all other classes
byte-identical. No proc/object/loader/VAD/page-table/provider/AP source edits.

Q8 acquires the unchanged ref_query_object with QUERY-or-LIMITED alternatives
before any target read. Under one outer IRQ guard, resolve o->u.proc.p and
verify p is used and p->object == o. Invalid identity returns INVALID_HANDLE.
For this private live-memory subset, terminated or teardown targets return
PROCESS_IS_TERMINATING. A missing live pml4 returns INVALID_HANDLE. These are
chosen backend refusal semantics, not claimed exact Windows exit/error
precedence. Inside that same guard call unchanged sample_peaks (nested IRQ)
and capture all five actual fields. Restore and drop the reference before
put_out of local data. Preserve existing required-size, short-buffer and
ReturnLength/output-fault precedence; every path balances reference/IRQ.

Q9 acquires full QUERY before length/input access, keeps the reference across
the batch, and rejects zero/nonmultiple-of-16 lengths with
INFO_LENGTH_MISMATCH. Verify the same identity/live-pml4 predicate under an
initial guard before any input copy. Each entry input copy occurs outside the
target guard. Under a new guard resolve/revalidate the same held object and
active process, then execute actual vad_find, vm_lookup, v->prot and vlock_find
and finish the local attribute scalar. Invalid/nonpresent/nonuser pages retain
the existing zero-attribute subset. Restore before the output copy. Repeat
identity/active checks for every entry, since user copies may permit another
thread to change or tear down the target. On any failure restore/drop and
return its status; previously copied entries remain copied. After all entries,
drop the reference, write optional ReturnLength=(uint32)len and propagate a
copy failure as ACCESS_VIOLATION. No whole-batch atomicity is promised.

## Independent ownership and validation

1. Freeze a dedicated host C/Python before production changes. Reuse the
   corrected owned-group producer exactly, with bounded timeout/interrupt
   refusal and pending FAIL until all commands/maps are sealed. Canonical
   header selections must use full paths, not basename overwrite. Read actual
   SDK counter/working-set schemas and retain their input pins. Execute actual
   query cases, wrappers, ref/handle/close/final process-free, sample_peaks,
   VAD lookup/growth and page-table walk/lookup/count/free where portable.
   Declare physical mapping, frame allocation/free, CR3/invlpg, scheduling,
   copy and lifecycle hook boundaries explicitly. Do not fabricate feature
   results through a fake memory-query transport or fake page flags.
2. Review fixture and producer before one pristine baseline RED. Cover Q8
   QUERY-only/LIMITED-only/combined success and Q9 full QUERY/combined success,
   all denial combinations, actual tag/type/high/closed handles and identity,
   reference/IRQ balance, chosen live-space refusal, short buffers, copies,
   ReturnLength faults and untouched oversized tails. Existing Q3/Q17/Q18
   contracts and memory-info/AppMemoryInfo reporting subset remain intact.
3. Model departures only at an actual unguarded seam. At sample_peaks' outer
   restore, execute actual close/final-free before explicit slot republication
   to expose Q8 wrong-owner snapshot. With a retained handle/reference, actual
   process_teardown must still swap/free PML4, detecting a reference-only weak
   fix. At actual VAD lookup/page-table lookup boundaries, actual VAD-array
   replacement/free or process teardown should expose Q9 unguarded stale data.
   The new outer guard must exclude that modeled departure. Observe guards
   and references in the actual providers. Include local nonempty output
   surviving departure after guard/ref release, partial batch departure,
   rejected copy, and retained terminated refusal. State modeled storage
   reuse openly; do not infer native allocator UAF or AP/SMP safety.
4. After meaningful RED, ROOT alone implements the one production file and
   two reviewers inspect it. Run frozen identical fixtures with GCC and
   Clang ASAN/UBSAN plus actual affected translation units. Run unchanged
   strict-query/time/priority regressions once. Independently rehash paired
   source/tool/artifact/body/header maps and actual raw logs.
5. Guest author appends only to t_k32_proc.c, preserving all previous 620
   checks and unchanged 654 priority probe. Cover independent rights, real
   allocated/touched/protected/locked/decommitted pages with existing actual
   providers, exact guarded counter/entry sizes, natural remote child lifetime,
   retained exit refusal and close/count restoration. Any forced cleanup is
   separate from natural completion. Freeze/independently review source and
   expected count before actual compile/link.
6. Freeze fresh actual CPP closure, four kernels, two selected DLLs and probes
   through new-prefix reviewed producers. Keep the historical T_HELLO-only
   qualification. Preflight and run one bounded UP KVM guest with exact API
   counts, both app0/fault0, all35 distinct PMA PASS, zero CPU1 failure summary,
   done0/SHZ-EXIT0, expectedQEMU1/noTimeout/reaped and all input maps stable.
   Final reviewed source-only commit/handoff requires no native/AP/whole-ISO
   acceptance claim and preserves predecessor original failures.

Actual Windows 98 retains VMM/USER/GDI/Explorer ownership. Host and standalone
UP checks remain components. Native desktop, full current runtime, modern
apps, installer/final ISO, original PMA361 and diagnostics remain open.
External full sysroots, compiler support libraries and Python internals are
not sealed. Preserve every initial setup/compile/behavioral failure.

Primary contracts:
[GetProcessMemoryInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo),
[QueryWorkingSetEx](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-queryworkingsetex),
[GetProcessInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessinformation),
[working-set attributes](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-psapi_working_set_ex_block).
