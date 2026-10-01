# Native Windows98 QUERY client

This original client calls the canonical one-owner PMA VxD endpoint through
`\\.\NTWRAP9X.VXD`. It uses an actual Windows auto-reset event and synchronous
`DeviceIoControl`; the registering thread also waits, receives and closes.
The VxD supplies authoritative VM/process/thread lifetimes. The client never
supplies user-selected identity, domain, channel epoch or wire sequence.

Initialize `struct ntwp_client client = {0}`. Open with a finite1..60000ms
timeout, call QUERY, then close on the same Windows thread. An open client,
pending query or incompletely closed local handle cannot be overwritten by a
second open. The client validates exact ticket/result correlation, endpoint and
PMA info layout/features, channel generation and monotonic64-bit `now_ns`.
Backend `now_ns` belongs to its own clock; `GetTickCount` only bounds local waits.

A QUERY ticket-copy failure, invalid completion or timeout keeps admission
uncertain, so another QUERY remains blocked until CLOSE. Local timeout is not
backend cancellation. CLOSE retries BUSY at the endpoint's20ms polling cadence
within a finite deadline. Handles remain retained until a successful status0
rundown response. A local CloseHandle failure after that response is retried
without requesting another backend PROCESS_EXIT. Failed registration remains
a failure; local handle disposal does not establish backend acceptance/rundown.

The exact native contract is REGISTER20/QUERY21/TAKE22/CLOSE23 with input
16/0/0/0bytes and output32/16/96/4bytes. No OVERLAPPED request is used. TAKE must
remain retained in the native adapter until validated user copy and unpin
succeed. CLOSE acknowledgement must survive a failed user copy; the current
peer adapter's post-dispatch CLOSE copy path requires that owner's resolution.
The client keeps the VxD resident by omitting delete-on-close, but cannot fence
an explicit VxD unload/reload against a retained backend epoch. The native owner
must provide persistent sequence/incarnation or proven new channel generation.

`probe.c` builds `PMAQUERY.EXE`. When actually run on Windows98, it checks the
OS identity, authoritative registration, denial of a foreign native thread and
process, two queries across two registrations, matching channel and monotonic
clock, increasing request/lifetime identifiers and confirmed PROCESS_EXIT.
It writes `PMAQUERY.LOG` (foreign child: `PMAFOREIGN.LOG`) and exits nonzero on
failure. It must execute in a fresh private guest output directory with its
same-named EXE available for the child. Root owns native boot/log capture.

Validation command, before the native endpoint is imported into this worktree:

```text
python3 -B ntwin32/pma/test.py --endpoint-root /root/Win98-Modern-pma-20261002 --out build/pma-client-unique
```

The runner requires a new output directory, captures all client inputs and the
exact endpoint/bridge/public ABI headers, compilers/internal native tools/import
library and compiler-discovered native SDK headers, rejects input changes, runs production
client C through modeled Win32 boundaries under GCC and ClangASan/UBSan, and
builds a real i486 PE32 executable with MinGW. An independent PE decoder checks
OS/subsystem4.0, no modern DLL flags, only the20 used Windows95/98 KERNEL32 API
imports and no CRT. This proves source behavior and build shape. It does not
prove loaded VxD callbacks, native event delivery, actual backend rundown,
replacement DOS boot, Windows VMM execution or SMP.

Preserved initial client failures: event-handle retry failed at test line146;
uncertain QUERY admission after ticket-copy failure failed at line160; repeated
open destroyed retained state and failed at line170. Their fixes and further
stale-notification, busy/deadline and GetTickCount-wrap controls passed251 host
assertions before20ms cadence alignment, then245 under GCC and sanitizers with
the final cadence. Final receipts retain all actual commands and source/tool
dependencies; no actual Windows/VMM execution has been performed by this lane.
