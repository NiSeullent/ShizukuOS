# Bounded registry-call diagnostic

`probes/registry_trace.asm` is a source-written DOS COM parent wrapper, not a
Windows fix or successful boot receipt. It executes one explicit DOS83 path
ending in `WIN.COM`, for example `REGTRACE C:\WINDOWS\WIN.COM`. An independent
host preparation must pin that actual selected Windows file and disk. The
wrapper checks the target with read-only open/read/seek/close before installing
vectors: MZ, oversized and invalid paths are unsupported. Its intended current
target is a verified flat COM image; `.COM` alone never admits an MZ image.

The wrapper retains its own memory while invoking the original DOS EXEC 4B00
service. An intercepted call queries the original AH51 current PSP, checks its
PSP parent against the actual wrapper PSP, and admits the first direct child
only when caller CS equals the child PSP. It then accepts only that PSP.
Relocated or different executable layouts can therefore produce no trace;
such a result is a diagnostic limitation, never evidence of a DOS failure.
The parent relationship and memory footprint differ from direct shell EXEC.

The hooks forward original services and record only registry pathname classes,
tracked handles, caller CS:IP, actual PSP, input AX/BX/CX/DX, returned
AX/BX/CX/DX/SI/DI/BP/DS and FLAGS. Exact selected-directory SYSTEM.DAT and
USER.DAT paths come from the explicit WIN path, compared case insensitively
within 79 bytes without copying any pathname or file buffer into the log.
INT21 3D, 4301, 3E, 3F, 40, 42 and 68 are eligible; operations on untracked
handles are passed through without records. INT2F 1611 returns are observed,
including unsupported returns. Shell pointers are never dereferenced, supplied
or repaired. No registry header, hive contents, Microsoft code, or product key
is copied into the log. WIN itself retains its original file operations.

An active guard chains reentrant calls directly to the old vector. Input
registers and entry flags are restored before forwarding, the old handler
receives the original interrupt FLAGS frame, and every output register and
returned FLAGS reaches the caller unchanged. The ring holds 128 records and
sets an explicit overflow word before passing subsequent calls through.
Overflow refuses a completed diagnostic, rather than wrapping or claiming
success. Logging performs no DOS file writes inside an intercepted service.

The private binary layout is little endian: `RT21`, version 1, count, capacity,
overflow and admitted child PSP form a 14-byte header. Each 36-byte record has
18 words: vector, input AX/BX/CX/DX, caller IP/CS, PSP, pathname class
(0=none, 1=USER, 2=SYSTEM), output AX/BX/CX/DX/SI/DI/BP/DS/FLAGS.
FLAGS bit 1 absent marks a pending call whose return was not observed. A reader
must reject incomplete header, count over capacity, overflow, or truncated
records. A pending call may be retained as an explicit incomplete observation;
its zero output fields cannot be interpreted as successful returns.

Before EXEC, a source-written message emits the bounded metadata buffer's
segment:offset and keeps the announcement visible for 54 BIOS ticks (about
three seconds). It atomically reads the BIOS Data Area timer without changing
the clock or consuming the INT1A midnight flag. Backwards movement, invalid
day counts, or a jump beyond 108 ticks refuses execution, except for a single
normal midnight rollover. A finite 0x04000000 poll bound refuses a stalled
timer; no keyboard input is required. If WIN never returns, a separately reviewed owned VM capture
may save exactly these 4622 bytes while preserving guest execution, and the
private result is inspected only after that VM has been stopped and reaped.
No such VM/capture acceptance follows from host tests. If WIN returns, the
wrapper verifies both vectors still belong to it, restores them, and uses CREATE_NEW for `C:\REGTRACE.BIN`;
existing output, empty log, overflow, short/failed write or close fails with
exit code 1. A partial output from failed writing remains private and invalid.
If the callee installed another vector, the wrapper refuses to overwrite it
or free memory that may remain in its chain: it marks header status 2 and
retains its memory through DOS31 with failure status. Its disabled hooks only
chain thereafter. Exit code 0 means a complete diagnostic file, never a
Windows desktop.

Build with NASM `-f bin`. `tests/test_registry_trace.py` executes the actual
assembled hooks and startup in Unicorn with explicitly modeled DOS services.
It covers register/FLAGS preservation, successful handle lifecycle, CF and
short-count propagation, unrelated paths, case handling, identity refusal,
ring overflow, reentrant chaining, unsupported 1611, segment wrap, malformed
CLI, format gates and failed EXEC vector restoration. The added pause tests
execute the same assembled timer routine with an explicitly reduced 16-poll
stall budget; progressive/rollover tests preserve caller registers and IF.
They model BIOS ticks and do not claim real BIOS timing measurements. It does not execute real
Windows, hardware, protected mode, or actual filesystem writes.

The original author’s [RBIL release 61](https://www.cs.cmu.edu/~ralf/files.html)
defines 1611 as shell parameters with executable and counted-command pointers;
this diagnostic observes its status without manufacturing those pointers.
The cached original Part C archive is pinned independently by the coordinator.

Path classes are exact words 0, 1 or 2 for every recorded operation, including
tracked reads, seeks, writes, commits and closes. The logger explicitly clears
AH before storing a handle-derived class. Earlier artifacts could retain the
input function AH in that word: such a binary is invalid under this schema and
must never be accepted by masking its high byte. A separately labeled recovery
observation may retain its raw values and explain the source defect; it is not
a successful typed trace or Windows receipt. The exact-word regression control
covers both USER and SYSTEM through all handle operations, including nonzero AL.
