This closed measurement uses the original Windows 98 SE 4.10.2222 kernel
`GlobalMemoryStatus`, `GetSystemTime` and `GetTickCount`. Each resolved pointer
must equal its named native Kernel32 export and belong to a committed immutable
executable native image section. Installed KernelEx, if present, must provide
the existing pinned original-export resolver. No compatibility API is accepted
as the measurement source.

`MEMSTAT.EXE` creates `C:\VXDLAB\MEMSTAT.LOG` with CREATE_NEW, records API
identity and captures three immediate snapshots before writing any snapshot
output. Every eight-digit hexadecimal field is a raw unsigned DWORD. UTC
timestamps bracket each API call; tick deltas use unsigned modulo-2^32
subtraction. The status API returns VOID and has no failure return contract.
Its actual last-error observation is captured immediately and is informational.
Length, load range, buffer canaries and available/total relations are checked;
raw values are retained even on a failure. Flag 32 marks a DWORD_MAX count,
which may represent the documented 32-bit limitation and is not itself a
failure. No 64-bit estimate, RAM adjustment, reclamation or setting change is
made. Zero totals alone are not assigned an invented API failure meaning.

`MEMWAIT.EXE` creates its own fresh `MEMWAIT.LOG` before child creation, verifies
the entire exact child image hash and EOF, refuses a pre-existing child log,
starts that fixed child with original OEM APIs, and waits 30 real seconds.
A timeout or failed wait triggers termination with 124 and a five-second reap;
that branch always fails. Acceptance requires a real signalled process with
exit 0 plus a fresh, fully readable, nonempty child log under 16 KiB. Read,
write, flush and close failures fail the diagnostic. Its own operating-system
exit still requires an independent observer. The child log should subsequently
be inspected for all three snapshot records; the outer only proves the
process result and log readability, not the truth of reported hardware values.

Microsoft documents the raw structure, volatile snapshots, DWORD limitations
and VOID result in the primary sources recorded in `contracts.json`. Their
modern supported-OS tables do not establish historical Win98 availability.
That is grounded here in the pinned actual OEM Kernel32 export table and the
runtime original-OS/export guards. Host controls test bounded raw formatting,
immutable inputs, relation flags, DWORD_MAX and tick wrap; they do not execute
the kernel API. Native observations remain pending. The CMOS 7240 KiB figure
is a hypothesis until the installed guest produces these snapshots.

Only the two new classic PE32 GUI 4.10 inputs and their two log paths are in
the generated staging plan, within existing per-input budgets. The builder
does not stage files or run a VM. Application success remains false; this
measurement does not establish graphics resources or modern app execution.
