# Owned observer lifecycle for the Win98 global-theme control

`SHZGBOOT.EXE` is an argument-free `WIN.INI` startup parent for the fixed
`C:\VXDLAB\SHZOBS.EXE` observer. It does not apply a theme, edit a registry,
terminate a child, access a network, or resolve APIs dynamically. Its only
persistent writes are a newly created, bounded phase log. It accepts only its
exact own path `C:\VXDLAB\SHZGBOOT.EXE`, bare or quoted with optional surrounding
ASCII spaces/tabs, and no arguments. ANSI APIs and a CRT-free entry point target
i486 OEM Win98SE (Win9x platform 1, version 4.10, build low word 2222).

This is an OEM Windows 98 control lane. It does not establish that ShizukuDOS
has replaced MS-DOS underneath Windows 98, or that the Kernel32/Kernel64 bridges
serve that replacement system. Those architecture claims need their own native
boot and bridge evidence.

## Strict phase input

`C:\VXDLAB\SHZCASE.TXT` must contain exactly 60 ASCII bytes, with CRLF lines,
no BOM, NUL, whitespace additions or trailing data:

```text
SHZGCASE1
nonce=0123456789abcdef0123456789abcdef
phase=1
```

The nonce has exactly 32 lowercase hexadecimal characters; phase is exactly
`1` or `2`. The displayed example uses three CRLF terminators. A bounded
60-byte read followed by a one-byte EOF check validates the file. The parent
closes this input before opening an output. Invalid input or a failed input
close creates no phase log and launches no observer. Host staging must bind
both cold boots to the same nonce and private disk; the launcher alone cannot
establish that host relationship.

## Ordered successful record

After valid input, `CREATE_NEW` opens only `C:\VXDLAB\SHZGB1.LOG` or
`C:\VXDLAB\SHZGB2.LOG` for the selected phase. Existing files are never
overwritten. The complete record is ASCII with CRLF after every field, exactly
in this order. Numeric fields are unsigned decimal, with no leading zeroes
except the single digit `0`; the example's variable values are placeholders.

```text
HEADER=SHZGB1_V1
NONCE=<32 lowercase hex>
PHASE=1
BOOTSTRAP_PID=<actual GetCurrentProcessId>
BOOTSTRAP_PATH=C:\VXDLAB\SHZGBOOT.EXE
BOOTSTRAP_COMMAND_MODE=FIXED_PATH_NO_ARGUMENTS
OS_PLATFORM=1
OS_MAJOR=4
OS_MINOR=10
OS_BUILD_RAW=<actual full DWORD>
OS_BUILD_LOW_WORD=2222
OBSERVER_COMMAND="C:\VXDLAB\SHZOBS.EXE"
OBSERVER_WORKING_DIRECTORY=C:\VXDLAB
OBSERVER_INHERIT_HANDLES=0
OBSERVER_PID=<actual CreateProcessA dwProcessId>
OBSERVER_THREAD_HANDLE_CLOSED=1
OBSERVER_WAIT_RESULT=0
OBSERVER_EXIT_QUERY_SUCCEEDED=1
OBSERVER_EXIT_CODE=0
OBSERVER_PROCESS_HANDLE_CLOSED=1
LOG_FLUSH_OBSERVED=1
LOG_FINAL_FLUSH=REQUESTED_NOT_EXTERNALLY_OBSERVED
LOG_FINAL_CLOSE=REQUESTED_NOT_EXTERNALLY_OBSERVED
BOOTSTRAP_EXTERNAL_EXIT=NOT_OBSERVED
BOOTSTRAP_REQUESTED_EXIT=0
RESULT=NOT_A_FINAL_BOOTSTRAP_EXIT_VERDICT
```

Phase 2 changes only the header to `SHZGB2_V1`, the phase to `2`, and actual
nonce/PIDs/OS values as appropriate. The host must correlate `OBSERVER_PID`
with the independently emitted observer PID, reject duplicate or extra fields,
and validate the observer's complete palette/profile/Run and GUI evidence.

The application and mutable command line passed to `CreateProcessA` are fixed
to the observer path and its quoted path respectively, with no arguments,
`bInheritHandles=FALSE`, null security attributes/environment, flags zero and
working directory `C:\VXDLAB`. The parent closes the thread handle before
waiting at most 450,000 ms on its own process handle. Only `WAIT_OBJECT_0`
permits `GetExitCodeProcess`; only an actual successful query whose **full
DWORD** equals zero permits the successful record. A low-word zero such as
`0x00010000`, `STILL_ACTIVE`, a timeout or failed wait cannot pass.

## Failure and final-I/O semantics

Every failed API, short write, invalid identity, nonzero child exit or exceeded
bound returns the requested failure exit code `5`. Cleanup attempts to release
all owned child handles without terminating the child. After a failed close it
may retry that handle once. An observer can remain alive after a wait timeout;
the host owns the separate bounded guest epoch and rollback procedure.

Where a valid output handle remains available, failures append these fields
best-effort: `FAIL_STAGE`, `FAIL_ERROR`, `BOOTSTRAP_EXTERNAL_EXIT=NOT_OBSERVED`,
`BOOTSTRAP_REQUESTED_EXIT=5`, and
`RESULT=NOT_A_FINAL_BOOTSTRAP_EXIT_VERDICT`. A write failure may leave an
incomplete record. A failure after an earlier footer appends a rejecting
failure suffix; duplicate fields or any such suffix must be rejected. Failed
case input, log creation or persistent I/O can leave no usable log at all.

The first successful flush happens **before** `LOG_FLUSH_OBSERVED=1` is written.
The final flush and close happen **after** the footer and are therefore only
requested in that footer. Failure of either returns `5` and attempts a failure
append while the log handle remains usable. The process's actual final flush,
close and own `ExitProcess` completion cannot be certified by its own earlier
log. No footer, host fixture, import gate or intended exit code is an external
bootstrap exit verdict. The automatic HKCU Run restore process also has no
owned handle here and its external exit remains unobserved.

All write attempts, including partial and failure records, consume a
conservative aggregate allowance of at most 4096 bytes. There is no unbounded
polling, dynamic command input, theme mutation or `TerminateProcess` path.

## Host verification and native limitation

`launcher_host_test.c` includes the real launcher through `launcher_mock.h`.
Deterministic API models exercise both phases and full ordered successful
records, malformed/trailing case data, own path and argument rejection, OS
rejection, create/wait/query failures, full-DWORD nonzero exits, and
read/write/short-write/flush/close failures. Mocks are required to model Win98
APIs on the host; they do not execute a Windows guest.

The initial zero-return stub compiled and actually failed the owned
create/wait/query assertion before the implementation was added. Direct host
and sanitizer outputs are restricted to `/dev/shm`; the root coordinator owns
the separate native compiler/import gate and receipt. Neither host tests nor a
future PE import pass establish real Win98 process execution, two cold boots,
theme persistence, repaint correctness or final ShizukuDOS architecture.

Root's current source-bound build actually passed on 2026-10-01, including
5,374 completed host assertions and the same 5,374 under ASan/UBSan, plus all
13 shared native-import/resource regressions. Receipt:
`build/win98-global-theme-bootstrap/20261001T173408Z-7183decb/result.json`, SHA256
`a2e5083e48feff2e6af4a70f40976f8c00fbff228bdc04c19f21600cbd9e556f`.
The 13,897-byte `SHZGBOOT.EXE` has SHA256
`c42b8039c7e73f4337dbe7f64fba1f1ae465c44dbd53be1cc70b6f37c1558f1c`,
i486 PE32 OS/GUI 4.10, HIGHLOW relocations and 14 named OEM KERNEL32 imports.
The build output including the receipt is 2,166,965 bytes, within its admitted
8 MiB limit. The v2 trial's actual compiler/source-closure reader accepted its
ten command/source bindings. This is build evidence; the native trial,
observer completion, parent external exit and cold boots remain unverified.
