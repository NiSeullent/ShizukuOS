# Default console handles and independent observations

The current UEFI GOP component VM ran all 151 ordinary test programs but
`T_K32_SYS.EXE` reported four failures in its first console observations. The
loader granted the default input handle only `GENERIC_READ`, and the output and
error handles only `GENERIC_WRITE`. `GetConsoleScreenBufferInfo` requires read
access, so the actual output handle failed before its geometry could be read.

[Microsoft's GetStdHandle contract](https://learn.microsoft.com/en-us/windows/console/getstdhandle)
and [Console Handles](https://learn.microsoft.com/en-us/windows/console/console-handles)
specify read/write access for initial console handles. A caller may replace a
standard handle with a handle carrying fewer rights.

The loader now grants `GENERIC_READ | GENERIC_WRITE` to its three newly created
console handles. The default backing objects carry the same access. An explicit
`CONIN$` or `CONOUT$` open records the caller's requested access; its handle grant
also remains that requested value. Endpoint identity stays separate from access.
Inherited handles, `STARTF_USESTDHANDLES`, and `SetStdHandle` are unchanged.

The original four `T_K32_SYS` conditions and diagnostic order remain. Their
observations are captured before printing the four results: printing uses the
same console and can move its cursor. No assertion was removed or weakened, and
the program retains its 94-check guest contract. The host test runs only the
four affected assertions, not the entire 94-check program.

## Host validation

```sh
python3 -B -W error::ResourceWarning tools/verify_std_console_access.py \
  --repo . --out build/std-console-host-new
```

The harness extracts actual source bodies for console creation, the loader's
default handle block, handle insertion and lookup, `GetStdHandle`, endpoint and
access validation, and the screen model. Allocation, native-query transport,
PEB storage, ASCII output, and locks are host boundaries. It launches no guest.

Each compiler runs four controls: original rights produce four assertion
failures; fixing rights alone leaves a logging interference failure at the
valid cursor position `(7,24)`; fixing rights and capturing observations passes
all four; corrupting the production geometry still fails an original assertion.
The logging control establishes independence for a legal nonzero cursor; it
does not claim that this cursor was observed in the failed VM.

The passing case additionally checks default input/output/error identity and
rights, explicit zero/read/write/read-write opens, reduced duplicate rights,
`SetStdHandle`, redirected ordinary files, input versus output, invalid handles,
and constructor allocation failure. GCC with warnings as errors and Clang with
AddressSanitizer and UndefinedBehaviorSanitizer each pass all eight case groups
in total. Four complete native/standalone kernel objects and the complete
MinGW test source compile with production flags.

The earlier GOP failure and host compilation failures remain saved separately.
These host checks do not replace a fresh coherent build and the required VM
rerun. They do not establish Windows 98 boot, replacement of MS-DOS, genuine
modern application execution, or final ShizukuOS 1.0.0 acceptance. ShizukuDOS,
Kernel32, and Kernel64 remain components serving the genuine Windows 98 goal.
