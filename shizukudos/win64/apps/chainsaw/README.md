# CHAINSAW

Native ShizukuOS process cleanup companion. It queries and executes the
Kernel64 `NtShzSaw` service. It never substitutes a Win32 single-process kill
for the native teardown service, and it does not claim RM/PSP contexts for
processes that have none.

```
CHAINSAW /list /verbose
CHAINSAW /zombies
CHAINSAW SAW 1842 /verbose
CHAINSAW SAW muzik.exe /nuke
CHAINSAW SAW 1842 /charbomba --ack-destructive=1842:42
```

The desktop Run dialog routes the complete `SAW` command to this executable
once the separately reviewed launcher patch is integrated. Native arguments
remain arguments; there is no command expansion. Process names must be exact,
case-insensitive names, at most 31 ASCII characters, and match exactly one
accessible row. Partial names and ambiguous matches never mutate a process.

Diagnostics use the existing native console output path. A desktop Run launch
currently exposes that output through the kernel/serial console and does not
create a desktop terminal window. Attach the existing console to read detector,
teardown and destructive-warning messages; a GUI console is still required for
an ordinary desktop-only command experience.

The detector uses the kernel's concrete lifecycle/resource contradictions.
Running, blocked, waiting and suspended state alone never establishes a
zombie. Protected ownership is displayed separately from zombie class.
An admitted zombie is intentionally retained object state, with the kernel
reason displayed, and is not automatically removed.

Every mutation binds the snapshot's PID and non-reused generation. NUKE asks
the kernel for its acquired process tree; it does not repeat a user-mode
single-process routine. The output reports actual acquired targets and actual
completed teardown steps. Pending, admitted, protected, malformed and failed
results never produce `SAWED`.

CHARBOMBA always displays a destructive warning. It requires the explicit
`--ack-destructive=PID:GENERATION` argument matching the selected snapshot
identity, followed by the kernel's independent privilege checks. There is no
implicit `/force`, automatic escalation or pretend interactive console prompt.
This acknowledgement exists because the current native console does not yet
provide a proven interactive confirmation consumer. A stale acknowledgement
cannot authorize a recycled PID. Successful forced teardown can still destroy
system invariants; this command does not promise recovery.

Exit codes: `0` detector/help or fully completed teardown; `1` backend error,
protection/refusal or invalid result; `2` syntax/target/acknowledgement rejected;
`3` pending or admitted state retained. Retained process object references may
still be queryable after real execution/resources have ended.

`tests/test_args.c` checks mutually exclusive modes, numeric overflow and
target-bound acknowledgement. `tests/test_reply.c` checks that pending,
admitted, protected and invalid identities cannot be claimed complete. These
are host policy tests; actual OS execution is a separate required milestone.
The normal Win64 producer discovers this directory automatically and installs
the executable at `\SHZ\SYS64\CHAINSAW.EXE`.
