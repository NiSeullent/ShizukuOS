# FD5C NTW64 handle lifetime

Date: 2026-10-02 (Asia/Seoul). Baseline:
`a648e9baa1c57289d50e58d3380827bd9239bc52`.

Assigned scope: prevent closed NTW64 client handles from becoming valid again
when their 13-bit generation is exhausted. Windows 98 remains the product OS;
these are existing wrapper-local records for Shizuku backend processes, not
Windows kernel handles or a new object subsystem.

Owned files:

- `ntwin32/win64/ntw64.c`
- `ntwin32/win64/tests/handle_lifetime_host.c`
- `ntwin32/win64/tests/mock/windows.h`
- `ntwin32/win64/tests/test_handle_lifetime.py`
- `docs/agents/status/FD5C_HANDLES.md`

## Root cause and change

The original global counter cycles from 1 through 8,191 and back to 1. With
repeated reuse of record zero, creation 8,192 returns the same handle as creation
one. The original closed handle then observes the newly created process through
`NtwWaitProcess64`, contradicting the wrapper's handle-lifetime contract.

Generation now belongs to each record. Successful creation increments that
record's retained generation, saves it across initialization of the other
record fields, and never wraps. Existing close and deferred cleanup paths retain
the generation history. Failed creation does not consume a generation, and
failed remote release retains the original record and handle state.

An unused record at generation 8,191 is retired. Other records remain available;
after all eight records retire, creation returns false with
`ERROR_TOO_MANY_OPEN_FILES` (4) and a null output handle before sending a remote
CREATE request. The existing tag, record index, 13-bit generation encoding,
wire structures and message family are unchanged. Caller serialization remains
the documented requirement.

## Evidence

The original source compiled successfully under GCC and Clang ASan/UBSan, then
failed the stale-handle rejection assertion on creation 8,192. It also failed
the independent per-record generation assertion following a failed deferred
release. Failure-path tests passed on the original and remain preserved as
regressions. The first temporary test compile used the wrong argument-field
name; correcting it to the existing `block_bytes` field preceded the recorded
red execution. Original red log: `build/fd5c-abi/handles-red.log`.

`python3 -B ntwin32/win64/tests/test_handle_lifetime.py` passes all three
scenarios under both GCC strict warnings and Clang ASan/UBSan:

| Scenario | Checks per compiler | Observed simulated starts/releases |
| --- | --- | --- |
| All eight records through full generation exhaustion | 2,162,440 | 65,528 / 65,528 |
| Failed CREATE, failed close/retry and remote NOENT cleanup | 175 | 4 / 4 |
| Close while running, failed deferred release and later reuse | 117 | 3 / 3 |

The fixture includes the actual production `ntw64.c` and calls its public APIs;
it does not copy the allocator or inject replacement client functions. Only
Win32 device/error/time callbacks are modeled. The device callback validates the
production CREATE/RELEASE payloads and supplies bounded reply/EXITED frames.
The public handle oracle checks stale rejection, per-record reuse, availability
of a different record after retirement, and no remote CREATE after exhaustion.
No source-private record fields are patched or reset during these scenarios.

The production client also compiles with the installed i686 MinGW SDK using
freestanding i486 flags, strict warnings, no SSE/MMX and no stack protector.
Object: `build/fd5c-handles/ntw64-i486.o`. This compile checks the actual 32-bit
Windows declarations; the lifecycle host executables use a host calling
convention and do not establish native stdcall or Windows loading behavior.

Green log: `build/fd5c-abi/handles-green.log`. Per-compiler compile/scenario logs
and executables: `build/fd5c-handles/`. No network, installation, guest or global
client settings were changed.

## Handoff

Dependencies: root owns Git integration and coordinates the VxD concurrency,
new ABI payload and wrapper-manifest lanes. Those files were not edited here.

Blockers: none for this bounded repair. Independent display reviewer approved
the exact production source606fe5108d90885abc89748cb4a289186a17e59d8a373ca9873efefbbde4c148.
Root freshly reproduced all three scenarios under both compilers. The existing
linked-DLL end-to-end regression also passed in root's final transport/IPC tree:
actual NTW32.DLL and NTW64RUN.EXE PE32 code, all10 expectations true and216 slots.
VMM/Kernel64 callbacks are modeled; this does not establish Windows loading.

Bounds and remaining work: each loaded wrapper instance can successfully issue
at most 65,528 process handles before retiring its entire local table. Retaining
the finite ABI and returning a real resource error is intentional. The guarantee
applies within that wrapper instance's lifetime; no cross-DLL-unload persistence
was introduced. Native Windows 98 VMM/channel2 positive acceptance, transport
restart/rundown ownership and concurrent callers remain separate work.

Code commit SHA: `8c51a72`. This agent made no Git index, commit or
remote mutations.
