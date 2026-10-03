# NTW64RUN execution and relay results

`NTW64RUN.EXE` is the existing native Windows 98 PE32 frontend for the
ShizukuCore long-mode execution path. It starts a real PE32+ process through
NTW32/VxD/W64 IPC and relays its ordered console bytes. It does not implement
the missing native Windows 98 connection for x64 application windows or input.

The frontend now preserves its own failures independently of the remote exit
code. Previously a console receive failure selected 255, then a successful
wait could replace it with the remote process's exit 0. Input reads/sends,
stdin close, stdout writes and process release could also fail without changing
the result. Those failures now return 255 even if the remote process exits 0.
An error diagnostic is attempted; an unwritable stderr cannot be made reliable.
Successful relay still returns the actual remote status, including 7,
`0xC0000005` and 255. Remote 255 remains indistinguishable from frontend 255;
that is the existing command's exit-code convention.

A successful native short write advances only by the written prefix. A false
write is never retried; zero progress or an impossible reported length fails.
This follows the synchronous [WriteFile result and byte-count contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile).
Native stdin pipe closure is EOF, following the
[ReadFile pipe contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile).
The existing early-child broken-pipe behavior remains valid. Receive/output
failure requests remote termination once, then still attempts wait and release.
Wait/release failure also remains a frontend failure. There is no replay through
another backend and no fabricated successful process result.

Run the focused host controls and actual PE compilation from the checkout:

```text
python3 ntwin32/win64/tests/test_runner_result.py --out build/ntw64run-result-NEW
```

The output directory must be new. GCC and Clang ASan/UBSan each execute 26
scenarios against the literal production `run()` body with modeled Win32 and
NTW32 callbacks. Controls preserve binary bytes and short-write order, real
remote statuses, expected EOF/broken pipes, failures before/after creation,
transport/cleanup failure and malformed callback lengths. `--baseline PATH`
executes a preserved old production body and records its expected RED results;
it is not a passing product qualification. The actual i486 PE32 frontend build
checks OS/subsystem 4.10, the original eight NTW32 imports and eight classic
KERNEL32 imports against the pinned public OEM export manifest, and absence of
TLS/delay imports/CLR/load configuration. Source hashes before/after, compiler
commands, artifacts and every failure remain in the component receipt.

These are host-model and compile checks. No application or VM executes here.
The command still forwards stdin before reading output and waits indefinitely
for a terminal remote response. Existing service backpressure and the sole VM
owner's external deadline/reaping remain necessary. A native capsule trial must
identify original Windows 98 USER/GDI/Explorer, execute `/q` and an archive-pinned
`T_HELLO.EXE`, observe its actual output and remote exit 7, and verify the
negative bridge/image/ABI cases. Native GUI/application functionality needs its
separate frame/input bridge and fresh exact-app tests; it is not proven by this
frontend result correction.
