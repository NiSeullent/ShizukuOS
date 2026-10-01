# Manual Windows 98 marker probe

`PERSCHK.EXE` is a source-built ANSI/i486 PE32 console testing probe with no
CRT imports, OS/subsystem 4.0 and only old Kernel32 APIs. It has no default
mode, path or nonce. It is never installed into normal startup/configuration.
Building it or running the host boundary model proves no Windows execution,
GUI, shutdown, true cold boot or persistence acceptance.

The operator chooses a **new** root file on `C:` and an independently recorded
64-character ASCII hexadecimal nonce. Names use 1..8 ASCII letters/digits or
underscores and an optional 1..3-character extension. The literal `C:\` prefix
is required. Device stems, traversal/directories, streams, wildcards, spaces,
trailing dots, non-ASCII and known boot/configuration/system filenames are
refused. Reserved device checks are case-insensitive, including COM0..9 and
LPT0..9 with extensions. Filename/nonce case is preserved. Mode is exactly
lowercase `create` or `verify`; quoted executable paths are supported, while
the three arguments use simple unquoted tokens. Entire commands are bounded
to 511 bytes and contain printable ASCII or horizontal whitespace only.

For an explicitly selected unused example path and a host-selected **actual**
nonce, manual invocation is:

```text
PERSCHK.EXE create C:\PERS0001.DAT ACTUAL_64_HEX_NONCE
```

The example nonce label is invalid and cannot produce a marker. Creation uses
`CREATE_NEW`, exclusive `GENERIC_WRITE`, complete positive-count short-write
handling, checked `FlushFileBuffers` and checked `CloseHandle`. Existing files
are refused. On any failure, the existing or partial file is retained as
unaccepted; the probe never overwrites, appends, deletes or adopts it.
Successful creation is followed by reopening through a fresh exclusive
read-only handle. Verification requires the exact 75-byte extent (high DWORD
zero), complete read including short-read handling, exact content, an extra
one-byte read yielding EOF and checked handle close. The exact file format is
ASCII `PERSCHK1 `, the literal 64 hexadecimal characters, then CRLF.

After a separately evidenced **real cold boot**, invoke the independent mode
with the same host-recorded path and nonce:

```text
PERSCHK.EXE verify C:\PERS0001.DAT ACTUAL_64_HEX_NONCE
```

`verify` uses only `OPEN_EXISTING`/`GENERIC_READ` on the target. Each invocation
checks the actual `GetVersion` result for Windows 98/98 SE (4.10 with the
Windows 9x flag). That API check itself cannot establish a native VMM or rule
out an emulated API environment. The probe issues no shutdown/reboot command.
`FlushFileBuffers` and a successful fresh read do not independently prove
power-loss durability. The external controller must establish the original
Windows run, cold-boot transition, new Windows run and independent disk/file
readback; host model or build receipts cannot supply those facts.

Success is exit zero **and the complete matching output**, bounded to 128
bytes, `PERSCHK CREATE VERIFIED path nonce` or `PERSCHK VERIFY VERIFIED path
nonce` followed by CRLF. Output uses complete short-write handling. Any API,
extent/content, owned handle-close or stdout failure returns nonzero. Stdout
is borrowed and is not closed. A failed stdout write can leave partial output;
partial output alone is never acceptance. Failure output is `PERSCHK FAILED`
with CRLF where stdout remains usable. Codes: 10 arguments, 20 OS version,
30 stdout handle, 40 exclusive create, 41 target write, 42 flush, 43 write
close, 50 read open, 51 extent, 52 read, 53 EOF, 54 content, 55 read close,
60 success-output write. A close failure overrides an earlier file error.

Run the bounded host controls and actual PE32 build in a fresh ignored local
output directory:

```sh
python3 -B ntwin32/persistence_probe/test.py --out build/persistence-probe-NEW
```

The runner tests the production C entry/API with GCC and Clang ASan/UBSan
against modeled WinAPI, then builds `PERSCHK.EXE` with the actual i686 toolchain.
It checks actual cgroup/host memory and local space before and during each command,
monitors the 64 MiB output budget, spools at most 1 MiB of raw output per command,
limits each child-created file to 8 MiB and confines compiler temporary files to
its owned output. Overflow or timeout kills the owned process group and reaps
its leader before returning failure. Actual child flood, oversized temporary
file and descendant timeout controls exercise these boundaries. It records full
command/raw logs, source hashes, observed
SDK header dependencies, actual compiler/assembler/linker/import-library hashes,
and their before/after equality. It independently parses the resulting PE
headers and exact named imports, hashes those parsed bytes and checks the final
executable still matches before publishing the result. Host shared-library dependencies are outside
that tool closure. Controls include existing files, partial failures, short
I/O, zero/oversized counts, EOF, every marker-byte mutation, extent, flush/close,
stdout, version and bounded parser/path/device refusals. Every receipt keeps
Windows/cold-boot/persistence/GUI acceptance false. No private Windows media,
NAS, VM, installer or startup file is changed by these controls.
