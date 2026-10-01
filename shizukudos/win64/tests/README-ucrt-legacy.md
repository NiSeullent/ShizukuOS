# Additive documented CRT helpers

This batch adds 13 named functions required by the actual Office client import
inventory. They are general runtime functions and contain no client names,
version checks, or application-specific success paths. Existing UCRT C sources,
module settings, and shared headers remain unchanged. The implementation is
new GPL-2.0-only code; no Microsoft or Wine CRT bodies are copied.

`fabs` uses the existing IEEE-754 bit helpers. `_mbschr`, `_mbsinc`, `_mbsdec`,
`_mbsnbcmp`, and `_mbsnbcpy_s` require the actual CRT C/POSIX single-byte locale
metadata. The secure copy delegates to existing `strncpy_s`, retaining its
range, zero-count, and `_TRUNCATE` behavior. The current locale provider accepts
only C/POSIX; this batch supplies no DBCS or UTF-8 CRT locale. A future changed
locale without a matching backend fails with `ENOSYS`, rather than pretending
its bytes are single-byte characters. Path encoding uses the actual kernel32
ACP conversion provider, consistent with existing CRT file helpers.

`_chmod` changes the real file's readonly attribute, preserving other metadata.
`_mktemp` checks actual disk names using the real process ID and the documented
26 letter candidates. It only accepts `ERROR_FILE_NOT_FOUND` as proof of an
absent name; missing directories and access/conversion errors fail honestly.
It does not create or reserve the file, as specified by this legacy API.
`_searchenv` uses an owned snapshot of the actual CRT environment, searches the
current directory before semicolon-separated directories, supports quoted
components, consumes overlong components completely, and publishes only a
checked absolute real file path. `_wgetdcwd` uses actual directory, volume,
and heap providers, with checked second calls and allocation cleanup. Drive zero
and an explicit current drive return the genuine current directory. The actual
kernel32 backend stores one process CWD, and CRT startup does not retain `=X:`
per-drive environment entries. An existing non-current drive therefore returns
NULL with `ENOSYS` and Win32 error 120 instead of presenting the provider's
`X:.` root fallback as a retained directory. Full per-drive behavior remains an
unsupported backend requirement; v1 evidence is preserved separately.

`_wassert` emits its actual UTF-8 stderr diagnostic and invokes the existing
SIGABRT/default abort implementation. This provider has a console route; no
GUI assertion dialog is fabricated. `system` finds the real COMSPEC or PATH
command interpreter, resolves the genuine `GetBinaryTypeW` capability, and
accepts only AMD64 executables supported by the actual process backend. It
uses actual process creation, inherited standard handles, wait, exit status,
and handle cleanup. Missing capability, absent files, incompatible executable
formats, and execution failures retain errors. A DOS/16-bit COMMAND.COM is
not an executable backend for the current AMD64 runtime. No installed working
command interpreter or positive native shell execution is claimed by this
source batch; a fake interpreter child is not used as evidence.

`_resetstkoflw` returns zero with `ENOSYS` and Win32 error 120. Actual kernel
stacks are fully committed, their StackLimit equals DeallocationStack, and
generic one-shot PAGE_GUARD has no overflow recovery/growth protocol. Merely
changing an arbitrary live stack page's protection would not recover that
stack. Genuine recovery requires a separate kernel stack contract, outside
this additive runtime scope.

Primary references were read at Wine commit
`db11d0fe6a169c457e23d007e20404643d067aa8`, in
[mbcs.c](https://gitlab.winehq.org/wine/wine/-/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/msvcrt/mbcs.c),
[dir.c](https://gitlab.winehq.org/wine/wine/-/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/msvcrt/dir.c),
[file.c](https://gitlab.winehq.org/wine/wine/-/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/msvcrt/file.c),
[process.c](https://gitlab.winehq.org/wine/wine/-/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/msvcrt/process.c), and
[misc.c](https://gitlab.winehq.org/wine/wine/-/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/msvcrt/misc.c).
Microsoft documents
[_chmod](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/chmod-wchmod?view=msvc-170),
[_mktemp](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/mktemp-wmktemp?view=msvc-170),
[_searchenv](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/searchenv-wsearchenv?view=msvc-170),
[_wgetdcwd](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/getdcwd-wgetdcwd?view=msvc-170), and
[system](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-170).
The specific `_mbsnbcpy_s` documentation has inconsistent zero-count wording
with its generic `strncpy_s` mapping and Wine's observed CRT tests. This batch
explicitly retains the existing genuine secure-copy C-locale contract,
including zero-count termination, and does not copy Wine's DBCS branches.

`test_ucrt_legacy_host.py` compiles the exact three new C files plus existing
`string.c` and `ctype.c` with isolated symbol names. GCC and Clang ASan/UBSan
check libc byte/string/math oracles, all 256 byte values, secure-copy errors,
file/environment/path/provider failures, allocation and handle ownership,
assertion diagnostics, and two pthreads. OS functions are explicitly host
contract adapters; their successful results are not native backend evidence.

`t_ucrt_legacy.c` uses actual DLL imports and real file attributes, directory
and environment APIs, heap allocation, per-thread errno, a real assertion
subprocess, and missing-shell errors. It creates files with CREATE_NEW and
restores only the environment entries it owns or snapshots. Failed worker
waits terminate the fixture before releasing an event used by a live worker.
The integration owner alone executes this fixture and the target applications.
Host tests and native import closure do not establish that a complete app runs.
