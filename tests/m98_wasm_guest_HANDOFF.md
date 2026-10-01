# Actual Win98 numeric WAMR probe

This additive probe exercises the unchanged twelve-function numeric C ABI from
the frozen `wasm-runtime-v24` build. It is separate from the private QuickJS
bridge. No browser WebAssembly object, current proposal completeness, DOM,
WebGL/WebGPU or application support is claimed.

The host and Win98 versions share the same real-engine test functions. Literal
oracles cover i32 overflow, i64 beyond double precision, multiple returns,
integer traps and output immutability, real load/store and memory growth,
zero-filled new memory, IEEE f32/f64 bits and signed zero, import callbacks and
reentry, callback traps, instruction/start-loop limits, real link/validation
failure, accounting, stale handles and complete store teardown. Every VM call
captures all 108 bytes of the caller's x87 state immediately before/after the
operation; the import deliberately clobbers its FP state. Host execution is
actual WAMR execution, with normal and instrumented engine objects from the
frozen runtime. It does not exercise Windows DLL loading or native APIs.

The native GUI executable is `C:\GOPLAB\WAS13PR.EXE`, loads only the exact
adjacent `C:\GOPLAB\M98WASM.DLL`, resolves every original named ABI export and
checks the original system MSVCRT path. It requires Windows 98 SE4.10.2222 and
ACP949. `C:\GOPLAB\WA13.LOG` is created with CREATE_NEW, contains the frozen
nonce, individual ordered checks and terminal totals, and is flushed/closed
before the real child exits. A failed check exits nonzero. File-write/flush/close
failures also exit nonzero; a partial log is never a successful run.

The builder requires a fresh owned build directory and an explicit nonce. It
pins the existing runtime receipt, current/frozen runtime sources, selected
original binary fixture bytes, prepared files, original build logs and reused
object-cache metadata/bytes. Generated arrays reproduce those original fixture
bytes; these are project-owned binary fixtures, not official conformance
modules. Original runtime files and caches are read-only. Host and native input
hashes are read again before the successful receipt is written. The original
runtime cache's compiler/version/local-header closure has a recorded limitation:
it does not prove the complete external compiler/system-header byte closure.

The new executable requires complete actual i486 disassembly-byte coverage,
PE32 GUI OS/subsystem4.10, relocations, a2MiB reserve/64KiB committed stack,
no modern PE directories and only actual OEM named imports. Static gates and
host tests leave native execution false.

Before any later native trial, create a separate independently tested owned
child observer, a frozen input/output stage and a strict stopped-run verifier.
The observer must obtain the actual child DWORD exit code and complete lifetime;
a log's STATUS or requested supervisor exit alone is insufficient. Use one new
private offline cold guest after the actual Win98 queue and resource floors
clear. Root CSS is ahead of this component in the queue. Preserve failures and
all original images, source archives and frozen stages. This builder launches
no VM and makes no global system changes.
