# Genuine WTF failure diagnostics

The retained real WTF v5 caller was executed in the original IO.SYS UEFI/GOP
Win98 SE guest in trial l. The reviewed guest displayed an abnormal-program-
termination dialog for `WTFNAT.EXE`. Both stopped log files had zero-byte FAT
lengths. This establishes an observed failure, without identifying its cause
or the last completed initializer. Empty logs do not establish absence of
execution. Root retains the exact guest/firmware/PE evidence separately.

The original caller's stdio log remains open across engine initialization and
closes on normal return. The new `core_wtf_diagnostic.cpp` is a separate copy;
it retains the genuine engine operations, archive members and runtime. Its
`core_Win9xDiagnosticLog.h` writes each checkpoint through actual
`CreateFileA`/`SetFilePointer`/`WriteFile`/`FlushFileBuffers`/`CloseHandle`.
Every operation must succeed. Log failures prevent a successful caller exit.
Unique before/after fields cover initialization, current thread, main RunLoop,
memory monitor, loop execution and teardown. The original v5 source, binaries,
frozen manifests and receipts remain unchanged.

The diagnostic link uses `--wrap=abort` with ordinary C `__wrap_abort` and
`__real_abort` declarations. MinGW adds its target underscore and links
`___wrap_abort`; the raw routed reference is `_abort`. The wrapper records the actual return PC,
process image base, thread ID, fixed-lifetime fresh nonce and interlocked main/
worker phase values to separately closed `C:\GOPLAB\WTFABRT.LOG`, then calls
the genuine CRT abort. That path uses a fixed stack buffer, no heap and no
stdio formatting. This covers only direct symbol references actually routed
by GNU ld. Independent aborts internal to a system DLL are not intercepted.

`core_link_wtf.py --diagnostic` requires at least the unchanged 20 GiB floor
plus 256 MiB margin and a 128 MiB selected output allowance before starting.
It retains real pre/post WTF/bmalloc members and pins the caller object across
linking. Acceptance requires actual disassembly of the wrapper forwarding to
real `_abort` and direct cxa/emutls sites reaching the wrapper. The diagnostic
fixture also freezes the exact header/caller and those disassembly receipts;
its two outputs are `WTFNAT.LOG` and `WTFABRT.LOG`. Root adds its external owned
process observer and `WTFEXIT.LOG` for actual post-CRT exit evidence.

The first diagnostic attempt, `wtf-native-diagnostic-v1`, completed its real
pre-link member snapshots, then the host free-space guard killed only the
owned compiler session during caller compilation. It produced no PE or
linking result. The failing receipt and exact failed source/header copies
are retained. This is a resource interruption, not a demonstrated compiler
or engine defect.

The second attempt, `wtf-native-diagnostic-v2`, completed the real caller
compilation, then failed linking with an undefined `_real__abort`. Its exact
caller/header/link-tool bytes and failure receipt are retained. A separate
small, never-executed linker control established MinGW's automatic target
underscore handling; the diagnostic source now uses the ordinary C names and
`--wrap=abort` above. Genuine-engine routing still requires the subsequent
actual PE's cxa and emutls disassembly; the small control is not engine or
Windows 98 runtime evidence.

The subsequent `wtf-native-diagnostic-v3` genuine link passed the whole PE
import and retained member/runtime gates. Its actual disassembly showed both
`___cxa_thread_atexit` and `___emutls_get_address` calling `___wrap_abort`, which
forwards to the real `_abort`. Its exact compiled source copies are retained.

The final `wtf-native-diagnostic-v4` additionally keeps the ordinary bounded
loop, monitor stop and worker wait running after a post-`CreateThread` logging
failure, then returns 11 at the final sticky error check. Its compile, link,
pre/post genuine-member gates and both actual abort routes passed. The PE SHA
is `794b466f5ec3666d5f0b24bdadf8433dc2271977aad8e1e53e9abe067761a8ff`;
its receipt SHA is `0cbc2c1c9ddf6d7dfaf85b2c1712f9d9f4d58e9b5a49d151725123f38d901c5c`.
The new `frozen-wtf-observed-diagnostic-v4/guest-files.json` fixture is ready
with two exact input PEs, 32 copied source receipts and three absent output
paths. Its SHA is `df3ffbf7e09cee1a62af4c1946c4b3d320e55866c2e3c333c889b05da6746454`,
and its fresh nonce is `83bd-wtf-5731440b6a314952b8c21a269e816832`. The selected
closed-handle external observer SHA is
`3525172a001240c90187e85a88231853ee0fcfd19b4da9c2a9aa5699b9916a31`.
Every frozen input and receipt hash was rechecked. Actual Windows 98 execution
with sufficient resource headroom remains required; no successful engine
initialization, JSC, renderer or graphics acceleration is established by this
compiled/static and frozen-input evidence.

A focused read-only inspection also ruled out attributing the earlier popup
to the deliberate W CryptoAPI probe. `cmakeconfig.h` centrally defines the
Win9x profile, and the actual standalone RandomDevice object calls the ANSI
acquisition function. That RandomDevice function is not linked into either
the original v5 caller or diagnostic v4; their acquisition calls are the
caller's deliberate measurements. The new native phase/abort-PC records are
needed to identify the actual initializer failure.
