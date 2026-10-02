# FD5C2 — native Windows 98 personalization component

Scope owner: `/root/display_audit`. Shared isolated checkout:
`/root/Win98-Modern-laptop-security-fd5c-20261002`, initial HEAD `5e2f125`.
Root owns commits/index. This lane created only
`ntwddm/win98/personalization/` and this status file. Existing graphics, installer,
account ABI, kernel and ISO sources were not edited. Other agents' shared
checkout changes remain separately owned. Implementation is ready for root's
independent review; commit pending root.

Actual production code: `native.c` creates an ordinary native ANSI USER32
settings window, uses OLE32/IActiveDesktop for wallpaper application and
GDI32 through the existing NTWDDM Win98 DIB adapter for preview. Explorer is
retained as the intended desktop owner. `core.c` supplies two bounded procedural
scenes, 5/10/20 FPS, KR/EN, versioned validated preferences, pause/power policy,
and the offline finite HTML generator. `store.c` supplies exclusive-handle
publication, complete write/flush/close/readback, MoveFileA backup/rollback and
interrupted-save recovery. The application reports actual HRESULT/Win32
failures, uses static SPI wallpaper fallback, and stops automatic retry after
Apply failure. Opening it does not apply a wallpaper. Closing it tries to
freeze a requested wallpaper; the offline script independently stops after
five minutes. NTW64 accounts/elevation are explicitly unconfigured, with no
fake credential success and no PE32-to-PE64 call.

Animated Apply reads existing ActiveDesktop options and changes only its active
desktop flag, preserving the unrelated components' enable setting. Native combo
boxes participate in keyboard tab navigation.

Feature TDD evidence is in ignored `build/personalization-fd5c/red/`:
the initial compilable production core scaffolding failed its actual caller
fixture with 159 failures / 8,145 checks (exit 1), then the production
implementation passed. Initial store scaffolding failed with 12 failures /
22 checks (exit 1), then implementation plus broader failure coverage passed.
These are new-feature RED/GREEN proofs, not regressions against an existing
shipping feature. Initial strict fixture/SDK/link setup errors were corrected:
test indentation warning, legacy IActiveDesktop SDK exposure via wininet.h,
NTWDDM include path, and libgcc supplying the retained compiler stack probe.
No failed compile was reported as a behavioral RED or successful run.
The stricter actual-store error-preservation fixture subsequently found one
failure / 104 checks: GetFileSize access denial was being overwritten with a
record-format error. The production load now preserves the original API error;
the same fixture is GREEN, with its RED logs retained in `red/store-error-*`.

Final owned validation executed:

```sh
python3 -B ntwddm/win98/personalization/verify.py --out build/personalization-fd5c/final-v5
python3 -B ntwddm/win98/test.py
```

`final-v5/result.json` has `passed=true`, before/after matching source/tool/libgcc
hashes, actual cross-compiler project include closure, commands and output
hashes. GCC strict and Clang ASan/UBSan each passed 8,147 production core checks and
104 production store checks. Store evidence includes every boundary-call
failure on a successful publication and preferences load, short writes,
readback corruption, publication rollback, failed rollback retaining a
recoverable backup, stale temporary recovery and concurrent lock rejection.
Node passed 78 checks executing the actual generated script (not a copied
decision): motion, one pending timer, pause/resume cancellation, bounds and
expiry. Existing adapter regression passed 398,287 checks in each strict and
ASan/UBSan variant (`ntwddm/win98/build/host-tests.json`). Its callbacks model
host graphics boundaries; no Windows API execution is implied.

Real MinGW compilation linked the new native production sources plus existing
adapter/core/freestanding memory as i486, no-SSE/MMX, soft-float PE32 GUI 4.10.
The executable has only KERNEL32, USER32, GDI32 and OLE32 imports, all present
in `benchmarks/win98se-ko-oem-native-exports-v1.json`, no MSVCRT/KernelEx import,
and no TLS/load-config/delay-import/CLR/security directory. MoveFileEx is not
used. The build keeps compiler stack probing and records libgcc's actual hash.
Project include closure is checked; external SDK/import-library/compiler
dependencies are explicitly not a complete sealed toolchain closure.

Frozen production hashes from final-v5:

| File | SHA-256 |
| --- | --- |
| native.c | d44acfae145eb832b214bddc253b773f8bcb8aca95aa0353eae7c8359cf5270a |
| core.c | dc1d2146437908f76a05e0cd116761874e6fbb5a296f9a59fa3d8d8a8250cf69 |
| core.h | b1dcfb8ebdefbdcee88059d1d40b47d8103be40e8d9935104107400bf28eaa7f |
| store.c | b30edcf577bdef70babbbc5ee08422202dbb1037f242784348d94577d6b8778f |
| store.h | 193f16718004b9d3c6b369728383a0f5ebadb3ae8f89c79484900816379d8040 |

All other fixture, runner, shared input, binary, tool and log hashes are in the
receipt. README documents user controls, writable local installation directory,
on-disk files, failure/rollback limits, API references and the acceptance steps.
No auth, driver, private media, VM, download, public upload or ISO mutation was
performed in this lane. The build writes only bounded local ignored artifacts.

Remaining native acceptance: Windows 98 on ShizukuDOS USER/GDI rendering,
installed ActiveDesktop local HTML behavior, native file/rename/share semantics,
Korean system-code-page rendering, actual power notifications and failure
fallback, preservation of Explorer and unrelated components. The receipt has
`native_Windows98_executed=false`, `wallpaper_applied=false`,
`Explorer_verified=false`. Power transitions after abnormal settings-process
termination are not monitored; only the HTML timer bounds animation then. The
save protocol is not an atomic FAT transaction or a power-loss durability
guarantee. A cleanup failure may leave the new file present but reports failure.
Account GUI companion integration needs an actual NTW64 bridge; public installer
and ISO registration remain owner-controlled follow-up work.

Final EXE SHA-256:
`e6e11ba5d14b8191164d8d9e9a345a1d41723b7fadbec125b0b39b05294c2288`.
Final receipt SHA-256:
`b80d0f75dc34a068516351ada345d0a960e3b2779670881eabf0d1fbfda33ad7`.
