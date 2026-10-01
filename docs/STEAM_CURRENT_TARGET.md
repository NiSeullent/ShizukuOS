# Current Valve Steam desktop target

Status on 2026-09-30: official desktop binaries acquired and inspected; real cooperative AMD64 fibers implemented and host-validated. The actual baseline standalone Kernel64 trial failed before process creation on the missing `ConvertThreadToFiber` export; revised-runtime startup and login/library/installation/game launch remain unverified. The coordinator owns guest execution against a private consistent runtime snapshot. A Steam web page or SteamCMD does not establish desktop-client compatibility.

## Publisher target and reproducibility

The [official win64 publisher manifest](https://cdn.fastly.steamstatic.com/client/steam_client_win64) retrieved for this task identifies version `1788652215`, publisher OS type `win10`. Its SHA-256 is `40ec2f2aac99fb65c62b7b60db77e8e1575e0c8b59cfeba80294eeb1c963731c`. Valve's [32-bit Windows support notice](https://help.steampowered.com/en/faqs/view/49A1-B944-48B8-FF00) makes the current native 64-bit client the target; the older win32 manifest is not a substitute.

`tools/steam_client_corpus.py` fetches only the official HTTPS publisher hostname, bounds download and expansion, verifies exact manifest size/SHA-256 for each ZIP, and rejects escaping paths, symlinks and conflicting Windows path identities before extraction. Identical publisher files shared between packages are retained once with both package owners recorded. Authenticode and the manifest's embedded signature have not been verified independently.

The acquisition directory is ignored: `build/steam-assessment-01a0f3d0cb43/`. Its `receipt.json`, `steam_client_win64.manifest`, `files.json`, `archives/` and `client/` retain the artifact identity. Eleven core English desktop packages total 308,652,653 download bytes and 720,684,637 expanded bytes, producing 5,624 distinct files. Optional codecs, hardware-specific packages, other languages, movies and sounds are not included. The tool supports a bounded `--all-packages` acquisition when those packages become necessary.

The inspected tree contains 87 PE images: 57 AMD64 and 30 original i386 helpers. Architecture fields and executable code were not rewritten. Representative original images:

| Image | Architecture | SHA-256 |
| --- | --- | --- |
| `steam.exe` | AMD64 | `48ea0576865d2dfda26001b7b210c3f7559d46e647424cd11704eb1ea842fe5a` |
| `steamclient64.dll` | AMD64 | `caba4826aa3501039d095aee1843a6bfb270fb43a3ab4455b2d6733223579fee` |
| `bin/cef/cef.win64/steamwebhelper.exe` | AMD64 | `f9ee1d1cc0f06fad16c9a277136a2e1b00b6b668901e28454a7dd8af29afde0d` |
| `bin/cef/cef.win64/libcef.dll` | AMD64 | `c85bf94462b3c79baeac63823db52d15e116eead71ea414e5d3a112c59e434d3` |

`steam.exe` imports `GetVersionExA`, `MulDiv` and the fiber family. Its `WSOCK32.dll` dependency is an ordinal thunk `#1142`; pefile's `GetAcceptExSockaddrs` name is only a hint. The audit preserves the real ordinal. The root agent owns ANSI version/integer scaling, and the Chromium agent owns the Winsock1 module and real address decoder. CEF's eager/delay imports and genuine graphics, networking, crypto, sandbox and process behavior remain part of the client target.

## Implemented fiber prerequisite

`shizukudos/win64/kernel32/k32_steam_fiber.c` implements forward/reverse conversion, allocation, cooperative switching and deletion on actual distinct stacks. It saves/restores all AMD64 nonvolatile integer registers, floating-point/SIMD state and Windows TEB stack/FLS/activation-context identity. Created fibers support synchronized migration between threads. Reverse conversion preserves the current FLS values without destructor calls. A narrow helper in `k32_core.c` detaches suspended FLS data and invokes callbacks without holding the slot lock; deletion reentry is guarded.

Original kernel thread stacks retain kernel ownership until thread teardown. Deleting their converted-fiber descriptor does not release a stale kernel-owned address. Cross-thread migration of these converted original stacks fails explicitly with `ERROR_NOT_SUPPORTED`; ownership transfer requires further kernel work. Independently created fibers can migrate. Other known limits are permanent low-page protection instead of automatic stack growth, existing FLS slot-generation/rundown limits, and retention until process teardown of an independently created stack that is reverse-converted or exits while executing. These branches are stated and exercised by the guest regression rather than reported as full Windows compatibility.

This is original code following the [Microsoft fiber contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-switchtofiber) and [AMD64 ABI](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170). Pinned Wine `db11d0fe6a169c457e23d007e20404643d067aa8` and ReactOS `f06eace89e11b6513afcf65b653f2d360db7ba77` implementations were read before implementation; reference URLs/hashes, pre-edit common-file snapshots and the exact own helper diff are recorded under `fiber-references/` and `fiber-build/`. No upstream implementation was copied.

## Additional genuine startup APIs

`k32_steam_io.c` implements ordinary default-stream `CopyFileExW` through real file reads/writes, handles partial writes, and passes actual byte counts to stream/chunk callbacks. CANCEL and `pbCancel` remove partial output, STOP retains completed bytes, and QUIET continues without further callbacks. Invalid flags, unsupported source/destination storage attributes and cancellation are checked before destination mutation; FAIL_IF_EXISTS preserves an existing file. Successful copies preserve ordinary file attributes and timestamps. Restart checkpoints, alternate streams, security descriptors, EFS/reparse/sparse/compressed storage and special I/O modes still need filesystem support and are not claimed.

`k32_steam_state.c` validates a real process handle and allows the only actual scheduler CPU mask (`1`). Process SET_INFORMATION access enforcement inherits current kernel limitations. Its heap query enumerates the actual registered heaps, safely rejects destroyed/foreign handles, and reports the actual standard first-fit allocator mode (`0`), with required length and bounded output. Unsupported information classes fail explicitly; it does not claim LFH. `t_steam_io.c` covers these real guest contracts.

The root's `k32_steam_compat.c` ANSI version/integer-scaling implementation was independently reviewed. `test_muldiv.py` compares the production arithmetic against an exact Fraction nearest-distance oracle: 54,913 boundary/random cases pass with undefined-behavior trap instrumentation. `t_steam_compat.c` checks ANSI basic/extended structure guards, invalid-size no-write behavior, manifest-less reporting and signed rounding/endpoints/overflow. Their MinGW Werror object compilation passes; guest API execution is pending.

## ANSI UI and display information imports

`user32_steam_text.c` reuses the existing actual UCRT formatter following the Wine glue's legacy wide-string option and 1024-unit output policy. It supports the documented integer/string subset including Windows `%S` and `%I64` forms; unsupported floating/dynamic-width formats and non-ASCII cross-width text fail explicitly. The latter requires future UTF-8 ACP conversion because the underlying CRT implements the C locale. Same-width UTF-8/UTF-16 text is preserved. The clean user32 module dependency adds `ucrtbase` without an import cycle.

The new ANSI title-length query converts actual Unicode window text to the configured code page. `DialogBoxParamA` preserves ordinal resource pointers or converts a strict UTF-8 named resource and runs the real existing modal dialog engine. All existing ANSI window APIs on this runtime retain Unicode callback procedures; full ANSI message thunking remains outside this change.

`gdi_steam_ic.c` creates a measured primary-display information context without a drawing bitmap. A small private `info_only` flag makes the generic DC getter reject it for drawing, while real capability queries and deletion accept it. Printer/other-device initialization and further information-DC query methods remain unsupported. `t_steam_text.c` with actual dialog resources tests formatter bounds/syntax, real supplementary-Unicode title byte length, modal resource identity/result, information caps, drawing refusal, unchanged pixels and deletion. Production/guest Werror and resource compilation pass; actual guest execution is pending. Graphics checks explicitly report SKIP without an actual display. The exact clean before/after helper changes are recorded in `ansi-build/own-clean-helper.diff` and `source-receipt.json`.

## Validation and guest gate

Fourteen corpus regressions pass, including archive boundaries, exact shared-package identity, architecture/forwarder honesty and ordinal thunk preservation. The production fiber/core source and `t_steam_fiber.c` compile with MinGW `-O2 -Wall -Wextra -Werror`. The host harness executes the production Microsoft-ABI context-switch assembly on separate mmap stacks: **70,548 checks and 10,251 switches passed**, including floating-point control restoration, synchronized created-fiber migration and explicit original-stack migration rejection. The host FLS/TEB adapters do not verify the real guest registry or kernel. The production copy helper additionally passes 1,324 real-file checks with injected partial/failed/zero writes, progress, cancellation, existing destinations and metadata arguments under undefined-behavior traps; its host metadata adapters do not prove guest metadata behavior.

`t_steam_fiber.c` is prepared to verify actual guest FLS/TLS identity, callback reentry, stack bounds/protection, 1,101 switches, created migration, reverse conversion, original-stack deletion/teardown ownership, explicit original-stack migration limit and current-fiber deletion. Its runtime result is pending. `fiber-build/source-receipt.json` records exact source/object identities and compile results.

The completed baseline trial is recorded in `/root/Win98-Modern-apps-cb43/build/modern-apps/steam-baseline/serial.log` and `result.json`: the original AMD64 executable maps, then the loader rejects missing `KERNEL32.dll!ConvertThreadToFiber` with `c0000139`. This observed blocker motivated the real fiber implementation. No Steam process output or desktop window was reached. Input hashes are recorded in `input-receipt.json`.

The actual first probe uses the original executable with `image=D:\steam\steam.exe`, `cmdline=steam.exe -console`, `cwd=D:\steam`, and a bounded 90-second observation. The coordinator supplies the generic Steam runner and private guest runtime. Preserve serial logs, import-binding failures, screenshots, source/image hashes and observed exit status. Host PE export presence is not an application startup result. Kernel64 guest results are also distinct from booting Windows 98 through its intended runtime bridge.

Completion requires a visible desktop Steam client, authentication, usable library, an installed test game launched through the client, and a clean shutdown on the intended Windows 98 Modern path. Any native service or i386 helper dependency encountered must be supported or truthfully blocked; neither PE machine rewriting nor success-only API stubs establishes that behavior.
