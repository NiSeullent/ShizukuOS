# ShizukuDOS 10.0 — Electron target: measured import coverage and phased plan (ELECTRON_TARGET)

Companion to `BASELINE.md` and `STATUS.md` (same evidence vocabulary: `SOURCE` · `BUILT` · `HOST_TESTED` · `GUEST_RUN`).
Everything numeric in this document is `HOST_TESTED`: a static PE audit of three real Win64 products against the DLLs
this tree builds, produced by `shizukudos/win64/tools/import_coverage.py` and committed under `docs/shizukudos10/coverage/`.
Nothing here is a claim that any of these applications runs on Kernel64; no guest run of them exists (section 12).
The one dynamic data point (section 9) comes from Wine on the Linux host and is labelled as such.

Measured at tree revision `2e079ac` (head of `wip/shizukudos-10-toydzv`), Win64 runtime built with
`python3 shizukudos/win64/build.py` (x86_64-w64-mingw32-gcc 13-win32). The user32/gdi32 track and the kernel32 track live on
other branches and are **not** in this tree; section 6.1 measures the user32/gdi32 sources of `integ2-dryrun` (`e384399`)
read-only so that track can see its own distance to the target.

## 1. Inputs (pinned)

| product | archive | tree | main image | version resource | embeds |
|---|---|---|---|---|---|
| Electron v44.4.5 win32-x64 | `electron-v44.4.5-win32-x64.zip`, 158,184,819 bytes, sha256 `11c395820a5aaa8ebcc0686b476d0ac98a730274ebfbdc8cf5538a7c2815cb5d` | 368 MB, 7 AMD64 PE images | `electron.exe` 246,032,896 bytes, sha256 `bd14928e0728366fd3f41499cb398ff3f4304dab259a3e605077899a6f8c748e` | FileVersion 44.4.5 | `Chrome/152.0.7977.130` |
| VSCodium 1.135.06055 win32-x64 | `VSCodium-win32-x64-1.135.06055.zip`, 250,898,961 bytes, sha256 `0bec978f201238624bc9ad43966f5e201ed8afacc37d77035a822252d9c9c200` | 712 MB, 39 AMD64 PE images (+9 ARM64/i386 skipped) | `VSCodium.exe` 222,056,960 bytes, sha256 `0a00f7fad6c4106f479d8123bfcf23693eda136220b22247e0cced5c634eead0` | FileVersion 1.135.06055 | `Chrome/148.0.7778.280`, `Electron/42.8.1` |
| Chromium Win_x64 snapshot 1706750 | `chrome-win.zip`, 358,617,751 bytes, sha256 `804da77eb033ac837a559f259c7e831d9440c28697f6647e860b123a410949a7` | 725 MB, 18 AMD64 PE images (17 measured) | `chrome.exe` 3,098,112 bytes, sha256 `50e3f9ee0aa1c2d55bde01aa822c7a91fa558fa73fdf2648d05bc00b2ba2c93e`; `chrome.dll` 334,176,256 bytes, sha256 `5a36d13089083cc3e84831bcac6f22d373217c00350d63d8492bc499371aae4c` | FileVersion 157.0.8079.0 | — |

Electron v44.5.0 (the version first requested) has a tag but no win32-x64 release asset (HTTP 404); v44.4.5 is the
newest 44.x with a Windows x64 build and is what Discord/VS Code-class applications of this generation ship.

Shizuku side (`build/shizukudos/win64`, `build-result.json`): advapi32.dll 47, bcrypt.dll 11, bcryptprimitives.dll 1, combase.dll 17, kernel32.dll 221, modtest.dll 2, ntdll.dll 256, ole32.dll 23, oleaut32.dll 38, rpcrt4.dll 12, shell32.dll 7, shlwapi.dll 44, version.dll 3, winmm.dll 7, ws2_32.dll 57. `modtest.dll` is a test fixture and never matches an
import. The kernel64 API-set schema (`shizukudos/kernel64/ldr.c` `apiset_schema`) has 29 entries in this tree.
Ordinal imports were named with the export tables of Wine 9.0's PE builds installed on this host
(`/usr/lib/x86_64-linux-gnu/wine/x86_64-windows`, package `wine64 9.0~repack-4build3`); Wine keeps Windows' ordinals, and
the tool records that source in `next.json` (`ordinal_ref`).

Reproduce (the committed JSON is the output of exactly this):

```
python3 shizukudos/win64/build.py
python3 shizukudos/win64/tools/import_coverage.py \
    electron=<electron tree> vscodium=<vscodium tree> chromium=<chrome-win> \
    --exclude interactive_ui_tests.exe --exclude '*/psreadline/*' \
    --top 40 --next 300 --summary-dir docs/shizukudos10/coverage --matrix docs/shizukudos10/coverage/matrix.json
```

Exclusions: `interactive_ui_tests.exe` (364 MB Chromium test binary, not part of the product; with it Chromium measures
18 images, 345/1415 = 24.4%) and the four `Microsoft.PowerShell.PSReadLine*.dll` under `resources/app/.../psreadline/`
(PE32 i386 managed assemblies for PowerShell; they are skipped as non-AMD64 anyway, so the exclusion changes no number).

## 2. What the tool measures (definitions)

* **distinct import** — one (system DLL or contract, function) pair; imports of DLLs shipped in the application tree are
  internal and are not counted; imports of `node.exe` by the VSCodium native addons (93 functions in 17 `.node` files)
  are all exported by `VSCodium.exe` and count as internal ("host-exe").
* **provided** — the function is in the export table of the DLL this tree builds. Nothing is said about behaviour.
* **load-time** vs **delay-load** — from the import directory versus the delay-import directory. A load-time import
  must resolve before the image runs at all; a delay-load import is resolved by the application's own CRT helper
  (`__delayLoadHelper2`: `LoadLibraryExA` + `GetProcAddress`, writing a delay IAT that lives in `.data`) at first call.
* **load closure** — the root executable plus every shipped DLL it imports at load time, transitively. `electron.exe`,
  `VSCodium.exe` and `chrome.dll` have no shipped load-time dependencies (`ffmpeg.dll` is delay-loaded);
  `chrome.exe` pulls `chrome_elf.dll`, and then loads `chrome.dll` with `LoadLibraryExW` at run time.
* **dll-missing** — the DLL is not built in this tree. **fn-missing** — the DLL is built, the function is not exported.
  **apiset-unmapped** — an `api-ms-*`/`ext-ms-*` name absent from the ldr.c schema; the loader fails such an import with
  `STATUS_DLL_NOT_FOUND` (ldr.c:316) even if the host DLL exists, so it blocks the load on its own.
  **ordinal-unpinned** — imported by ordinal into a Shizuku DLL; no Shizuku `.def` file pins ordinals (0 `@` lines
  in all 15 `.def` files), so the number resolves to whatever the linker put at that position (section 7).
* **effort classes** used in the plan: **S** ≤ 1 person-day, **M** 2–5 days, **L** 1–4 weeks, **XL** more than a month
  or a new kernel subsystem.
* **explicit-failure implementation** — a function that returns its documented failure code (and sets the last error),
  is listed as unsupported in the module and has a test asserting that failure. This is the only acceptable form of
  "not implemented" under BASELINE §5 / ldr.c's "nothing is silently stubbed"; a function that returns success without
  doing the work is a fabricated stub and is never proposed here.

## 3. Headline numbers

| application | AMD64 images | distinct imports | resolve today | coverage | root-image load closure: unresolved load-time functions |
|---|---:|---:|---:|---:|---|
| Electron 44.4.5 | 7 | 1,308 | 332 | **25.4 %** | `electron.exe`: **297** = kernel32 227 (of 409 imported), winmm 28 (of 31), crypt32 28 (DLL absent), ws2_32 11 (of 54), ntdll 2 (of 11), dwrite 1 (DLL absent); version 3/3 resolve |
| VSCodium 1.135.06055 | 39 (+9 skipped) | 1,686 | 373 | **22.1 %** | `VSCodium.exe`: **297**, same DLL breakdown as electron.exe |
| Chromium 157.0.8079.0 | 17 | 1,385 | 343 | **24.8 %** | `chrome.exe`+`chrome_elf.dll`: **100** (all kernel32; ntdll 13/13 and version 3/3 resolve); `chrome.dll` (run-time): **287** = kernel32 219, winmm 28, crypt32 26, ws2_32 13, dwrite 1 |

Across the three: **1,457 distinct unresolved (DLL, function) pairs** — dll-missing 775, fn-missing 530,
apiset-unmapped 143, ordinal-unpinned 9. Per Shizuku DLL, distinct functions imported by any of the three (missing/total):
kernel32 292/485, advapi32 114/156, winmm 29/32, ole32 28/48, shell32 27/34, ws2_32 17/65, oleaut32 8/28, combase 7/15,
ntdll 6/33, shlwapi 5/13, bcrypt 4/12, rpcrt4 1/3, version 1/4, bcryptprimitives 0/1.

The load-time picture is much narrower than the totals suggest: the Electron-class executables import only **seven**
system DLLs at load time (`kernel32`, `ntdll`, `version`, `winmm`, `ws2_32`, `crypt32`, `DWrite`) and defer everything
else to delay-load — 48 delay-only DLLs/contracts for electron.exe, 47 for VSCodium.exe, 55 for chrome.dll (§5),
`user32`/`gdi32` included. M1 is therefore a kernel32 problem (227 functions) plus two small DLLs and three partial
ones, not a 1,457-function problem. VSCodium.exe's 227 kernel32 names differ from electron.exe's only in
`IsThreadAFiber`/`lstrcmpiW`; chrome.dll's 219 include 25 names electron.exe lacks (`FoldStringW`, `LCMapStringEx`,
`FindFirstVolumeW`/`FindNextVolumeW`/`FindVolumeClose`, `GetVolumeNameForVolumeMountPointW`,
`GetVolumePathNamesForVolumeNameW`, `Module32FirstW`/`NextW`, `K32GetModuleFileNameExA`/`W`, `K32GetMappedFileNameW`,
`QueryDosDeviceW`, `SetDllDirectoryW`, `SetThreadExecutionState`, `GetFirmwareType`, `IsProcessInJob`, …) and lack 33
of electron.exe's (console, pipe and packaging names).

## 4. Image lists

**electron images (7 AMD64 images; skipped 0)**

| image | file bytes | SizeOfImage | subsystem | load-time system DLLs | load imports | delay imports | ordinal |
|---|---:|---:|---|---|---:|---:|---:|
| `electron.exe` | 246,032,896 | 236.0 MiB | GUI | crypt32.dll, dwrite.dll, kernel32.dll, ntdll.dll, version.dll, winmm.dll, ws2_32.dll | 537 | 747 | 12 |
| `dxcompiler.dll` | 25,745,408 | 24.6 MiB | DLL | advapi32.dll, kernel32.dll, ole32.dll, oleaut32.dll, user32.dll | 145 | 0 | 0 |
| `vk_swiftshader.dll` | 5,520,384 | 5.4 MiB | DLL | gdi32.dll, kernel32.dll, user32.dll | 133 | 0 | 0 |
| `d3dcompiler_47.dll` | 4,741,488 | 4.6 MiB | DLL | advapi32.dll, kernel32.dll, rpcrt4.dll | 131 | 0 | 0 |
| `ffmpeg.dll` | 3,113,472 | 4.5 MiB | DLL | kernel32.dll | 100 | 0 | 0 |
| `dxil.dll` | 1,509,760 | 1.5 MiB | DLL | advapi32.dll, api-ms-win-crt-convert-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1, api-ms-win-crt-utility-l1, kernel32.dll, ole32.dll | 127 | 0 | 0 |
| `vulkan-1.dll` | 939,520 | 0.9 MiB | DLL | advapi32.dll, cfgmgr32.dll, kernel32.dll | 120 | 0 | 0 |

**vscodium images (39 AMD64 images; skipped 9)**

| image | file bytes | SizeOfImage | subsystem | load-time system DLLs | load imports | delay imports | ordinal |
|---|---:|---:|---|---|---:|---:|---:|
| `VSCodium.exe` | 222,056,960 | 213.2 MiB | GUI | crypt32.dll, dwrite.dll, kernel32.dll, ntdll.dll, version.dll, winmm.dll, ws2_32.dll | 537 | 737 | 11 |
| `bin/codium-tunnel.exe` | 28,899,328 | 27.6 MiB | CUI | advapi32.dll, bcrypt.dll, bcryptprimitives.dll, crypt32.dll, iphlpapi.dll, kernel32.dll, netapi32.dll, ntdll.dll, ole32.dll, oleaut32.dll, pdh.dll, powrprof.dll, psapi.dll, secur32.dll, shell32.dll, user32.dll, ws2_32.dll | 337 | 0 | 0 |
| `dxcompiler.dll` | 25,640,448 | 24.5 MiB | DLL | advapi32.dll, kernel32.dll, ole32.dll, oleaut32.dll, user32.dll | 145 | 0 | 0 |
| `libGLESv2.dll` | 8,003,584 | 7.7 MiB | DLL | dxgi.dll, gdi32.dll, kernel32.dll, user32.dll | 145 | 5 | 0 |
| `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-exec.exe` | 6,220,096 | 5.9 MiB | CUI | advapi32.dll, api-ms-win-core-winrt-error-l1, bcrypt.dll, bcryptprimitives.dll, combase.dll, kernel32.dll, ntdll.dll, ole32.dll, oleaut32.dll, shell32.dll, userenv.dll, winhvplatform.dll, ws2_32.dll | 258 | 0 | 0 |
| `vk_swiftshader.dll` | 5,526,016 | 5.4 MiB | DLL | gdi32.dll, kernel32.dll, user32.dll | 133 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/ripgrep-universal/bin/win32-x64/rg.exe` | 5,430,784 | 5.2 MiB | CUI | bcryptprimitives.dll, kernel32.dll, ntdll.dll, userenv.dll | 129 | 0 | 0 |
| `d3dcompiler_47.dll` | 4,730,880 | 4.6 MiB | DLL | advapi32.dll, kernel32.dll, rpcrt4.dll | 131 | 0 | 0 |
| `resources/app/extensions/microsoft-authentication/dist/msalruntime.dll` | 3,142,728 | 3.0 MiB | DLL | advapi32.dll, api-ms-win-core-console-l3, api-ms-win-core-datetime-l1, api-ms-win-core-debug-l1, api-ms-win-core-fibers-l1, api-ms-win-core-file-l2, api-ms-win-core-heap-l2, api-ms-win-core-heap-obsolete-l1, api-ms-win-core-largeinteger-l1, api-ms-win-core-string-l2, api-ms-win-core-string-obsolete-l1, api-ms-win-core-threadpool-l1, api-ms-win-core-util-l1, bcrypt.dll, crypt32.dll, gdi32.dll, kernel32.dll, ncrypt.dll, ntdll.dll, ole32.dll, oleaut32.dll, rpcrt4.dll, shell32.dll, sspicli.dll, user32.dll, version.dll, wininet.dll | 303 | 0 | 0 |
| `ffmpeg.dll` | 3,063,808 | 4.4 MiB | DLL | kernel32.dll | 100 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/sqlite3/build/Release/vscode-sqlite3.node` | 1,830,400 | 1.8 MiB | DLL | kernel32.dll | 129 | 70 | 0 |
| `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-test-proxy.exe` | 1,774,392 | 1.7 MiB | CUI | bcryptprimitives.dll, kernel32.dll, ntdll.dll, oleaut32.dll, ws2_32.dll | 141 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/os-proxy-resolver-win32-x64-msvc/os_proxy_resolver.node` | 1,723,904 | 1.7 MiB | DLL | advapi32.dll, api-ms-win-crt-heap-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, bcryptprimitives.dll, iphlpapi.dll, kernel32.dll, ntdll.dll, vcruntime140.dll, winhttp.dll, ws2_32.dll | 102 | 0 | 0 |
| `dxil.dll` | 1,499,136 | 1.5 MiB | DLL | advapi32.dll, api-ms-win-crt-convert-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1, api-ms-win-crt-utility-l1, kernel32.dll, ole32.dll | 127 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-windows-sandbox-daemon.exe` | 1,326,904 | 1.3 MiB | CUI | bcryptprimitives.dll, kernel32.dll, ntdll.dll, ws2_32.dll | 152 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-windows-sandbox-guest.exe` | 1,231,160 | 1.2 MiB | CUI | bcryptprimitives.dll, kernel32.dll, ntdll.dll, ws2_32.dll | 142 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/mxc-diagnostic-console.exe` | 1,094,504 | 1.1 MiB | CUI | advapi32.dll, kernel32.dll, ntdll.dll, oleaut32.dll, psapi.dll, tdh.dll | 145 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty/OpenConsole.exe` | 1,062,472 | 1.0 MiB | GUI | advapi32.dll, api-ms-win-core-debug-l1, api-ms-win-core-file-l2, api-ms-win-core-heap-l2, api-ms-win-core-heap-obsolete-l1, api-ms-win-core-io-l1, api-ms-win-core-largeinteger-l1, api-ms-win-core-namedpipe-l1, api-ms-win-core-path-l1, api-ms-win-core-psapi-l1, api-ms-win-core-realtime-l1, api-ms-win-core-sidebyside-l1, api-ms-win-core-threadpool-l1, api-ms-win-core-util-l1, api-ms-win-core-winrt-error-l1, api-ms-win-crt-convert-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-locale-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1, api-ms-win-ntuser-sysparams-l1, api-ms-win-shcore-obsolete-l1, api-ms-win-shcore-scaling-l1, api-ms-win-shell-namespace-l1, combase.dll, d2d1.dll, d3d11.dll, dwrite.dll, dxgi.dll, ext-ms-win-uiacore-l1, gdi32.dll, imm32.dll, kernel32.dll, ntdll.dll, ole32.dll, oleaut32.dll, propsys.dll, shell32.dll, shlwapi.dll, user32.dll, usp10.dll, version.dll, winmm.dll | 399 | 11 | 2 |
| `vulkan-1.dll` | 931,840 | 0.9 MiB | DLL | advapi32.dll, cfgmgr32.dll, kernel32.dll | 120 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-host-prep.exe` | 907,576 | 0.9 MiB | CUI | advapi32.dll, kernel32.dll, ntdll.dll, oleaut32.dll | 135 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/winhttp-proxy-shim.exe` | 815,976 | 0.8 MiB | CUI | advapi32.dll, kernel32.dll, ntdll.dll, ole32.dll, oleaut32.dll | 112 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/spdlog/build/Release/spdlog.node` | 566,784 | 0.6 MiB | DLL | kernel32.dll | 113 | 36 | 0 |
| `resources/app/node_modules.asar.unpacked/@parcel/watcher/build/Release/watcher.node` | 523,776 | 0.5 MiB | DLL | kernel32.dll | 123 | 46 | 0 |
| `libEGL.dll` | 484,352 | 0.5 MiB | DLL | kernel32.dll | 92 | 0 | 0 |
| `resources/app/extensions/microsoft-authentication/dist/msal-node-runtime.node` | 349,696 | 0.4 MiB | DLL | kernel32.dll, user32.dll | 148 | 50 | 64 |
| `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty.node` | 292,352 | 0.3 MiB | DLL | kernel32.dll, shlwapi.dll | 108 | 40 | 0 |
| `resources/app/node_modules.asar.unpacked/kerberos/build/Release/kerberos.node` | 195,584 | 0.2 MiB | DLL | crypt32.dll, kernel32.dll, secur32.dll | 91 | 51 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscodium/policy-watcher/build/Release/vscodium-policy-watcher.node` | 175,616 | 0.2 MiB | DLL | advapi32.dll, kernel32.dll, userenv.dll | 86 | 43 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscodium/native-keymap/build/Release/keymapping.node` | 169,472 | 0.2 MiB | DLL | advapi32.dll, kernel32.dll, ole32.dll, user32.dll | 90 | 18 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/windows-process-tree/build/Release/windows_process_tree.node` | 152,064 | 0.2 MiB | DLL | kernel32.dll | 87 | 41 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/windows-ca-certs/build/Release/crypt32.node` | 144,896 | 0.2 MiB | DLL | crypt32.dll, kernel32.dll | 81 | 37 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/windows-mutex/build/Release/CreateMutex.node` | 144,384 | 0.2 MiB | DLL | kernel32.dll | 80 | 35 | 0 |
| `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty_console_list.node` | 135,680 | 0.2 MiB | DLL | kernel32.dll | 81 | 32 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/windows-registry/build/Release/winregistry.node` | 119,296 | 0.1 MiB | DLL | advapi32.dll, kernel32.dll | 81 | 8 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/deviceid/build/Release/windows.node` | 116,224 | 0.1 MiB | DLL | advapi32.dll, kernel32.dll | 83 | 6 | 0 |
| `resources/app/node_modules.asar.unpacked/@vscode/native-watchdog/build/Release/watchdog.node` | 111,616 | 0.1 MiB | DLL | kernel32.dll | 81 | 9 | 0 |
| `resources/app/node_modules.asar.unpacked/windows-foreground-love/build/Release/foreground_love.node` | 111,104 | 0.1 MiB | DLL | kernel32.dll, user32.dll | 79 | 10 | 0 |
| `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty/conpty.dll` | 110,152 | 0.1 MiB | DLL | api-ms-win-core-debug-l1, api-ms-win-core-file-l2, api-ms-win-core-heap-l2, api-ms-win-core-namedpipe-l1, api-ms-win-core-psapi-l1, api-ms-win-core-util-l1, api-ms-win-core-wow64-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-locale-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1, kernel32.dll, ntdll.dll | 98 | 0 | 0 |
| `resources/app/node_modules.asar.unpacked/native-is-elevated/build/Release/iselevated.node` | 110,080 | 0.1 MiB | DLL | advapi32.dll, kernel32.dll | 81 | 3 | 0 |

skipped: `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/arm64/mxc-diagnostic-console.exe` (machine ARM64 (not AMD64)); `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/arm64/winhttp-proxy-shim.exe` (machine ARM64 (not AMD64)); `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/arm64/wxc-exec.exe` (machine ARM64 (not AMD64)); `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/arm64/wxc-host-prep.exe` (machine ARM64 (not AMD64)); `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/arm64/wxc-test-proxy.exe` (machine ARM64 (not AMD64)); `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/arm64/wxc-windows-sandbox-daemon.exe` (machine ARM64 (not AMD64)); `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/arm64/wxc-windows-sandbox-guest.exe` (machine ARM64 (not AMD64)); `resources/app/node_modules.asar.unpacked/@vscode/ripgrep-universal/bin/win32-arm64/rg.exe` (machine ARM64 (not AMD64)); `resources/app/node_modules.asar.unpacked/@vscode/ripgrep-universal/bin/win32-ia32/rg.exe` (machine i386 (not AMD64))

**chromium images (17 AMD64 images; skipped 0)**

| image | file bytes | SizeOfImage | subsystem | load-time system DLLs | load imports | delay imports | ordinal |
|---|---:|---:|---|---|---:|---:|---:|
| `chrome.dll` | 334,176,256 | 320.7 MiB | DLL | crypt32.dll, dwrite.dll, kernel32.dll, ntdll.dll, version.dll, winmm.dll, ws2_32.dll | 536 | 772 | 12 |
| `dxcompiler.dll` | 25,348,096 | 24.2 MiB | DLL | advapi32.dll, kernel32.dll, ole32.dll, oleaut32.dll, user32.dll | 145 | 0 | 0 |
| `setup.exe` | 6,293,504 | 6.1 MiB | GUI | advapi32.dll, combase.dll, dbghelp.dll, kernel32.dll, ntdll.dll, ole32.dll, oleaut32.dll, propsys.dll, shell32.dll, shlwapi.dll, urlmon.dll, user32.dll, userenv.dll, version.dll, winhttp.dll, winmm.dll | 405 | 1 | 4 |
| `vk_swiftshader.dll` | 5,814,272 | 5.6 MiB | DLL | gdi32.dll, kernel32.dll, user32.dll | 133 | 0 | 0 |
| `D3DCompiler_47.dll` | 4,753,864 | 4.6 MiB | DLL | advapi32.dll, kernel32.dll, rpcrt4.dll | 131 | 0 | 0 |
| `elevated_tracing_service.exe` | 4,335,616 | 4.2 MiB | GUI | advapi32.dll, combase.dll, dbghelp.dll, kernel32.dll, ntdll.dll, ole32.dll, pdh.dll, rpcrt4.dll, shell32.dll, shlwapi.dll, user32.dll, version.dll, winhttp.dll, winmm.dll | 383 | 1 | 0 |
| `elevation_service.exe` | 3,117,056 | 3.1 MiB | GUI | advapi32.dll, crypt32.dll, dbghelp.dll, kernel32.dll, ntdll.dll, ole32.dll, oleaut32.dll, rpcrt4.dll, shell32.dll, shlwapi.dll, user32.dll, userenv.dll, winmm.dll | 281 | 0 | 0 |
| `chrome.exe` | 3,098,112 | 3.1 MiB | GUI | kernel32.dll, ntdll.dll, version.dll | 254 | 116 | 0 |
| `chrome_pwa_launcher.exe` | 1,704,448 | 1.7 MiB | GUI | advapi32.dll, dbghelp.dll, kernel32.dll, ntdll.dll, ole32.dll, shell32.dll, user32.dll, userenv.dll, winmm.dll | 184 | 0 | 0 |
| `chrome_elf.dll` | 1,588,736 | 1.6 MiB | DLL | kernel32.dll, ntdll.dll, version.dll | 192 | 39 | 0 |
| `notification_helper.exe` | 1,551,360 | 1.6 MiB | GUI | advapi32.dll, api-ms-win-core-winrt-error-l1, combase.dll, dbghelp.dll, kernel32.dll, ntdll.dll, ole32.dll, shell32.dll, shlwapi.dll, user32.dll, version.dll, winmm.dll | 232 | 0 | 0 |
| `chrome_proxy.exe` | 1,417,728 | 1.4 MiB | GUI | advapi32.dll, dbghelp.dll, kernel32.dll, ntdll.dll, ole32.dll, shell32.dll, user32.dll, userenv.dll, winmm.dll | 182 | 0 | 0 |
| `vulkan-1.dll` | 1,013,760 | 1.0 MiB | DLL | advapi32.dll, cfgmgr32.dll, kernel32.dll | 120 | 0 | 0 |
| `libEGL.dll` | 471,040 | 0.5 MiB | DLL | kernel32.dll | 87 | 0 | 0 |
| `libGLESv2.dll` | 471,040 | 0.5 MiB | DLL | kernel32.dll | 87 | 0 | 0 |
| `chrome_wer.dll` | 116,736 | 0.1 MiB | DLL | kernel32.dll | 75 | 0 | 0 |
| `eventlog_provider.dll` | 6,144 | 0.0 MiB | DLL |  | 0 | 0 | 0 |

Per-image unresolved load-time functions (what "electron.exe *and its DLLs*" means for M1: the shipped DLLs are all
loaded at run time, and each carries its own load-time set):

**per-image unresolved load-time functions**

| app | image | load-time imports (system) | unresolved | of which DLL absent | DLL(s) absent |
|---|---|---:|---:|---:|---|
| electron | `electron.exe` | 537 | 297 | 29 | crypt32.dll, dwrite.dll |
| electron | `dxil.dll` | 127 | 56 | 43 | api-ms-win-crt-convert-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1, api-ms-win-crt-utility-l1 |
| electron | `vk_swiftshader.dll` | 133 | 38 | 5 | gdi32.dll, user32.dll |
| electron | `vulkan-1.dll` | 120 | 30 | 9 | cfgmgr32.dll |
| electron | `dxcompiler.dll` | 145 | 28 | 1 | user32.dll |
| electron | `d3dcompiler_47.dll` | 131 | 27 | 0 |  |
| electron | `ffmpeg.dll` | 100 | 18 | 0 |  |
| vscodium | `VSCodium.exe` | 537 | 297 | 29 | crypt32.dll, dwrite.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty/OpenConsole.exe` | 397 | 282 | 240 | api-ms-win-core-debug-l1, api-ms-win-core-file-l2, api-ms-win-core-heap-l2, api-ms-win-core-heap-obsolete-l1, api-ms-win-core-io-l1, api-ms-win-core-largeinteger-l1, api-ms-win-core-namedpipe-l1, api-ms-win-core-path-l1, api-ms-win-core-psapi-l1, api-ms-win-core-realtime-l1, api-ms-win-core-sidebyside-l1, api-ms-win-core-threadpool-l1, api-ms-win-core-util-l1, api-ms-win-core-winrt-error-l1, api-ms-win-crt-convert-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-locale-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1, api-ms-win-ntuser-sysparams-l1, api-ms-win-shcore-obsolete-l1, api-ms-win-shcore-scaling-l1, api-ms-win-shell-namespace-l1, d2d1.dll, d3d11.dll, dwrite.dll, dxgi.dll, ext-ms-win-uiacore-l1, gdi32.dll, imm32.dll, propsys.dll, user32.dll, usp10.dll |
| vscodium | `resources/app/extensions/microsoft-authentication/dist/msalruntime.dll` | 303 | 175 | 128 | api-ms-win-core-console-l3, api-ms-win-core-datetime-l1, api-ms-win-core-debug-l1, api-ms-win-core-fibers-l1, api-ms-win-core-file-l2, api-ms-win-core-heap-l2, api-ms-win-core-heap-obsolete-l1, api-ms-win-core-largeinteger-l1, api-ms-win-core-string-l2, api-ms-win-core-string-obsolete-l1, api-ms-win-core-threadpool-l1, api-ms-win-core-util-l1, crypt32.dll, gdi32.dll, ncrypt.dll, sspicli.dll, user32.dll, wininet.dll |
| vscodium | `bin/codium-tunnel.exe` | 337 | 150 | 48 | crypt32.dll, iphlpapi.dll, netapi32.dll, pdh.dll, powrprof.dll, psapi.dll, secur32.dll, user32.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-exec.exe` | 258 | 95 | 23 | api-ms-win-core-winrt-error-l1, userenv.dll, winhvplatform.dll |
| vscodium | `dxil.dll` | 127 | 56 | 43 | api-ms-win-crt-convert-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1, api-ms-win-crt-utility-l1 |
| vscodium | `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty/conpty.dll` | 98 | 50 | 34 | api-ms-win-core-debug-l1, api-ms-win-core-file-l2, api-ms-win-core-heap-l2, api-ms-win-core-namedpipe-l1, api-ms-win-core-psapi-l1, api-ms-win-core-util-l1, api-ms-win-core-wow64-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-locale-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1 |
| vscodium | `libGLESv2.dll` | 145 | 47 | 24 | dxgi.dll, gdi32.dll, user32.dll |
| vscodium | `vk_swiftshader.dll` | 133 | 38 | 5 | gdi32.dll, user32.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/mxc-diagnostic-console.exe` | 145 | 36 | 2 | psapi.dll, tdh.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/os-proxy-resolver-win32-x64-msvc/os_proxy_resolver.node` | 102 | 35 | 31 | api-ms-win-crt-heap-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, iphlpapi.dll, vcruntime140.dll, winhttp.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-host-prep.exe` | 135 | 34 | 0 |  |
| vscodium | `vulkan-1.dll` | 120 | 30 | 9 | cfgmgr32.dll |
| vscodium | `dxcompiler.dll` | 145 | 28 | 1 | user32.dll |
| vscodium | `d3dcompiler_47.dll` | 131 | 27 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-windows-sandbox-daemon.exe` | 152 | 26 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/ripgrep-universal/bin/win32-x64/rg.exe` | 129 | 25 | 1 | userenv.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/@parcel/watcher/build/Release/watcher.node` | 123 | 24 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/sqlite3/build/Release/vscode-sqlite3.node` | 129 | 23 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-test-proxy.exe` | 141 | 22 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-windows-sandbox-guest.exe` | 142 | 22 | 0 |  |
| vscodium | `ffmpeg.dll` | 100 | 18 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/spdlog/build/Release/spdlog.node` | 113 | 18 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/kerberos/build/Release/kerberos.node` | 91 | 18 | 11 | crypt32.dll, secur32.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty.node` | 108 | 18 | 0 |  |
| vscodium | `libEGL.dll` | 92 | 16 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/winhttp-proxy-shim.exe` | 112 | 15 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/windows-process-tree/build/Release/windows_process_tree.node` | 87 | 14 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscodium/native-keymap/build/Release/keymapping.node` | 90 | 14 | 7 | user32.dll |
| vscodium | `resources/app/extensions/microsoft-authentication/dist/msal-node-runtime.node` | 84 | 12 | 3 | user32.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/windows-ca-certs/build/Release/crypt32.node` | 81 | 9 | 3 | crypt32.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty_console_list.node` | 81 | 9 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscodium/policy-watcher/build/Release/vscodium-policy-watcher.node` | 86 | 8 | 2 | userenv.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/native-watchdog/build/Release/watchdog.node` | 81 | 7 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/windows-mutex/build/Release/CreateMutex.node` | 80 | 7 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/native-is-elevated/build/Release/iselevated.node` | 81 | 7 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/windows-foreground-love/build/Release/foreground_love.node` | 79 | 7 | 1 | user32.dll |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/deviceid/build/Release/windows.node` | 83 | 6 | 0 |  |
| vscodium | `resources/app/node_modules.asar.unpacked/@vscode/windows-registry/build/Release/winregistry.node` | 81 | 6 | 0 |  |
| chromium | `chrome.dll` | 522 | 287 | 27 | crypt32.dll, dwrite.dll |
| chromium | `setup.exe` | 405 | 203 | 50 | dbghelp.dll, propsys.dll, urlmon.dll, user32.dll, userenv.dll, winhttp.dll |
| chromium | `elevated_tracing_service.exe` | 383 | 186 | 45 | dbghelp.dll, pdh.dll, user32.dll, winhttp.dll |
| chromium | `elevation_service.exe` | 281 | 105 | 15 | crypt32.dll, dbghelp.dll, user32.dll, userenv.dll |
| chromium | `chrome.exe` | 249 | 97 | 0 |  |
| chromium | `notification_helper.exe` | 232 | 86 | 11 | api-ms-win-core-winrt-error-l1, dbghelp.dll, user32.dll |
| chromium | `chrome_elf.dll` | 192 | 59 | 0 |  |
| chromium | `chrome_pwa_launcher.exe` | 184 | 53 | 12 | dbghelp.dll, user32.dll, userenv.dll |
| chromium | `chrome_proxy.exe` | 182 | 52 | 12 | dbghelp.dll, user32.dll, userenv.dll |
| chromium | `vk_swiftshader.dll` | 133 | 38 | 5 | gdi32.dll, user32.dll |
| chromium | `vulkan-1.dll` | 120 | 30 | 9 | cfgmgr32.dll |
| chromium | `dxcompiler.dll` | 145 | 28 | 1 | user32.dll |
| chromium | `D3DCompiler_47.dll` | 131 | 27 | 0 |  |
| chromium | `libEGL.dll` | 87 | 15 | 0 |  |
| chromium | `libGLESv2.dll` | 87 | 15 | 0 |  |
| chromium | `chrome_wer.dll` | 75 | 9 | 0 |  |
| chromium | `eventlog_provider.dll` | 0 | 0 | 0 |  |

VSCodium's native addons and helper executables and their load-time DLL sets (all loaded at run time by the editor,
`rg.exe`/`OpenConsole.exe`/`codium-tunnel.exe` as child processes):

**VSCodium native addons (.node) and helper executables: load-time DLLs**

- `bin/codium-tunnel.exe`: L=337 D=0: advapi32.dll, bcrypt.dll, bcryptprimitives.dll, crypt32.dll, iphlpapi.dll, kernel32.dll, netapi32.dll, ntdll.dll, ole32.dll, oleaut32.dll, pdh.dll, powrprof.dll, psapi.dll, secur32.dll, shell32.dll, user32.dll, ws2_32.dll
- `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-exec.exe`: L=258 D=0: advapi32.dll, api-ms-win-core-winrt-error-l1, bcrypt.dll, bcryptprimitives.dll, combase.dll, kernel32.dll, ntdll.dll, ole32.dll, oleaut32.dll, shell32.dll, userenv.dll, winhvplatform.dll, ws2_32.dll
- `resources/app/node_modules.asar.unpacked/@vscode/ripgrep-universal/bin/win32-x64/rg.exe`: L=129 D=0: bcryptprimitives.dll, kernel32.dll, ntdll.dll, userenv.dll
- `resources/app/extensions/microsoft-authentication/dist/msalruntime.dll`: L=303 D=0: advapi32.dll, api-ms-win-core-console-l3, api-ms-win-core-datetime-l1, api-ms-win-core-debug-l1, api-ms-win-core-fibers-l1, api-ms-win-core-file-l2, api-ms-win-core-heap-l2, api-ms-win-core-heap-obsolete-l1, api-ms-win-core-largeinteger-l1, api-ms-win-core-string-l2, api-ms-win-core-string-obsolete-l1, api-ms-win-core-threadpool-l1, api-ms-win-core-util-l1, bcrypt.dll, crypt32.dll, gdi32.dll, kernel32.dll, ncrypt.dll, ntdll.dll, ole32.dll, oleaut32.dll, rpcrt4.dll, shell32.dll, sspicli.dll, user32.dll, version.dll, wininet.dll
- `resources/app/node_modules.asar.unpacked/@vscode/sqlite3/build/Release/vscode-sqlite3.node`: L=129 D=70: kernel32.dll
- `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-test-proxy.exe`: L=141 D=0: bcryptprimitives.dll, kernel32.dll, ntdll.dll, oleaut32.dll, ws2_32.dll
- `resources/app/node_modules.asar.unpacked/@vscode/os-proxy-resolver-win32-x64-msvc/os_proxy_resolver.node`: L=102 D=0: advapi32.dll, api-ms-win-crt-heap-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, bcryptprimitives.dll, iphlpapi.dll, kernel32.dll, ntdll.dll, vcruntime140.dll, winhttp.dll, ws2_32.dll
- `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-windows-sandbox-daemon.exe`: L=152 D=0: bcryptprimitives.dll, kernel32.dll, ntdll.dll, ws2_32.dll
- `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-windows-sandbox-guest.exe`: L=142 D=0: bcryptprimitives.dll, kernel32.dll, ntdll.dll, ws2_32.dll
- `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/mxc-diagnostic-console.exe`: L=145 D=0: advapi32.dll, kernel32.dll, ntdll.dll, oleaut32.dll, psapi.dll, tdh.dll
- `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty/OpenConsole.exe`: L=399 D=11: advapi32.dll, api-ms-win-core-debug-l1, api-ms-win-core-file-l2, api-ms-win-core-heap-l2, api-ms-win-core-heap-obsolete-l1, api-ms-win-core-io-l1, api-ms-win-core-largeinteger-l1, api-ms-win-core-namedpipe-l1, api-ms-win-core-path-l1, api-ms-win-core-psapi-l1, api-ms-win-core-realtime-l1, api-ms-win-core-sidebyside-l1, api-ms-win-core-threadpool-l1, api-ms-win-core-util-l1, api-ms-win-core-winrt-error-l1, api-ms-win-crt-convert-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-locale-l1, api-ms-win-crt-math-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1, api-ms-win-ntuser-sysparams-l1, api-ms-win-shcore-obsolete-l1, api-ms-win-shcore-scaling-l1, api-ms-win-shell-namespace-l1, combase.dll, d2d1.dll, d3d11.dll, dwrite.dll, dxgi.dll, ext-ms-win-uiacore-l1, gdi32.dll, imm32.dll, kernel32.dll, ntdll.dll, ole32.dll, oleaut32.dll, propsys.dll, shell32.dll, shlwapi.dll, user32.dll, usp10.dll, version.dll, winmm.dll
- `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/wxc-host-prep.exe`: L=135 D=0: advapi32.dll, kernel32.dll, ntdll.dll, oleaut32.dll
- `resources/app/node_modules.asar.unpacked/@microsoft/mxc-sdk/bin/x64/winhttp-proxy-shim.exe`: L=112 D=0: advapi32.dll, kernel32.dll, ntdll.dll, ole32.dll, oleaut32.dll
- `resources/app/node_modules.asar.unpacked/@vscode/spdlog/build/Release/spdlog.node`: L=113 D=36: kernel32.dll
- `resources/app/node_modules.asar.unpacked/@parcel/watcher/build/Release/watcher.node`: L=123 D=46: kernel32.dll
- `resources/app/extensions/microsoft-authentication/dist/msal-node-runtime.node`: L=148 D=50: kernel32.dll, user32.dll
- `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty.node`: L=108 D=40: kernel32.dll, shlwapi.dll
- `resources/app/node_modules.asar.unpacked/kerberos/build/Release/kerberos.node`: L=91 D=51: crypt32.dll, kernel32.dll, secur32.dll
- `resources/app/node_modules.asar.unpacked/@vscodium/policy-watcher/build/Release/vscodium-policy-watcher.node`: L=86 D=43: advapi32.dll, kernel32.dll, userenv.dll
- `resources/app/node_modules.asar.unpacked/@vscodium/native-keymap/build/Release/keymapping.node`: L=90 D=18: advapi32.dll, kernel32.dll, ole32.dll, user32.dll
- `resources/app/node_modules.asar.unpacked/@vscode/windows-process-tree/build/Release/windows_process_tree.node`: L=87 D=41: kernel32.dll
- `resources/app/node_modules.asar.unpacked/@vscode/windows-ca-certs/build/Release/crypt32.node`: L=81 D=37: crypt32.dll, kernel32.dll
- `resources/app/node_modules.asar.unpacked/@vscode/windows-mutex/build/Release/CreateMutex.node`: L=80 D=35: kernel32.dll
- `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty_console_list.node`: L=81 D=32: kernel32.dll
- `resources/app/node_modules.asar.unpacked/@vscode/windows-registry/build/Release/winregistry.node`: L=81 D=8: advapi32.dll, kernel32.dll
- `resources/app/node_modules.asar.unpacked/@vscode/deviceid/build/Release/windows.node`: L=83 D=6: advapi32.dll, kernel32.dll
- `resources/app/node_modules.asar.unpacked/@vscode/native-watchdog/build/Release/watchdog.node`: L=81 D=9: kernel32.dll
- `resources/app/node_modules.asar.unpacked/windows-foreground-love/build/Release/foreground_love.node`: L=79 D=10: kernel32.dll, user32.dll
- `resources/app/node_modules.asar.unpacked/node-pty/build/Release/conpty/conpty.dll`: L=98 D=0: api-ms-win-core-debug-l1, api-ms-win-core-file-l2, api-ms-win-core-heap-l2, api-ms-win-core-namedpipe-l1, api-ms-win-core-psapi-l1, api-ms-win-core-util-l1, api-ms-win-core-wow64-l1, api-ms-win-crt-heap-l1, api-ms-win-crt-locale-l1, api-ms-win-crt-runtime-l1, api-ms-win-crt-stdio-l1, api-ms-win-crt-string-l1, kernel32.dll, ntdll.dll
- `resources/app/node_modules.asar.unpacked/native-is-elevated/build/Release/iselevated.node`: L=81 D=3: advapi32.dll, kernel32.dll

## 5. Per-DLL provided/imported tables

**electron per-DLL table (imported 1308, provided 332, 25.4%)**

| system DLL / contract | imported | provided | load-time images | delay-only images | ordinal | Shizuku DLL |
|---|---:|---:|---:|---:|---:|---|
| kernel32.dll | 424 | 188 | 7 | 0 | 0 | yes |
| user32.dll | 215 | 0 | 2 | 1 | 0 | none |
| gdi32.dll | 95 | 0 | 1 | 1 | 0 | none |
| advapi32.dll | 85 | 33 | 4 | 1 | 0 | yes |
| ws2_32.dll | 54 | 43 | 1 | 0 | 0 | yes |
| ole32.dll | 33 | 14 | 2 | 1 | 0 | yes |
| winmm.dll | 31 | 3 | 1 | 0 | 0 | yes |
| crypt32.dll | 28 | 0 | 1 | 0 | 0 | none |
| shell32.dll | 24 | 6 | 0 | 1 | 2 | yes |
| mfplat.dll | 23 | 0 | 0 | 1 | 0 | none |
| oleaut32.dll | 22 | 20 | 1 | 1 | 0 | yes |
| api-ms-win-crt-stdio-l1 | 15 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-crt-runtime-l1 | 14 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| dbghelp.dll | 14 | 0 | 0 | 1 | 0 | none |
| winhttp.dll | 14 | 0 | 0 | 1 | 0 | none |
| iphlpapi.dll | 13 | 0 | 0 | 1 | 0 | none |
| ntdll.dll | 11 | 9 | 1 | 0 | 0 | yes |
| hid.dll | 11 | 0 | 0 | 1 | 0 | none |
| ncrypt.dll | 11 | 0 | 0 | 1 | 0 | none |
| cfgmgr32.dll | 11 | 0 | 1 | 1 | 0 | none |
| bthprops.cpl | 11 | 0 | 0 | 1 | 0 | none |
| setupapi.dll | 10 | 0 | 0 | 1 | 0 | none |
| uiautomationcore.dll | 9 | 0 | 0 | 1 | 0 | none |
| winusb.dll | 9 | 0 | 0 | 1 | 0 | none |
| combase.dll | 8 | 6 | 0 | 1 | 0 | yes |
| winspool.drv | 8 | 0 | 0 | 1 | 1 | none |
| api-ms-win-crt-string-l1 | 7 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| shlwapi.dll | 7 | 4 | 0 | 1 | 2 | yes |
| secur32.dll | 7 | 0 | 0 | 1 | 0 | none |
| wintrust.dll | 6 | 0 | 0 | 1 | 0 | none |
| uxtheme.dll | 6 | 0 | 0 | 1 | 1 | none |
| comctl32.dll | 5 | 0 | 0 | 1 | 4 | none |
| dwmapi.dll | 5 | 0 | 0 | 1 | 0 | none |
| pdh.dll | 5 | 0 | 0 | 1 | 0 | none |
| wevtapi.dll | 5 | 0 | 0 | 1 | 0 | none |
| oleacc.dll | 5 | 0 | 0 | 1 | 0 | none |
| wtsapi32.dll | 4 | 0 | 0 | 1 | 0 | none |
| userenv.dll | 4 | 0 | 0 | 1 | 0 | none |
| api-ms-win-crt-heap-l1 | 3 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| version.dll | 3 | 3 | 1 | 0 | 0 | yes |
| propsys.dll | 3 | 0 | 0 | 1 | 0 | none |
| api-ms-win-shcore-scaling-l1 | 3 | 0 | 0 | 1 | 0 | contract not in ldr.c |
| rpcrt4.dll | 2 | 2 | 1 | 1 | 0 | yes |
| api-ms-win-crt-math-l1 | 2 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| dxgi.dll | 2 | 0 | 0 | 1 | 0 | none |
| mf.dll | 2 | 0 | 0 | 1 | 0 | none |
| api-ms-win-power-base-l1 | 2 | 0 | 0 | 1 | 0 | contract not in ldr.c |
| dcomp.dll | 2 | 0 | 0 | 1 | 0 | none |
| dhcpcsvc.dll | 2 | 0 | 0 | 1 | 0 | none |
| api-ms-win-crt-utility-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-crt-convert-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| dwrite.dll | 1 | 0 | 1 | 0 | 0 | none |
| cryptui.dll | 1 | 0 | 0 | 1 | 0 | none |
| d3d11.dll | 1 | 0 | 0 | 1 | 0 | none |
| mmdevapi.dll | 1 | 0 | 0 | 1 | 1 | none |
| mfreadwrite.dll | 1 | 0 | 0 | 1 | 0 | none |
| api-ms-win-core-realtime-l1 | 1 | 0 | 0 | 1 | 0 | contract not in ldr.c |
| tbs.dll | 1 | 0 | 0 | 1 | 0 | none |
| d3d12.dll | 1 | 0 | 0 | 1 | 1 | none |
| bcryptprimitives.dll | 1 | 1 | 0 | 1 | 0 | yes |
| comdlg32.dll | 1 | 0 | 0 | 1 | 0 | none |
| urlmon.dll | 1 | 0 | 0 | 1 | 0 | none |

**vscodium per-DLL table (imported 1686, provided 373, 22.1%)**

| system DLL / contract | imported | provided | load-time images | delay-only images | ordinal | Shizuku DLL |
|---|---:|---:|---:|---:|---:|---|
| kernel32.dll | 458 | 191 | 39 | 0 | 0 | yes |
| user32.dll | 253 | 0 | 9 | 1 | 0 | none |
| advapi32.dll | 120 | 37 | 17 | 1 | 0 | yes |
| gdi32.dll | 107 | 0 | 4 | 1 | 0 | none |
| ws2_32.dll | 62 | 48 | 7 | 0 | 0 | yes |
| ole32.dll | 43 | 19 | 8 | 1 | 0 | yes |
| crypt32.dll | 42 | 0 | 5 | 0 | 0 | none |
| winmm.dll | 32 | 3 | 2 | 0 | 0 | yes |
| oleaut32.dll | 27 | 19 | 9 | 1 | 0 | yes |
| ntdll.dll | 26 | 20 | 14 | 0 | 0 | yes |
| shell32.dll | 25 | 6 | 4 | 1 | 3 | yes |
| api-ms-win-crt-runtime-l1 | 25 | 0 | 4 | 0 | 0 | contract not in ldr.c |
| mfplat.dll | 23 | 0 | 0 | 1 | 0 | none |
| api-ms-win-crt-stdio-l1 | 19 | 0 | 3 | 0 | 0 | contract not in ldr.c |
| winhvplatform.dll | 17 | 0 | 1 | 0 | 0 | none |
| secur32.dll | 16 | 0 | 2 | 1 | 0 | none |
| iphlpapi.dll | 16 | 0 | 2 | 1 | 0 | none |
| combase.dll | 15 | 8 | 2 | 1 | 0 | yes |
| winhttp.dll | 15 | 0 | 1 | 1 | 0 | none |
| dbghelp.dll | 14 | 0 | 0 | 1 | 0 | none |
| ncrypt.dll | 13 | 0 | 1 | 1 | 0 | none |
| bcrypt.dll | 12 | 8 | 3 | 0 | 0 | yes |
| api-ms-win-crt-string-l1 | 12 | 0 | 3 | 0 | 0 | contract not in ldr.c |
| api-ms-win-crt-math-l1 | 12 | 0 | 3 | 0 | 0 | contract not in ldr.c |
| cfgmgr32.dll | 11 | 0 | 1 | 1 | 0 | none |
| bthprops.cpl | 11 | 0 | 0 | 1 | 0 | none |
| hid.dll | 11 | 0 | 0 | 1 | 0 | none |
| icu.dll | 11 | 0 | 0 | 1 | 0 | none |
| shlwapi.dll | 10 | 8 | 2 | 1 | 1 | yes |
| setupapi.dll | 10 | 0 | 0 | 1 | 0 | none |
| wininet.dll | 10 | 0 | 1 | 0 | 0 | none |
| uiautomationcore.dll | 9 | 0 | 0 | 1 | 0 | none |
| winusb.dll | 9 | 0 | 0 | 1 | 0 | none |
| api-ms-win-core-threadpool-l1 | 9 | 0 | 2 | 0 | 0 | contract not in ldr.c |
| winspool.drv | 8 | 0 | 0 | 1 | 1 | none |
| userenv.dll | 8 | 0 | 3 | 1 | 0 | none |
| vcruntime140.dll | 8 | 0 | 1 | 0 | 0 | none |
| pdh.dll | 7 | 0 | 1 | 1 | 0 | none |
| api-ms-win-crt-heap-l1 | 7 | 0 | 4 | 0 | 0 | contract not in ldr.c |
| propsys.dll | 6 | 0 | 1 | 1 | 0 | none |
| uxtheme.dll | 6 | 0 | 0 | 1 | 1 | none |
| wintrust.dll | 6 | 0 | 0 | 1 | 0 | none |
| comctl32.dll | 5 | 0 | 0 | 1 | 4 | none |
| dwmapi.dll | 5 | 0 | 0 | 1 | 0 | none |
| wevtapi.dll | 5 | 0 | 0 | 1 | 0 | none |
| oleacc.dll | 5 | 0 | 0 | 1 | 0 | none |
| d3d9.dll | 5 | 0 | 0 | 1 | 0 | none |
| ext-ms-win-uiacore-l1 | 5 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| version.dll | 4 | 3 | 3 | 0 | 0 | yes |
| wtsapi32.dll | 4 | 0 | 0 | 1 | 0 | none |
| netapi32.dll | 4 | 0 | 1 | 0 | 0 | none |
| api-ms-win-core-heap-l2 | 4 | 0 | 3 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-fibers-l1 | 4 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| usp10.dll | 4 | 0 | 1 | 0 | 0 | none |
| api-ms-win-shcore-scaling-l1 | 3 | 0 | 1 | 1 | 0 | contract not in ldr.c |
| dxgi.dll | 3 | 0 | 2 | 1 | 0 | none |
| psapi.dll | 3 | 0 | 2 | 0 | 0 | none |
| api-ms-win-crt-convert-l1 | 3 | 0 | 2 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-heap-obsolete-l1 | 3 | 0 | 2 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-debug-l1 | 3 | 0 | 3 | 0 | 0 | contract not in ldr.c |
| api-ms-win-ntuser-sysparams-l1 | 3 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-power-base-l1 | 2 | 0 | 0 | 1 | 0 | contract not in ldr.c |
| dhcpcsvc.dll | 2 | 0 | 0 | 1 | 0 | none |
| api-ms-win-core-realtime-l1 | 2 | 0 | 1 | 1 | 0 | contract not in ldr.c |
| rpcrt4.dll | 2 | 2 | 2 | 1 | 0 | yes |
| dcomp.dll | 2 | 0 | 0 | 1 | 0 | none |
| mf.dll | 2 | 0 | 0 | 1 | 0 | none |
| api-ms-win-core-util-l1 | 2 | 0 | 3 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-string-obsolete-l1 | 2 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-string-l2 | 2 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-datetime-l1 | 2 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-winrt-error-l1 | 2 | 0 | 2 | 0 | 0 | contract not in ldr.c |
| api-ms-win-crt-locale-l1 | 2 | 0 | 2 | 0 | 0 | contract not in ldr.c |
| dwrite.dll | 1 | 0 | 2 | 0 | 0 | none |
| comdlg32.dll | 1 | 0 | 0 | 1 | 0 | none |
| fontsub.dll | 1 | 0 | 0 | 1 | 0 | none |
| urlmon.dll | 1 | 0 | 0 | 1 | 0 | none |
| d3d11.dll | 1 | 0 | 1 | 1 | 0 | none |
| mmdevapi.dll | 1 | 0 | 0 | 1 | 1 | none |
| mfreadwrite.dll | 1 | 0 | 0 | 1 | 0 | none |
| d3d12.dll | 1 | 0 | 0 | 1 | 1 | none |
| bcryptprimitives.dll | 1 | 1 | 7 | 1 | 0 | yes |
| powrprof.dll | 1 | 0 | 1 | 0 | 0 | none |
| api-ms-win-crt-utility-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| sspicli.dll | 1 | 0 | 1 | 0 | 0 | none |
| api-ms-win-core-console-l3 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-largeinteger-l1 | 1 | 0 | 2 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-file-l2 | 1 | 0 | 3 | 0 | 0 | contract not in ldr.c |
| tdh.dll | 1 | 0 | 1 | 0 | 0 | none |
| api-ms-win-shell-namespace-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-path-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-psapi-l1 | 1 | 0 | 2 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-namedpipe-l1 | 1 | 0 | 2 | 0 | 0 | contract not in ldr.c |
| api-ms-win-shcore-obsolete-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-sidebyside-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| imm32.dll | 1 | 0 | 1 | 0 | 0 | none |
| d2d1.dll | 1 | 0 | 1 | 0 | 1 | none |
| api-ms-win-core-io-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |
| api-ms-win-core-wow64-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |

**chromium per-DLL table (imported 1385, provided 343, 24.8%)**

| system DLL / contract | imported | provided | load-time images | delay-only images | ordinal | Shizuku DLL |
|---|---:|---:|---:|---:|---:|---|
| kernel32.dll | 423 | 186 | 16 | 0 | 0 | yes |
| user32.dll | 230 | 0 | 8 | 2 | 0 | none |
| advapi32.dll | 129 | 39 | 9 | 3 | 0 | yes |
| gdi32.dll | 95 | 0 | 1 | 1 | 0 | none |
| ws2_32.dll | 52 | 39 | 1 | 0 | 0 | yes |
| ole32.dll | 42 | 17 | 7 | 3 | 0 | yes |
| winmm.dll | 31 | 3 | 7 | 2 | 0 | yes |
| shell32.dll | 29 | 6 | 6 | 3 | 8 | yes |
| crypt32.dll | 26 | 0 | 2 | 0 | 0 | none |
| oleaut32.dll | 22 | 20 | 3 | 1 | 0 | yes |
| mfplat.dll | 20 | 0 | 0 | 1 | 0 | none |
| winhttp.dll | 19 | 0 | 2 | 2 | 0 | none |
| ntdll.dll | 15 | 15 | 9 | 0 | 0 | yes |
| dbghelp.dll | 13 | 0 | 6 | 3 | 0 | none |
| ncrypt.dll | 13 | 0 | 0 | 1 | 0 | none |
| secur32.dll | 12 | 0 | 0 | 1 | 0 | none |
| esent.dll | 12 | 0 | 0 | 1 | 0 | none |
| hid.dll | 11 | 0 | 0 | 1 | 0 | none |
| cfgmgr32.dll | 11 | 0 | 1 | 1 | 0 | none |
| bthprops.cpl | 11 | 0 | 0 | 1 | 0 | none |
| iphlpapi.dll | 10 | 0 | 0 | 1 | 0 | none |
| setupapi.dll | 10 | 0 | 0 | 1 | 0 | none |
| wintrust.dll | 10 | 0 | 0 | 1 | 0 | none |
| uiautomationcore.dll | 9 | 0 | 0 | 1 | 0 | none |
| shlwapi.dll | 9 | 4 | 4 | 2 | 4 | yes |
| winusb.dll | 9 | 0 | 0 | 1 | 0 | none |
| userenv.dll | 8 | 0 | 4 | 2 | 0 | none |
| combase.dll | 8 | 6 | 3 | 1 | 0 | yes |
| winspool.drv | 8 | 0 | 0 | 1 | 1 | none |
| netapi32.dll | 7 | 0 | 0 | 1 | 0 | none |
| pdh.dll | 6 | 0 | 1 | 1 | 0 | none |
| uxtheme.dll | 6 | 0 | 0 | 1 | 1 | none |
| wevtapi.dll | 5 | 0 | 0 | 1 | 0 | none |
| oleacc.dll | 5 | 0 | 0 | 1 | 0 | none |
| dwmapi.dll | 5 | 0 | 0 | 1 | 0 | none |
| propsys.dll | 4 | 0 | 1 | 1 | 0 | none |
| wtsapi32.dll | 4 | 0 | 0 | 1 | 0 | none |
| version.dll | 3 | 3 | 6 | 0 | 0 | yes |
| bcrypt.dll | 3 | 3 | 0 | 1 | 0 | yes |
| ndfapi.dll | 3 | 0 | 0 | 1 | 0 | none |
| api-ms-win-shcore-scaling-l1 | 3 | 0 | 0 | 1 | 0 | contract not in ldr.c |
| api-ms-win-power-setting-l1 | 3 | 0 | 0 | 1 | 0 | contract not in ldr.c |
| rpcrt4.dll | 2 | 1 | 3 | 0 | 0 | yes |
| dxgi.dll | 2 | 0 | 0 | 1 | 0 | none |
| mf.dll | 2 | 0 | 0 | 1 | 0 | none |
| urlmon.dll | 2 | 0 | 1 | 1 | 0 | none |
| cryptui.dll | 2 | 0 | 0 | 1 | 0 | none |
| api-ms-win-power-base-l1 | 2 | 0 | 0 | 4 | 0 | contract not in ldr.c |
| tbs.dll | 2 | 0 | 0 | 1 | 0 | none |
| dcomp.dll | 2 | 0 | 0 | 1 | 0 | none |
| dhcpcsvc.dll | 2 | 0 | 0 | 1 | 0 | none |
| dwrite.dll | 1 | 0 | 1 | 0 | 0 | none |
| mmdevapi.dll | 1 | 0 | 0 | 1 | 1 | none |
| d3d11.dll | 1 | 0 | 0 | 1 | 0 | none |
| mfreadwrite.dll | 1 | 0 | 0 | 1 | 0 | none |
| comctl32.dll | 1 | 0 | 0 | 1 | 0 | none |
| credui.dll | 1 | 0 | 0 | 1 | 0 | none |
| imm32.dll | 1 | 0 | 0 | 1 | 0 | none |
| api-ms-win-core-realtime-l1 | 1 | 0 | 0 | 1 | 0 | contract not in ldr.c |
| d3d12.dll | 1 | 0 | 0 | 1 | 1 | none |
| bcryptprimitives.dll | 1 | 1 | 0 | 1 | 0 | yes |
| comdlg32.dll | 1 | 0 | 0 | 1 | 0 | none |
| wininet.dll | 1 | 0 | 0 | 1 | 0 | none |
| api-ms-win-core-winrt-error-l1 | 1 | 0 | 1 | 0 | 0 | contract not in ldr.c |

Delay-load DLL sets of the main images (resolved by the CRT helper at first call; each is a feature blocker, not a load
blocker):

- electron/electron.exe: 48 delay-only: advapi32.dll, api-ms-win-core-realtime-l1, api-ms-win-power-base-l1, api-ms-win-shcore-scaling-l1, bcryptprimitives.dll, bthprops.cpl, cfgmgr32.dll, combase.dll, comctl32.dll, comdlg32.dll, cryptui.dll, d3d11.dll, d3d12.dll, dbghelp.dll, dcomp.dll, dhcpcsvc.dll, dwmapi.dll, dxgi.dll, gdi32.dll, hid.dll, iphlpapi.dll, mf.dll, mfplat.dll, mfreadwrite.dll, mmdevapi.dll, ncrypt.dll, ole32.dll, oleacc.dll, oleaut32.dll, pdh.dll, propsys.dll, rpcrt4.dll, secur32.dll, setupapi.dll, shell32.dll, shlwapi.dll, tbs.dll, uiautomationcore.dll, urlmon.dll, user32.dll, userenv.dll, uxtheme.dll, wevtapi.dll, winhttp.dll, winspool.drv, wintrust.dll, winusb.dll, wtsapi32.dll
- vscodium/VSCodium.exe: 47 delay-only: advapi32.dll, api-ms-win-core-realtime-l1, api-ms-win-power-base-l1, api-ms-win-shcore-scaling-l1, bcryptprimitives.dll, bthprops.cpl, cfgmgr32.dll, combase.dll, comctl32.dll, comdlg32.dll, d3d11.dll, d3d12.dll, dbghelp.dll, dcomp.dll, dhcpcsvc.dll, dwmapi.dll, dxgi.dll, fontsub.dll, gdi32.dll, hid.dll, iphlpapi.dll, mf.dll, mfplat.dll, mfreadwrite.dll, mmdevapi.dll, ncrypt.dll, ole32.dll, oleacc.dll, oleaut32.dll, pdh.dll, propsys.dll, rpcrt4.dll, secur32.dll, setupapi.dll, shell32.dll, shlwapi.dll, uiautomationcore.dll, urlmon.dll, user32.dll, userenv.dll, uxtheme.dll, wevtapi.dll, winhttp.dll, winspool.drv, wintrust.dll, winusb.dll, wtsapi32.dll
- chromium/chrome.dll: 55 delay-only: advapi32.dll, api-ms-win-core-realtime-l1, api-ms-win-power-base-l1, api-ms-win-power-setting-l1, api-ms-win-shcore-scaling-l1, bcrypt.dll, bcryptprimitives.dll, bthprops.cpl, cfgmgr32.dll, combase.dll, comctl32.dll, comdlg32.dll, credui.dll, cryptui.dll, d3d11.dll, d3d12.dll, dbghelp.dll, dcomp.dll, dhcpcsvc.dll, dwmapi.dll, dxgi.dll, esent.dll, gdi32.dll, hid.dll, imm32.dll, iphlpapi.dll, mf.dll, mfplat.dll, mfreadwrite.dll, mmdevapi.dll, ncrypt.dll, ndfapi.dll, netapi32.dll, ole32.dll, oleacc.dll, oleaut32.dll, pdh.dll, propsys.dll, secur32.dll, setupapi.dll, shell32.dll, shlwapi.dll, tbs.dll, uiautomationcore.dll, urlmon.dll, user32.dll, userenv.dll, uxtheme.dll, wevtapi.dll, winhttp.dll, wininet.dll, winspool.drv, wintrust.dll, winusb.dll, wtsapi32.dll
- chromium/chrome.exe: 10 delay-only: advapi32.dll, api-ms-win-power-base-l1, dbghelp.dll, ole32.dll, shell32.dll, shlwapi.dll, user32.dll, userenv.dll, winhttp.dll, winmm.dll
- chromium/chrome_elf.dll: 5 delay-only: advapi32.dll, dbghelp.dll, ole32.dll, shell32.dll, winmm.dll

## 6. Load-blocker DLLs (no Shizuku implementation), ordered by impact

Impact = number of images (across the three products) importing the DLL at load time, then distinct functions.
"main-image use" says whether the product's main image needs the DLL at load time (L) or by delay-load (D); everything
marked only D for the main images is loaded by the helper executables, the GPU/shader DLLs or the VSCodium addons.

| DLL / contract | distinct functions | load-time images (all apps) | delay-only images | apps | main-image use (L=load-time, D=delay) |
|---|---:|---:|---:|---|---|
| user32.dll | 271 | 19 | 4 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| crypt32.dll | 42 | 8 | 0 | chromium, electron, vscodium | chromium:L, electron:L, vscodium:L |
| userenv.dll | 11 | 7 | 4 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| gdi32.dll | 107 | 6 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| dbghelp.dll | 15 | 6 | 5 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| api-ms-win-crt-runtime-l1 | 25 | 5 | 0 | electron, vscodium | - |
| api-ms-win-crt-heap-l1 | 7 | 5 | 0 | electron, vscodium | - |
| api-ms-win-crt-stdio-l1 | 19 | 4 | 0 | electron, vscodium | - |
| api-ms-win-crt-math-l1 | 12 | 4 | 0 | electron, vscodium | - |
| api-ms-win-crt-string-l1 | 12 | 4 | 0 | electron, vscodium | - |
| dwrite.dll | 1 | 4 | 0 | chromium, electron, vscodium | chromium:L, electron:L, vscodium:L |
| winhttp.dll | 20 | 3 | 4 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| cfgmgr32.dll | 11 | 3 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| api-ms-win-core-heap-l2 | 4 | 3 | 0 | vscodium | - |
| api-ms-win-core-debug-l1 | 3 | 3 | 0 | vscodium | - |
| api-ms-win-crt-convert-l1 | 3 | 3 | 0 | electron, vscodium | - |
| api-ms-win-core-util-l1 | 2 | 3 | 0 | vscodium | - |
| api-ms-win-core-winrt-error-l1 | 2 | 3 | 0 | chromium, vscodium | - |
| api-ms-win-core-file-l2 | 1 | 3 | 0 | vscodium | - |
| secur32.dll | 20 | 2 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| iphlpapi.dll | 17 | 2 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| api-ms-win-core-threadpool-l1 | 9 | 2 | 0 | vscodium | - |
| pdh.dll | 7 | 2 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| propsys.dll | 7 | 2 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| api-ms-win-core-heap-obsolete-l1 | 3 | 2 | 0 | vscodium | - |
| dxgi.dll | 3 | 2 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| psapi.dll | 3 | 2 | 0 | vscodium | - |
| api-ms-win-crt-locale-l1 | 2 | 2 | 0 | vscodium | - |
| api-ms-win-core-largeinteger-l1 | 1 | 2 | 0 | vscodium | - |
| api-ms-win-core-namedpipe-l1 | 1 | 2 | 0 | vscodium | - |
| api-ms-win-core-psapi-l1 | 1 | 2 | 0 | vscodium | - |
| api-ms-win-crt-utility-l1 | 1 | 2 | 0 | electron, vscodium | - |
| winhvplatform.dll | 17 | 1 | 0 | vscodium | - |
| ncrypt.dll | 14 | 1 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| wininet.dll | 11 | 1 | 1 | chromium, vscodium | chromium:D |
| netapi32.dll | 9 | 1 | 1 | chromium, vscodium | chromium:D |
| vcruntime140.dll | 8 | 1 | 0 | vscodium | - |
| ext-ms-win-uiacore-l1 | 5 | 1 | 0 | vscodium | - |
| api-ms-win-core-fibers-l1 | 4 | 1 | 0 | vscodium | - |
| usp10.dll | 4 | 1 | 0 | vscodium | - |
| api-ms-win-ntuser-sysparams-l1 | 3 | 1 | 0 | vscodium | - |
| api-ms-win-shcore-scaling-l1 | 3 | 1 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| api-ms-win-core-datetime-l1 | 2 | 1 | 0 | vscodium | - |
| api-ms-win-core-realtime-l1 | 2 | 1 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| api-ms-win-core-string-l2 | 2 | 1 | 0 | vscodium | - |
| api-ms-win-core-string-obsolete-l1 | 2 | 1 | 0 | vscodium | - |
| imm32.dll | 2 | 1 | 1 | chromium, vscodium | chromium:D |
| urlmon.dll | 2 | 1 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| api-ms-win-core-console-l3 | 1 | 1 | 0 | vscodium | - |
| api-ms-win-core-io-l1 | 1 | 1 | 0 | vscodium | - |
| api-ms-win-core-path-l1 | 1 | 1 | 0 | vscodium | - |
| api-ms-win-core-sidebyside-l1 | 1 | 1 | 0 | vscodium | - |
| api-ms-win-core-wow64-l1 | 1 | 1 | 0 | vscodium | - |
| api-ms-win-shcore-obsolete-l1 | 1 | 1 | 0 | vscodium | - |
| api-ms-win-shell-namespace-l1 | 1 | 1 | 0 | vscodium | - |
| d2d1.dll | 1 | 1 | 0 | vscodium | - |
| d3d11.dll | 1 | 1 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| powrprof.dll | 1 | 1 | 0 | vscodium | - |
| sspicli.dll | 1 | 1 | 0 | vscodium | - |
| tdh.dll | 1 | 1 | 0 | vscodium | - |
| mfplat.dll | 23 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| esent.dll | 12 | 0 | 1 | chromium | chromium:D |
| bthprops.cpl | 11 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| hid.dll | 11 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| icu.dll | 11 | 0 | 1 | vscodium | - |
| setupapi.dll | 10 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| wintrust.dll | 10 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| uiautomationcore.dll | 9 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| winusb.dll | 9 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| winspool.drv | 8 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| uxtheme.dll | 6 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| comctl32.dll | 5 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| d3d9.dll | 5 | 0 | 1 | vscodium | - |
| dwmapi.dll | 5 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| oleacc.dll | 5 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| wevtapi.dll | 5 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| wtsapi32.dll | 4 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| api-ms-win-power-setting-l1 | 3 | 0 | 1 | chromium | chromium:D |
| ndfapi.dll | 3 | 0 | 1 | chromium | chromium:D |
| api-ms-win-power-base-l1 | 2 | 0 | 6 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| cryptui.dll | 2 | 0 | 2 | chromium, electron | chromium:D, electron:D |
| dcomp.dll | 2 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| dhcpcsvc.dll | 2 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| mf.dll | 2 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| tbs.dll | 2 | 0 | 2 | chromium, electron | chromium:D, electron:D |
| comdlg32.dll | 1 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| credui.dll | 1 | 0 | 1 | chromium | chromium:D |
| d3d12.dll | 1 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| fontsub.dll | 1 | 0 | 1 | vscodium | vscodium:D |
| mfreadwrite.dll | 1 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |
| mmdevapi.dll | 1 | 0 | 3 | chromium, electron, vscodium | chromium:D, electron:D, vscodium:D |

### 6.1 The two big ones are on the GUI track already

`user32.dll` (271 distinct imported functions; 215 delay-loaded by `electron.exe`) and `gdi32.dll` (107; 95 by
`electron.exe`) exist on branch `integ2-dryrun` (`e384399`), not in this tree. Measured read-only against that branch's
sources (`DLLAPI` definitions plus `module.json` forwarders, same regex as `build.py`): its `user32` exports 129 names
and covers **109 of the 271** imported (40.2 %; 75 of the 142 load-time-imported names; 105 of electron.exe's 215),
its `gdi32` exports 107 names and covers **61 of the 107** imported (57.0 %; 30 of 44 load-time; 55 of electron.exe's
95). The 162 user32 and 46 gdi32 names still missing there are listed by name in `matrix.json` (`user32.dll`,
`gdi32.dll`); the branch also maps 11 `ext-ms-win-ntuser-*`/`ext-ms-win-gdi-*` contracts that this tree's ldr.c does
not (41 schema entries versus 30). These are needed for M4, and for M3 only in so far as the GPU/SwiftShader DLLs and
`OpenConsole.exe` import them at load time.

### 6.2 Approach and effort per missing DLL

Policy reminder (BASELINE §5): own implementations carry `SPDX-License-Identifier: GPL-2.0-only`; a Wine excerpt
(LGPL-2.1-or-later) or ReactOS excerpt (GPL-2.0-or-later) is allowed only in the external-reuse profile, pinned by commit
and licence in `shizukudos/upstream/manifest.json` with the patch set under the consuming component, and is never
labelled an original implementation. `THIRD_PARTY.md` already records Wine `df15af36…` and ReactOS `9dc3ca87…` as
reviewed sources for the x86 wrappers; the Win64 profile should pin its own commits.

| DLL / group | needed for | approach (truthful) | effort |
|---|---|---|---|
| `crypt32.dll` (42 distinct; 28 at load time in electron.exe/VSCodium.exe, 26 in chrome.dll) | M1 (load), M3 (network stack reads the certificate store; DPAPI for cookie/login encryption) | Own module. M1: export the 28 with explicit-failure semantics where Chromium tolerates absence (`CertOpenStore`/`CertOpenSystemStoreW` returning NULL with `ERROR_NOT_SUPPORTED`, enumerations returning nothing, `CertGetCertificateChain` failing) — Chromium treats an empty system store as "no roots" and continues; `CryptProtectData`/`CryptUnprotectData`/`CryptProtectMemory`/`CryptUnprotectMemory` implemented for real over the existing `bcrypt` AES-GCM with a per-installation key (own). X.509 parsing/chain building for real (`CryptQueryObject`, `CertGetCertificateChain`, `CryptVerifyCertificateSignatureEx`): Wine `dlls/crypt32` excerpt under the reuse policy, or own ASN.1/X.509 over bcrypt. | M (M1 form), L (full) |
| `dwrite.dll` (1 function, `DWriteCreateFactory`; every image of the three products that renders text) | M1 (load), M3/M4 (Chromium 148–157 on Windows has no non-DirectWrite font path: Skia's `SkFontMgr_DirectWrite`, `gfx::win::` font fallback and `DWriteFontProxy` all start from `IDWriteFactory`) | Own module. M1/M2: `DWriteCreateFactory` returning `E_NOTIMPL` (explicit failure) so the import resolves; M3: a factory that implements `IDWriteFactory{,1,2,3}::GetSystemFontCollection`, `CreateFontFileReference`, `CreateFontFace`, `IDWriteFontFace::TryGetFontTable`/`GetGlyphIndices`/`GetDesignGlyphMetrics`/`GetMetrics`, `IDWriteFontCollection`/`Family`/`Font` enumeration over TrueType/OpenType files shipped with the system (Chromium shapes with HarfBuzz on the raw tables and rasterises with Skia, so the DirectWrite rasteriser is not needed for M3/M4; `IDWriteTextAnalyzer`/`IDWriteFontFallback` are needed for the UI font fallback path). Wine `dlls/dwrite` is a large LGPL implementation (uses FreeType for rasterisation) and is the candidate excerpt for the object model; the table-parsing subset is small enough to own. | S (M1 form), L–XL (M3 form) |
| `winmm.dll` (built, 3/32 provided; 28 wave/midi functions at load time) | M1 | Own: the 28 are all `waveIn*/waveOut*/midiIn*/midiOut*`; with no audio device they legitimately return `MMSYSERR_NODRIVER`/`MMSYSERR_BADDEVICEID` and `*GetNumDevs` returns 0 — Chromium's audio manager then reports no devices. Real audio needs a Kernel64 sound driver (XL, out of scope). | S |
| `ws2_32.dll` (built, 17/65 missing; 11–13 at load time) | M1 | Own over the existing socket layer: `GetAddrInfoExW`/`FreeAddrInfoExW`/`GetAddrInfoExCancel` (synchronous form over `getaddrinfo`), `GetNameInfoW`, `WSAEnumProtocolsW` (one TCP and one UDP `WSAPROTOCOL_INFOW`), `WSAGetOverlappedResult` (needs overlapped socket I/O — see IOCP below), `WSADuplicateSocketW` (cross-process handle duplication; Chromium uses it only for socket brokering, explicit failure acceptable), `WSALookupService*`/`WSASetServiceW`/`WSC*`/`WSAEnumNameSpaceProvidersW` (explicit failure `WSASERVICE_NOT_FOUND`). | M |
| `ntdll.dll` (built; `LdrLockLoaderLock`, `LdrUnlockLoaderLock`) | M1 | Own: a critical section around the loader database, matching the cookie/flags contract. | S |
| `kernel32.dll` (built, 221 exports; 292 distinct missing, 227 in electron.exe's load-time set) | M1–M4 | Own; this is the kernel32 track's list. Grouped in section 10 with effort per group. Cheap first: `RtlAddFunctionTable`/`RtlDeleteFunctionTable` are already exported by Shizuku ntdll (forward them like the 7 existing forwarders in `build.py:101`); `psapi.dll`'s 3 functions are the `K32*` names. The project's own x86 code has SList and InitOnce implementations (`src/m98_slist.c`, `src/m98_initonce.c`, GPL-2.0-only, with their Wine/ReactOS review receipts) that can be ported to Win64. | see §10 |
| `userenv.dll` (11; 7 load-time images, mostly helper exes and `rg.exe`) | M3 for child processes (`rg.exe` search, VSCodium helpers) | Own: `GetUserProfileDirectoryW`, `CreateEnvironmentBlock`/`DestroyEnvironmentBlock` over the loader's environment; the rest explicit failure. | S–M |
| `dbghelp.dll` (15; 6 Chromium helper exes at load time, delay in the main images) | Chromium helper exes; crash reporting | Own: `MiniDumpWriteDump` and `Sym*` as explicit failures (`ERROR_NOT_SUPPORTED`); `ImageNtHeader`/`ImageRvaToVa` for real (PE helpers). | S |
| `api-ms-win-crt-*` (5 contracts, 25+19+12+12+7+3+2+1 functions) and `vcruntime140.dll` (8) | only `dxil.dll` (shader compiler), `conpty.dll`/`OpenConsole.exe` (VSCodium terminals) and `os_proxy_resolver.node` | These are the only images built against the dynamic UCRT; the products' main images link the CRT statically. A `ucrtbase.dll`/`vcruntime140.dll` implementation is XL and Microsoft's own cannot be shipped. Recommendation: out of scope for M1–M4; `dxil.dll` is never needed with `--disable-gpu`, and VSCodium terminals are a post-M4 feature. | XL (declared out of scope) |
| `winhttp.dll` (20), `wininet.dll` (11) | Chromium reads the system proxy configuration (`WinHttpGetIEProxyConfigForCurrentUser`, `WinHttpGetProxyForUrl`) | Own: proxy-configuration functions returning "no proxy" honestly (`WinHttpGetIEProxyConfigForCurrentUser` with all-NULL config and `fAutoDetect = FALSE`), session/request functions explicit failure — Chromium's HTTP stack is its own (BoringSSL/net), it does not use WinHTTP for transfers. | S |
| `cfgmgr32.dll` (11; `vulkan-1.dll` load time), `setupapi.dll` (10), `hid.dll` (11), `winusb.dll` (9), `bthprops.cpl` (11), `dhcpcsvc.dll` (2), `tbs.dll` (2) | device enumeration (USB/HID/Bluetooth/TPM) — none for M1–M4 | Own: enumeration APIs that report no devices (`CM_Get_Device_ID_List_SizeW` → 1, `CM_Locate_DevNodeW` → `CR_NO_SUCH_DEVNODE`, `SetupDiGetClassDevsW` → an empty set); these are honest answers on a system with no such buses. | S |
| `secur32.dll`/`sspicli.dll` (20+1) | HTTP auth (NTLM/Negotiate), `kerberos.node` | Own: `EnumerateSecurityPackagesW` reporting no packages, `AcquireCredentialsHandleW` → `SEC_E_SECPKG_NOT_FOUND`; `GetUserNameExW` for real (formats over the single local user). | S |
| `iphlpapi.dll` (17) | network change notification, adapter enumeration (`GetAdaptersAddresses`, `NotifyAddrChange`, `GetIfTable2`) — used by Chromium's `NetworkChangeNotifierWin` at network-service start (M3) | Own over the Kernel64 network stack (one adapter, its addresses, a never-signalled change notification). | M |
| `pdh.dll` (7), `wevtapi.dll` (5), `wtsapi32.dll` (4), `netapi32.dll` (9), `esent.dll` (12), `ndfapi.dll` (3), `tdh.dll` (1), `powrprof.dll` (1 + 2 contracts) | metrics/telemetry/session queries | Own explicit failures; `PowerDeterminePlatformRoleEx` → `PlatformRoleDesktop`, `CallNtPowerInformation(SystemPowerCapabilities)` for real (small struct), `WTSQuerySessionInformationW` for real (one session). | S |
| `propsys.dll` (7), `urlmon.dll` (2), `credui.dll` (1), `cryptui.dll` (2), `comdlg32.dll` (1), `fontsub.dll` (1), `icu.dll` (11, VSCodium addon only) | shell integration, dialogs | `PropVariant*` helpers for real (own, small); the rest explicit failure. | S–M |
| `dxgi.dll` (3), `d3d11.dll` (1), `d3d12.dll` (#101 `D3D12CreateDevice`), `dcomp.dll` (2), `d2d1.dll` (#1), `d3d9.dll` (5) | GPU; `vk_swiftshader.dll`/`libGLESv2.dll` also import user32/gdi32 at load time | Own: `CreateDXGIFactory{1,2}` → `DXGI_ERROR_UNSUPPORTED`, `D3D11CreateDevice`/`D3D12CreateDevice` → `DXGI_ERROR_UNSUPPORTED`; with `--disable-gpu` Chromium takes the software compositor. A real D3D/Vulkan path is XL and out of scope. | S |
| `mfplat.dll` (23), `mf.dll` (2), `mfreadwrite.dll` (1), `mmdevapi.dll` (#17 `ActivateAudioInterfaceAsync`) | media playback | Own: `MFStartup` → `MF_E_PLATFORM_NOT_INITIALIZED` family of explicit failures; `ActivateAudioInterfaceAsync` → `E_NOTIMPL`. | S |
| `uiautomationcore.dll` (9) + `ext-ms-win-uiacore-l1` (5), `oleacc.dll` (5) | accessibility | Own explicit failures (`UiaReturnRawElementProvider` → `E_NOTIMPL`, `UiaHostProviderFromHwnd` likewise); Chromium disables accessibility when the platform reports none. | S |
| `winspool.drv` (8, #203), `uxtheme.dll` (6, #47 `DrawThemeBackgroundEx`), `dwmapi.dll` (5), `imm32.dll` (2), `comctl32.dll` (5: #345 `TaskDialogIndirect`, #410 `SetWindowSubclass`, #412 `RemoveWindowSubclass`, #413 `DefSubclassProc`, +1 by name), `usp10.dll` (4) | M4 window chrome and input | Belongs with the GUI track: `DwmIsCompositionEnabled` → FALSE and the other DWM calls `E_NOTIMPL`; `uxtheme` as explicit failures (classic look); `imm32` explicit failure (no IME); `comctl32` subclassing for real (own, small) and `TaskDialogIndirect` explicit failure; printing explicit failure. | S–M |
| `api-ms-win-shcore-scaling-l1` (`GetDpiForMonitor`, `GetScaleFactorForMonitor`, `SetProcessDpiAwareness`), `api-ms-win-core-realtime-l1` (`QueryUnbiasedInterruptTime[Precise]`), `api-ms-win-power-base-l1`, `api-ms-win-core-winrt-error-l1` (`RoOriginateError[W]`) — the four contracts the main images use | M3/M4 (delay-loaded by electron.exe/VSCodium.exe/chrome.dll) | Own functions in the hosting module (kernel32 for realtime, combase for winrt-error, a `shcore.dll` or user32 for scaling, `powrprof.dll` for power) **and** the ldr.c schema entry; ldr.c's rule is that a contract is listed only when the host really exports the functions. | S each |
| `winhvplatform.dll` (17) | `wxc-exec.exe` (VSCodium's Windows Sandbox helper) | Out of scope (Hyper-V platform). | — |

## 7. Imports by ordinal: the unpinned-ordinal hazard

| DLL | ordinal | denotes (Wine 9.0 export table) | binds to in Shizuku build | apps | load-time in |
|---|---|---|---|---|---|
| comctl32.dll | #345 | TaskDialogIndirect | DLL absent | electron, vscodium | - |
| comctl32.dll | #410 | SetWindowSubclass | DLL absent | electron, vscodium | - |
| comctl32.dll | #412 | RemoveWindowSubclass | DLL absent | electron, vscodium | - |
| comctl32.dll | #413 | DefSubclassProc | DLL absent | electron, vscodium | - |
| d2d1.dll | #1 | D2D1CreateFactory | DLL absent | vscodium | vscodium |
| d3d12.dll | #101 | D3D12CreateDevice | DLL absent | chromium, electron, vscodium | - |
| mmdevapi.dll | #17 | ActivateAudioInterfaceAsync | DLL absent | chromium, electron, vscodium | - |
| shell32.dll | #2 | SHChangeNotifyRegister | **GetCurrentProcessExplicitAppUserModelID** (wrong function) | chromium | - |
| shell32.dll | #4 | SHChangeNotifyDeregister | **SHGetKnownFolderPath** (wrong function) | chromium | - |
| shell32.dll | #102 | SHCoCreateInstance | out of range | vscodium | vscodium |
| shell32.dll | #155 | ILFree | out of range | chromium, electron, vscodium | chromium |
| shell32.dll | #190 | ILCreateFromPathW | out of range | chromium, electron, vscodium | chromium |
| shell32.dll | #680 | IsUserAnAdmin | out of range | chromium | chromium |
| shlwapi.dll | #12 | SHCreateMemStream | **PathIsRootW** (wrong function) | chromium, electron, vscodium | - |
| shlwapi.dll | #219 | QISearch | out of range | chromium, electron | - |
| shlwapi.dll | #437 | IsOS | out of range | chromium | chromium |
| uxtheme.dll | #47 | DrawThemeBackgroundEx | DLL absent | chromium, electron, vscodium | - |
| winspool.drv | #203 | GetDefaultPrinterW | DLL absent | chromium, electron, vscodium | - |

Shizuku's `.def` files are written by `build.py:write_def` as bare name lists, so mingw numbers the exports
alphabetically from 1. Windows' `shell32`/`shlwapi`/`comctl32` ordinals are fixed interface numbers. Today an ordinal
import into a Shizuku DLL either falls outside the export range (the loader reports `STATUS_ORDINAL_NOT_FOUND`, ldr.c:260)
or, worse, **silently binds the wrong function**: `shlwapi!#12` (`SHCreateMemStream` on Windows) would resolve to
Shizuku's `PathIsRootW`; `shell32!#2`/`#4` (`SHChangeNotifyRegister`/`Deregister`) to
`GetCurrentProcessExplicitAppUserModelID`/`SHGetKnownFolderPath`. Fix (S): give `write_def` an ordinal table per DLL
(the `NAME @N` form) taken from a pinned reference — the mingw-w64 `.def` files for these DLLs, or the export tables of
the Wine PE builds used above; both carry Windows' numbers, which are interface data — and make `import_coverage.py`'s
`ordinal-unpinned` count a CI gate at zero. Until then `GetProcAddress(h, MAKEINTRESOURCE(n))` is unsafe for these
modules too (electron.exe's delay-load helper uses exactly that for the six ordinals above).

## 8. API-set contracts missing from the ldr.c schema

Only 9 of the 143 unmapped-contract functions, in 4 contracts, are used by the three products' main images, and all
of them are delay-loaded: `api-ms-win-shcore-scaling-l1` (`GetDpiForMonitor`, `GetScaleFactorForMonitor`,
`SetProcessDpiAwareness`), `api-ms-win-power-base-l1` (`CallNtPowerInformation`, `PowerDeterminePlatformRoleEx`),
`api-ms-win-core-realtime-l1` (`QueryUnbiasedInterruptTimePrecise`) and, chrome.dll only, `api-ms-win-power-setting-l1`
(`PowerGetActiveScheme`, `PowerReadACValue`, `PowerReadDCValue`); `notification_helper.exe` additionally needs
`api-ms-win-core-winrt-error-l1` at load time. Everything else is the dynamic-UCRT set (`dxil.dll`, ConPTY,
`os_proxy_resolver.node`) and `msalruntime.dll`/`OpenConsole.exe`, which are built against many `api-ms-win-core-*`
contracts whose functions kernel32 largely does not export yet either. The "host by name family" column is a
suggestion for the schema entry, not a statement that the host exports the names.

| contract prefix | functions | images | apps | binding | host by name family | function names |
|---|---:|---:|---|---|---|---|
| api-ms-win-power-base-l1 | 2 | 6 | chromium, electron, vscodium | delay-load only | powrprof.dll | CallNtPowerInformation, PowerDeterminePlatformRoleEx |
| api-ms-win-crt-runtime-l1 | 25 | 5 | electron, vscodium | load-time | ucrtbase.dll | _c_exit, _cexit, _configure_narrow_argv, _configure_wide_argv, _crt_atexit, _errno, _execute_onexit_table, _exit, _get_wide_winmain_command_line, _initialize_narrow_environment, _initialize_onexit_table, _initialize_wide_environment, _initterm, _initterm_e, _invalid_parameter_noinfo, _invalid_parameter_noinfo_noreturn, _invoke_watson, _register_onexit_function, _register_thread_local_exe_atexit_callback, _seh_filter_dll, _seh_filter_exe, _set_app_type, abort, exit, terminate |
| api-ms-win-crt-heap-l1 | 7 | 5 | electron, vscodium | load-time | ucrtbase.dll | _aligned_free, _aligned_malloc, _callnewh, _set_new_mode, calloc, free, malloc |
| api-ms-win-crt-stdio-l1 | 19 | 4 | electron, vscodium | load-time | ucrtbase.dll | __acrt_iob_func, __p__commode, __stdio_common_vsnprintf_s, __stdio_common_vsprintf, __stdio_common_vsprintf_s, __stdio_common_vswprintf, __stdio_common_vswprintf_s, _chsize, _close, _fileno, _get_osfhandle, _lseek, _open_osfhandle, _read, _set_fmode, _setmode, _write, _wsopen_dispatch, fwrite |
| api-ms-win-crt-math-l1 | 12 | 4 | electron, vscodium | load-time | ucrtbase.dll | __setusermatherr, _fpclass, ceil, ceilf, floorf, log10, lrintf, lround, lroundf, pow, powf, roundf |
| api-ms-win-crt-string-l1 | 12 | 4 | electron, vscodium | load-time | ucrtbase.dll | isalnum, isalpha, isdigit, isprint, strcmp, strcpy_s, strlen, toupper, towlower, wcscpy_s, wcsncmp, wcsnlen |
| api-ms-win-shcore-scaling-l1 | 3 | 4 | chromium, electron, vscodium | load-time | shcore.dll | GetDpiForMonitor, GetScaleFactorForMonitor, SetProcessDpiAwareness |
| api-ms-win-core-realtime-l1 | 2 | 4 | chromium, electron, vscodium | load-time | kernel32.dll | QueryUnbiasedInterruptTime, QueryUnbiasedInterruptTimePrecise |
| api-ms-win-core-heap-l2 | 4 | 3 | vscodium | load-time | kernel32.dll | GlobalAlloc, GlobalFree, LocalAlloc, LocalFree |
| api-ms-win-core-debug-l1 | 3 | 3 | vscodium | load-time | kernel32.dll | DebugBreak, IsDebuggerPresent, OutputDebugStringW |
| api-ms-win-crt-convert-l1 | 3 | 3 | electron, vscodium | load-time | ucrtbase.dll | atoi, wcstol, wcstoul |
| api-ms-win-core-util-l1 | 2 | 3 | vscodium | load-time | kernel32.dll | DecodePointer, EncodePointer |
| api-ms-win-core-winrt-error-l1 | 2 | 3 | chromium, vscodium | load-time | combase.dll | RoOriginateError, RoOriginateErrorW |
| api-ms-win-core-file-l2 | 1 | 3 | vscodium | load-time | kernel32.dll | GetFileInformationByHandleEx |
| api-ms-win-core-threadpool-l1 | 9 | 2 | vscodium | load-time | kernel32.dll | CloseThreadpoolTimer, CloseThreadpoolWait, CreateThreadpoolTimer, CreateThreadpoolWait, SetThreadpoolTimer, SetThreadpoolWait, TrySubmitThreadpoolCallback, WaitForThreadpoolTimerCallbacks, WaitForThreadpoolWaitCallbacks |
| api-ms-win-core-heap-obsolete-l1 | 3 | 2 | vscodium | load-time | kernel32.dll | GlobalLock, GlobalSize, GlobalUnlock |
| api-ms-win-crt-locale-l1 | 2 | 2 | vscodium | load-time | ucrtbase.dll | ___lc_codepage_func, _configthreadlocale |
| api-ms-win-core-largeinteger-l1 | 1 | 2 | vscodium | load-time | kernel32.dll | MulDiv |
| api-ms-win-core-namedpipe-l1 | 1 | 2 | vscodium | load-time | kernel32.dll | CreatePipe |
| api-ms-win-core-psapi-l1 | 1 | 2 | vscodium | load-time | kernel32.dll | K32GetModuleFileNameExW |
| api-ms-win-crt-utility-l1 | 1 | 2 | electron, vscodium | load-time | ucrtbase.dll | qsort |
| ext-ms-win-uiacore-l1 | 5 | 1 | vscodium | load-time | uiautomationcore.dll | UiaGetReservedMixedAttributeValue, UiaGetReservedNotSupportedValue, UiaHostProviderFromHwnd, UiaRaiseAutomationEvent, UiaReturnRawElementProvider |
| api-ms-win-core-fibers-l1 | 4 | 1 | vscodium | load-time | kernel32.dll | FlsAlloc, FlsFree, FlsGetValue, FlsSetValue |
| api-ms-win-ntuser-sysparams-l1 | 3 | 1 | vscodium | load-time | user32.dll | GetMonitorInfoW, GetSystemMetrics, SystemParametersInfoW |
| api-ms-win-power-setting-l1 | 3 | 1 | chromium | delay-load only | powrprof.dll | PowerGetActiveScheme, PowerReadACValue, PowerReadDCValue |
| api-ms-win-core-datetime-l1 | 2 | 1 | vscodium | load-time | kernel32.dll | GetDateFormatW, GetTimeFormatW |
| api-ms-win-core-string-l2 | 2 | 1 | vscodium | load-time | kernel32.dll | CharLowerW, CharNextW |
| api-ms-win-core-string-obsolete-l1 | 2 | 1 | vscodium | load-time | kernel32.dll | lstrcmpW, lstrcmpiW |
| api-ms-win-core-console-l3 | 1 | 1 | vscodium | load-time | kernel32.dll | GetConsoleWindow |
| api-ms-win-core-io-l1 | 1 | 1 | vscodium | load-time | kernel32.dll | DeviceIoControl |
| api-ms-win-core-path-l1 | 1 | 1 | vscodium | load-time | kernel32.dll | PathCchRemoveExtension |
| api-ms-win-core-sidebyside-l1 | 1 | 1 | vscodium | load-time | kernel32.dll | CreateActCtxW |
| api-ms-win-core-wow64-l1 | 1 | 1 | vscodium | load-time | kernel32.dll | IsWow64Process2 |
| api-ms-win-shcore-obsolete-l1 | 1 | 1 | vscodium | load-time | shcore.dll | CommandLineToArgvW |
| api-ms-win-shell-namespace-l1 | 1 | 1 | vscodium | load-time | shell32.dll | SHCreateItemFromParsingName |

The seven contracts electron.exe does use that **are** mapped resolve today: `api-ms-win-core-synch-l1-2-0`
(`WaitOnAddress`/`WakeByAddress*`, provided), `api-ms-win-core-handle-l1`, `api-ms-win-core-winrt-l1`
(`RoInitialize`/`RoUninitialize` provided; `RoGetActivationFactory`/`RoActivateInstance` missing in combase),
`api-ms-win-core-winrt-string-l1` (HSTRING functions provided).

## 9. Dynamic evidence from Wine (host-side, not Kernel64)

Wine 9.0 (`wine64 9.0~repack-4build3`, Debian PE builds) is installed on the build host, so `electron.exe --version`
was run there twice with `WINEDEBUG=+relay` restricted to `kernel32.*;kernelbase.*;ntdll.*;ws2_32.*;winmm.*;crypt32.*;`
`dwrite.*;version.*` (calls *from* kernel32/user32/gdi32/advapi32 are excluded by Wine's default `RelayFromExclude`, so
the counts below are calls made by electron.exe's own code). This is host-side evidence about which imported functions
the start-up path actually calls; it says nothing about Kernel64 and the code paths can differ there (Wine reports a
different OS build, has a display, and its own DLLs answer).

| run | result | relay call lines | distinct functions called (by DLL) | electron.exe load-time imports called | of which unresolved in Shizuku |
|---|---|---:|---|---:|---:|
| without a display | exited 3 after `nodrv_CreateWindow` (start-up creates a window before handling `--version`), no output | 318,202 | dwrite.dll 1, kernel32.dll 125, kernelbase.dll 8, ntdll.dll 163, ws2_32.dll 6 | 126 of 537 | 37 |
| under Xvfb (`xvfb-run`) | printed `v44.4.5`, exit code 0 (7 s wall clock) | 512,048 | dwrite.dll 1, kernel32.dll 137, kernelbase.dll 11, ntdll.dll 167, ws2_32.dll 6 | 135 of 537 | 43 |

Functions that the complete `--version` run called and that Shizuku does not export today (call counts in brackets;
this is the M2 short list, to be confirmed on the guest):

* **dwrite.dll** (1): `DWriteCreateFactory`[1]
* **kernel32.dll** (42): `AreFileApisANSI`[1], `CompareStringW`[484], `CreateFileMappingW`[48], `CreateIoCompletionPort`[5], `CreateNamedPipeA`[1], `FindResourceW`[10], `GetDynamicTimeZoneInformation`[1], `GetErrorMode`[1], `GetFileAttributesExW`[57], `GetGeoInfoW`[1], `GetLocaleInfoEx`[1], `GetLogicalProcessorInformationEx`[1], `GetModuleHandleExA`[3], `GetModuleHandleExW`[9], `GetPackageFamilyName`[1], `GetProcessMitigationPolicy`[1], `GetProductInfo`[1], `GetQueuedCompletionStatus`[19], `GetQueuedCompletionStatusEx`[1], `GetStringTypeW`[9], `GetSystemPowerStatus`[1], `GetThreadPreferredUILanguages`[2], `GetUserDefaultLocaleName`[5], `GetUserGeoID`[1], `GlobalLock`[2], `GlobalSize`[2], `GlobalUnlock`[2], `HeapSetInformation`[1], `LCIDToLocaleName`[568], `LCMapStringW`[16], `LoadResource`[10], `LocaleNameToLCID`[4], `MapViewOfFile`[48], `PostQueuedCompletionStatus`[15], `RegisterWaitForSingleObject`[1], `SetConsoleCtrlHandler`[5], `SetNamedPipeHandleState`[1], `SetThreadInformation`[4], `SizeofResource`[4], `UnmapViewOfFile`[46], `VerifyVersionInfoW`[1], `lstrcmpW`[6]

The other 92 imported functions it called are exported by Shizuku already; whether they behave as Chromium
expects is not measured here. DLLs Wine loaded for the run (from `+loaddll`): the seven load-time DLLs plus, by delay-load,
`advapi32`, `shell32`, `shlwapi`, `ole32`, `oleaut32`, `combase`, `user32`, `gdi32`, `uxtheme`, `imm32`, `shcore`, `powrprof`,
`bcrypt`, `bcryptprimitives`, `rpcrt4`, `windows.media` — that is, `--version` already touches the GUI and shell DLLs.
`chrome.exe --version` under the same Wine exits 1 without printing: chrome.exe loaded `chrome.dll`, crashpad's
`TransactNamedPipe` registration failed (`Broken pipe`), and `base::i18n` aborted with `Invalid file descriptor to ICU data`
(`icu_util.cc:237/310`) — i.e. Chromium's `--version` path already needs a working named pipe and a memory-mapped
`icudtl.dat`, which Electron's earlier `--version` exit does not. It was not investigated further.

## 10. Top 300 unresolved functions (all three products)

Rank = products importing the function at load time, then images at load time, then the same for delay-load.
Status `fn-missing` = DLL built, function not exported; `dll-missing` = DLL not built. Ordinals show the Windows name.
The full ranking (all 1,457) is in `coverage/next.json` (`next`, first 300) and `coverage/matrix.json` (all).

| # | DLL / contract | function | status | apps L | images L | apps D | images D |
|---:|---|---|---|---:|---:|---:|---:|
| 1 | kernel32.dll | InitializeSListHead | fn-missing | 3 | 62 | 0 | 0 |
| 2 | kernel32.dll | GetModuleHandleExW | fn-missing | 3 | 60 | 0 | 0 |
| 3 | kernel32.dll | FindFirstFileExW | fn-missing | 3 | 58 | 0 | 0 |
| 4 | kernel32.dll | LCMapStringW | fn-missing | 3 | 58 | 0 | 0 |
| 5 | kernel32.dll | GetStringTypeW | fn-missing | 3 | 57 | 0 | 0 |
| 6 | kernel32.dll | CompareStringW | fn-missing | 3 | 42 | 0 | 0 |
| 7 | kernel32.dll | InterlockedFlushSList | fn-missing | 3 | 42 | 0 | 0 |
| 8 | kernel32.dll | ReadConsoleW | fn-missing | 3 | 34 | 0 | 0 |
| 9 | kernel32.dll | EnumSystemLocalesW | fn-missing | 3 | 33 | 0 | 0 |
| 10 | kernel32.dll | GetLocaleInfoW | fn-missing | 3 | 33 | 0 | 0 |
| 11 | kernel32.dll | GetUserDefaultLCID | fn-missing | 3 | 33 | 0 | 0 |
| 12 | kernel32.dll | IsValidLocale | fn-missing | 3 | 33 | 0 | 0 |
| 13 | kernel32.dll | FormatMessageA | fn-missing | 3 | 27 | 0 | 0 |
| 14 | kernel32.dll | GetConsoleScreenBufferInfo | fn-missing | 3 | 27 | 0 | 0 |
| 15 | kernel32.dll | GetDateFormatW | fn-missing | 3 | 27 | 0 | 0 |
| 16 | kernel32.dll | GetTimeFormatW | fn-missing | 3 | 27 | 0 | 0 |
| 17 | kernel32.dll | FormatMessageW | fn-missing | 3 | 25 | 0 | 0 |
| 18 | kernel32.dll | GetFileInformationByHandle | fn-missing | 3 | 25 | 0 | 0 |
| 19 | kernel32.dll | CreateFileMappingW | fn-missing | 3 | 19 | 0 | 0 |
| 20 | kernel32.dll | MapViewOfFile | fn-missing | 3 | 19 | 0 | 0 |
| 21 | kernel32.dll | OpenProcess | fn-missing | 3 | 19 | 0 | 0 |
| 22 | kernel32.dll | SetConsoleTextAttribute | fn-missing | 3 | 19 | 0 | 0 |
| 23 | kernel32.dll | UnmapViewOfFile | fn-missing | 3 | 19 | 0 | 0 |
| 24 | kernel32.dll | FreeLibraryAndExitThread | fn-missing | 3 | 18 | 0 | 0 |
| 25 | kernel32.dll | SetFileInformationByHandle | fn-missing | 3 | 17 | 0 | 0 |
| 26 | kernel32.dll | SetHandleInformation | fn-missing | 3 | 17 | 0 | 0 |
| 27 | kernel32.dll | GetFileInformationByHandleEx | fn-missing | 3 | 16 | 0 | 0 |
| 28 | kernel32.dll | GetProcessTimes | fn-missing | 3 | 16 | 0 | 0 |
| 29 | kernel32.dll | DeleteProcThreadAttributeList | fn-missing | 3 | 15 | 0 | 0 |
| 30 | kernel32.dll | ExpandEnvironmentStringsW | fn-missing | 3 | 15 | 0 | 0 |
| 31 | kernel32.dll | GetDriveTypeW | fn-missing | 3 | 15 | 0 | 0 |
| 32 | kernel32.dll | HeapQueryInformation | fn-missing | 3 | 15 | 0 | 0 |
| 33 | kernel32.dll | InitializeProcThreadAttributeList | fn-missing | 3 | 15 | 0 | 0 |
| 34 | kernel32.dll | UpdateProcThreadAttribute | fn-missing | 3 | 15 | 0 | 0 |
| 35 | advapi32.dll | GetTokenInformation | fn-missing | 3 | 14 | 3 | 5 |
| 36 | kernel32.dll | IsWow64Process | fn-missing | 3 | 14 | 0 | 0 |
| 37 | kernel32.dll | GetLogicalProcessorInformation | fn-missing | 3 | 13 | 0 | 0 |
| 38 | kernel32.dll | GetProcessId | fn-missing | 3 | 13 | 0 | 0 |
| 39 | kernel32.dll | SetFileAttributesW | fn-missing | 3 | 13 | 0 | 0 |
| 40 | advapi32.dll | OpenProcessToken | fn-missing | 3 | 12 | 3 | 4 |
| 41 | kernel32.dll | CreateNamedPipeW | fn-missing | 3 | 12 | 0 | 0 |
| 42 | kernel32.dll | GetFileAttributesExW | fn-missing | 3 | 12 | 0 | 0 |
| 43 | kernel32.dll | SetConsoleCtrlHandler | fn-missing | 3 | 12 | 0 | 0 |
| 44 | kernel32.dll | SystemTimeToTzSpecificLocalTime | fn-missing | 3 | 12 | 0 | 0 |
| 45 | kernel32.dll | VerSetConditionMask | fn-missing | 3 | 12 | 0 | 0 |
| 46 | kernel32.dll | VerifyVersionInfoW | fn-missing | 3 | 12 | 0 | 0 |
| 47 | kernel32.dll | GetProductInfo | fn-missing | 3 | 11 | 0 | 0 |
| 48 | kernel32.dll | K32EnumProcessModules | fn-missing | 3 | 11 | 0 | 0 |
| 49 | kernel32.dll | K32GetModuleInformation | fn-missing | 3 | 11 | 0 | 0 |
| 50 | kernel32.dll | LockFileEx | fn-missing | 3 | 11 | 0 | 0 |
| 51 | kernel32.dll | QueryThreadCycleTime | fn-missing | 3 | 11 | 0 | 0 |
| 52 | kernel32.dll | RtlCaptureStackBackTrace | fn-missing | 3 | 11 | 0 | 0 |
| 53 | kernel32.dll | SetFileTime | fn-missing | 3 | 11 | 0 | 0 |
| 54 | kernel32.dll | SetThreadInformation | fn-missing | 3 | 11 | 0 | 0 |
| 55 | kernel32.dll | UnlockFileEx | fn-missing | 3 | 11 | 0 | 0 |
| 56 | kernel32.dll | CreateIoCompletionPort | fn-missing | 3 | 10 | 0 | 0 |
| 57 | kernel32.dll | GetFinalPathNameByHandleW | fn-missing | 3 | 10 | 0 | 0 |
| 58 | kernel32.dll | GetLongPathNameW | fn-missing | 3 | 10 | 0 | 0 |
| 59 | kernel32.dll | PostQueuedCompletionStatus | fn-missing | 3 | 10 | 0 | 0 |
| 60 | kernel32.dll | ReadProcessMemory | fn-missing | 3 | 10 | 0 | 0 |
| 61 | kernel32.dll | ConnectNamedPipe | fn-missing | 3 | 9 | 0 | 0 |
| 62 | kernel32.dll | CreateHardLinkW | fn-missing | 3 | 9 | 0 | 0 |
| 63 | kernel32.dll | DeviceIoControl | fn-missing | 3 | 9 | 0 | 0 |
| 64 | kernel32.dll | GetLocaleInfoEx | fn-missing | 3 | 9 | 0 | 0 |
| 65 | kernel32.dll | HeapWalk | fn-missing | 3 | 9 | 0 | 0 |
| 66 | kernel32.dll | IsThreadAFiber | fn-missing | 3 | 9 | 0 | 0 |
| 67 | kernel32.dll | PeekNamedPipe | fn-missing | 3 | 9 | 0 | 0 |
| 68 | kernel32.dll | RegisterWaitForSingleObject | fn-missing | 3 | 9 | 0 | 0 |
| 69 | kernel32.dll | SetNamedPipeHandleState | fn-missing | 3 | 9 | 0 | 0 |
| 70 | kernel32.dll | UnregisterWaitEx | fn-missing | 3 | 9 | 0 | 0 |
| 71 | kernel32.dll | AssignProcessToJobObject | fn-missing | 3 | 8 | 0 | 0 |
| 72 | kernel32.dll | CancelIo | fn-missing | 3 | 8 | 0 | 0 |
| 73 | kernel32.dll | GetComputerNameExW | fn-missing | 3 | 8 | 0 | 0 |
| 74 | kernel32.dll | GetFileTime | fn-missing | 3 | 8 | 0 | 0 |
| 75 | kernel32.dll | GetThreadId | fn-missing | 3 | 8 | 0 | 0 |
| 76 | kernel32.dll | HeapSetInformation | fn-missing | 3 | 8 | 0 | 0 |
| 77 | kernel32.dll | WaitNamedPipeW | fn-missing | 3 | 8 | 0 | 0 |
| 78 | user32.dll | IsWindow | dll-missing | 3 | 7 | 3 | 4 |
| 79 | kernel32.dll | AreFileApisANSI | fn-missing | 3 | 7 | 0 | 0 |
| 80 | kernel32.dll | CreateFileMappingA | fn-missing | 3 | 7 | 0 | 0 |
| 81 | kernel32.dll | FlushViewOfFile | fn-missing | 3 | 7 | 0 | 0 |
| 82 | kernel32.dll | GetLogicalProcessorInformationEx | fn-missing | 3 | 7 | 0 | 0 |
| 83 | kernel32.dll | GetModuleHandleExA | fn-missing | 3 | 7 | 0 | 0 |
| 84 | kernel32.dll | GetOverlappedResult | fn-missing | 3 | 7 | 0 | 0 |
| 85 | kernel32.dll | GetUserDefaultLangID | fn-missing | 3 | 7 | 0 | 0 |
| 86 | kernel32.dll | K32GetProcessMemoryInfo | fn-missing | 3 | 7 | 0 | 0 |
| 87 | kernel32.dll | K32QueryWorkingSetEx | fn-missing | 3 | 7 | 0 | 0 |
| 88 | kernel32.dll | ReplaceFileW | fn-missing | 3 | 7 | 0 | 0 |
| 89 | kernel32.dll | SetFileCompletionNotificationModes | fn-missing | 3 | 7 | 0 | 0 |
| 90 | kernel32.dll | SetProcessShutdownParameters | fn-missing | 3 | 7 | 0 | 0 |
| 91 | kernel32.dll | TransactNamedPipe | fn-missing | 3 | 7 | 0 | 0 |
| 92 | kernel32.dll | WriteProcessMemory | fn-missing | 3 | 7 | 0 | 0 |
| 93 | user32.dll | GetClientRect | dll-missing | 3 | 6 | 3 | 3 |
| 94 | user32.dll | GetDC | dll-missing | 3 | 6 | 3 | 3 |
| 95 | user32.dll | ReleaseDC | dll-missing | 3 | 6 | 3 | 3 |
| 96 | crypt32.dll | CertCloseStore | dll-missing | 3 | 6 | 0 | 0 |
| 97 | kernel32.dll | CreateToolhelp32Snapshot | fn-missing | 3 | 6 | 0 | 0 |
| 98 | kernel32.dll | CreateWaitableTimerExW | fn-missing | 3 | 6 | 0 | 0 |
| 99 | kernel32.dll | DisconnectNamedPipe | fn-missing | 3 | 6 | 0 | 0 |
| 100 | kernel32.dll | GetHandleInformation | fn-missing | 3 | 6 | 0 | 0 |
| 101 | kernel32.dll | GetProcessHandleCount | fn-missing | 3 | 6 | 0 | 0 |
| 102 | kernel32.dll | GetProcessMitigationPolicy | fn-missing | 3 | 6 | 0 | 0 |
| 103 | kernel32.dll | GetQueuedCompletionStatus | fn-missing | 3 | 6 | 0 | 0 |
| 104 | kernel32.dll | GetThreadContext | fn-missing | 3 | 6 | 0 | 0 |
| 105 | kernel32.dll | K32GetPerformanceInfo | fn-missing | 3 | 6 | 0 | 0 |
| 106 | kernel32.dll | MapViewOfFileEx | fn-missing | 3 | 6 | 0 | 0 |
| 107 | kernel32.dll | QueryFullProcessImageNameW | fn-missing | 3 | 6 | 0 | 0 |
| 108 | kernel32.dll | SetInformationJobObject | fn-missing | 3 | 6 | 0 | 0 |
| 109 | kernel32.dll | SetWaitableTimer | fn-missing | 3 | 6 | 0 | 0 |
| 110 | kernel32.dll | VirtualQueryEx | fn-missing | 3 | 6 | 0 | 0 |
| 111 | crypt32.dll | CertEnumCertificatesInStore | dll-missing | 3 | 5 | 0 | 0 |
| 112 | crypt32.dll | CertFindCertificateInStore | dll-missing | 3 | 5 | 0 | 0 |
| 113 | crypt32.dll | CertFreeCertificateContext | dll-missing | 3 | 5 | 0 | 0 |
| 114 | crypt32.dll | CertOpenStore | dll-missing | 3 | 5 | 0 | 0 |
| 115 | crypt32.dll | CryptProtectData | dll-missing | 3 | 5 | 0 | 0 |
| 116 | crypt32.dll | CryptUnprotectData | dll-missing | 3 | 5 | 0 | 0 |
| 117 | kernel32.dll | CreateJobObjectW | fn-missing | 3 | 5 | 0 | 0 |
| 118 | kernel32.dll | CreateRemoteThread | fn-missing | 3 | 5 | 0 | 0 |
| 119 | kernel32.dll | FindResourceW | fn-missing | 3 | 5 | 0 | 0 |
| 120 | kernel32.dll | GetCurrentProcessorNumber | fn-missing | 3 | 5 | 0 | 0 |
| 121 | kernel32.dll | GetNamedPipeClientProcessId | fn-missing | 3 | 5 | 0 | 0 |
| 122 | kernel32.dll | GetNamedPipeServerProcessId | fn-missing | 3 | 5 | 0 | 0 |
| 123 | kernel32.dll | GetPriorityClass | fn-missing | 3 | 5 | 0 | 0 |
| 124 | kernel32.dll | GetSystemDefaultLCID | fn-missing | 3 | 5 | 0 | 0 |
| 125 | kernel32.dll | GetThreadLocale | fn-missing | 3 | 5 | 0 | 0 |
| 126 | kernel32.dll | GetUserDefaultLocaleName | fn-missing | 3 | 5 | 0 | 0 |
| 127 | kernel32.dll | GetVolumeInformationW | fn-missing | 3 | 5 | 0 | 0 |
| 128 | kernel32.dll | InitOnceBeginInitialize | fn-missing | 3 | 5 | 0 | 0 |
| 129 | kernel32.dll | InitOnceComplete | fn-missing | 3 | 5 | 0 | 0 |
| 130 | kernel32.dll | LoadResource | fn-missing | 3 | 5 | 0 | 0 |
| 131 | kernel32.dll | LockResource | fn-missing | 3 | 5 | 0 | 0 |
| 132 | kernel32.dll | Process32FirstW | fn-missing | 3 | 5 | 0 | 0 |
| 133 | kernel32.dll | Process32NextW | fn-missing | 3 | 5 | 0 | 0 |
| 134 | kernel32.dll | SetProcessMitigationPolicy | fn-missing | 3 | 5 | 0 | 0 |
| 135 | kernel32.dll | TzSpecificLocalTimeToSystemTime | fn-missing | 3 | 5 | 0 | 0 |
| 136 | kernel32.dll | VirtualProtectEx | fn-missing | 3 | 5 | 0 | 0 |
| 137 | kernel32.dll | Wow64GetThreadContext | fn-missing | 3 | 5 | 0 | 0 |
| 138 | advapi32.dll | CryptAcquireContextW | fn-missing | 3 | 4 | 3 | 3 |
| 139 | advapi32.dll | CryptCreateHash | fn-missing | 3 | 4 | 3 | 3 |
| 140 | advapi32.dll | CryptDestroyHash | fn-missing | 3 | 4 | 3 | 3 |
| 141 | advapi32.dll | CryptReleaseContext | fn-missing | 3 | 4 | 3 | 3 |
| 142 | gdi32.dll | StretchDIBits | dll-missing | 3 | 4 | 3 | 3 |
| 143 | user32.dll | UnregisterClassA | dll-missing | 3 | 4 | 2 | 2 |
| 144 | crypt32.dll | CertAddCertificateContextToStore | dll-missing | 3 | 4 | 0 | 0 |
| 145 | crypt32.dll | CertGetCertificateContextProperty | dll-missing | 3 | 4 | 0 | 0 |
| 146 | crypt32.dll | CryptAcquireCertificatePrivateKey | dll-missing | 3 | 4 | 0 | 0 |
| 147 | dwrite.dll | DWriteCreateFactory | dll-missing | 3 | 4 | 0 | 0 |
| 148 | kernel32.dll | AttachConsole | fn-missing | 3 | 4 | 0 | 0 |
| 149 | kernel32.dll | CancelIoEx | fn-missing | 3 | 4 | 0 | 0 |
| 150 | kernel32.dll | DebugBreak | fn-missing | 3 | 4 | 0 | 0 |
| 151 | kernel32.dll | EnumSystemLocalesEx | fn-missing | 3 | 4 | 0 | 0 |
| 152 | kernel32.dll | GetActiveProcessorCount | fn-missing | 3 | 4 | 0 | 0 |
| 153 | kernel32.dll | GetDiskFreeSpaceA | fn-missing | 3 | 4 | 0 | 0 |
| 154 | kernel32.dll | GetDiskFreeSpaceExW | fn-missing | 3 | 4 | 0 | 0 |
| 155 | kernel32.dll | GetDiskFreeSpaceW | fn-missing | 3 | 4 | 0 | 0 |
| 156 | kernel32.dll | GetDynamicTimeZoneInformation | fn-missing | 3 | 4 | 0 | 0 |
| 157 | kernel32.dll | GetProcessHeaps | fn-missing | 3 | 4 | 0 | 0 |
| 158 | kernel32.dll | GetShortPathNameW | fn-missing | 3 | 4 | 0 | 0 |
| 159 | kernel32.dll | GetTempFileNameA | fn-missing | 3 | 4 | 0 | 0 |
| 160 | kernel32.dll | GetThreadPreferredUILanguages | fn-missing | 3 | 4 | 0 | 0 |
| 161 | kernel32.dll | GetThreadPriorityBoost | fn-missing | 3 | 4 | 0 | 0 |
| 162 | kernel32.dll | HeapCompact | fn-missing | 3 | 4 | 0 | 0 |
| 163 | kernel32.dll | InterlockedPushEntrySList | fn-missing | 3 | 4 | 0 | 0 |
| 164 | kernel32.dll | LockFile | fn-missing | 3 | 4 | 0 | 0 |
| 165 | kernel32.dll | PowerClearRequest | fn-missing | 3 | 4 | 0 | 0 |
| 166 | kernel32.dll | PowerCreateRequest | fn-missing | 3 | 4 | 0 | 0 |
| 167 | kernel32.dll | PowerSetRequest | fn-missing | 3 | 4 | 0 | 0 |
| 168 | kernel32.dll | PrefetchVirtualMemory | fn-missing | 3 | 4 | 0 | 0 |
| 169 | kernel32.dll | QueryInformationJobObject | fn-missing | 3 | 4 | 0 | 0 |
| 170 | kernel32.dll | QueryProcessCycleTime | fn-missing | 3 | 4 | 0 | 0 |
| 171 | kernel32.dll | ReadDirectoryChangesW | fn-missing | 3 | 4 | 0 | 0 |
| 172 | kernel32.dll | SetDefaultDllDirectories | fn-missing | 3 | 4 | 0 | 0 |
| 173 | kernel32.dll | SetPriorityClass | fn-missing | 3 | 4 | 0 | 0 |
| 174 | kernel32.dll | SetThreadPriorityBoost | fn-missing | 3 | 4 | 0 | 0 |
| 175 | kernel32.dll | SizeofResource | fn-missing | 3 | 4 | 0 | 0 |
| 176 | kernel32.dll | TerminateJobObject | fn-missing | 3 | 4 | 0 | 0 |
| 177 | kernel32.dll | UnlockFile | fn-missing | 3 | 4 | 0 | 0 |
| 178 | kernel32.dll | VirtualFreeEx | fn-missing | 3 | 4 | 0 | 0 |
| 179 | kernel32.dll | VirtualLock | fn-missing | 3 | 4 | 0 | 0 |
| 180 | kernel32.dll | VirtualUnlock | fn-missing | 3 | 4 | 0 | 0 |
| 181 | kernel32.dll | lstrcmpW | fn-missing | 3 | 4 | 0 | 0 |
| 182 | advapi32.dll | CryptGetHashParam | fn-missing | 3 | 3 | 3 | 3 |
| 183 | cfgmgr32.dll | CM_Locate_DevNodeW | dll-missing | 3 | 3 | 3 | 3 |
| 184 | cfgmgr32.dll | CM_Get_Device_IDW | dll-missing | 3 | 3 | 1 | 1 |
| 185 | advapi32.dll | CryptHashData | fn-missing | 3 | 3 | 0 | 0 |
| 186 | cfgmgr32.dll | CM_Get_Child | dll-missing | 3 | 3 | 0 | 0 |
| 187 | cfgmgr32.dll | CM_Get_DevNode_Registry_PropertyW | dll-missing | 3 | 3 | 0 | 0 |
| 188 | cfgmgr32.dll | CM_Get_DevNode_Status | dll-missing | 3 | 3 | 0 | 0 |
| 189 | cfgmgr32.dll | CM_Get_Device_ID_ListW | dll-missing | 3 | 3 | 0 | 0 |
| 190 | cfgmgr32.dll | CM_Get_Device_ID_List_SizeW | dll-missing | 3 | 3 | 0 | 0 |
| 191 | cfgmgr32.dll | CM_Get_Sibling | dll-missing | 3 | 3 | 0 | 0 |
| 192 | cfgmgr32.dll | CM_Open_DevNode_Key | dll-missing | 3 | 3 | 0 | 0 |
| 193 | crypt32.dll | CertAddEncodedCertificateToStore | dll-missing | 3 | 3 | 0 | 0 |
| 194 | crypt32.dll | CertAddStoreToCollection | dll-missing | 3 | 3 | 0 | 0 |
| 195 | crypt32.dll | CertCompareCertificateName | dll-missing | 3 | 3 | 0 | 0 |
| 196 | crypt32.dll | CertControlStore | dll-missing | 3 | 3 | 0 | 0 |
| 197 | crypt32.dll | CertFindChainInStore | dll-missing | 3 | 3 | 0 | 0 |
| 198 | crypt32.dll | CertGetEnhancedKeyUsage | dll-missing | 3 | 3 | 0 | 0 |
| 199 | crypt32.dll | CertGetIntendedKeyUsage | dll-missing | 3 | 3 | 0 | 0 |
| 200 | crypt32.dll | CertGetNameStringW | dll-missing | 3 | 3 | 0 | 0 |
| 201 | crypt32.dll | CertOpenSystemStoreW | dll-missing | 3 | 3 | 0 | 0 |
| 202 | crypt32.dll | CertVerifyTimeValidity | dll-missing | 3 | 3 | 0 | 0 |
| 203 | crypt32.dll | CryptMsgClose | dll-missing | 3 | 3 | 0 | 0 |
| 204 | crypt32.dll | CryptMsgGetParam | dll-missing | 3 | 3 | 0 | 0 |
| 205 | crypt32.dll | CryptProtectMemory | dll-missing | 3 | 3 | 0 | 0 |
| 206 | crypt32.dll | CryptQueryObject | dll-missing | 3 | 3 | 0 | 0 |
| 207 | crypt32.dll | CryptUnprotectMemory | dll-missing | 3 | 3 | 0 | 0 |
| 208 | crypt32.dll | CryptVerifyCertificateSignatureEx | dll-missing | 3 | 3 | 0 | 0 |
| 209 | kernel32.dll | AllocConsole | fn-missing | 3 | 3 | 0 | 0 |
| 210 | kernel32.dll | CheckRemoteDebuggerPresent | fn-missing | 3 | 3 | 0 | 0 |
| 211 | kernel32.dll | ClearCommError | fn-missing | 3 | 3 | 0 | 0 |
| 212 | kernel32.dll | ConvertFiberToThread | fn-missing | 3 | 3 | 0 | 0 |
| 213 | kernel32.dll | ConvertThreadToFiberEx | fn-missing | 3 | 3 | 0 | 0 |
| 214 | kernel32.dll | CreateFiberEx | fn-missing | 3 | 3 | 0 | 0 |
| 215 | kernel32.dll | CreateRemoteThreadEx | fn-missing | 3 | 3 | 0 | 0 |
| 216 | kernel32.dll | DeleteFiber | fn-missing | 3 | 3 | 0 | 0 |
| 217 | kernel32.dll | DiscardVirtualMemory | fn-missing | 3 | 3 | 0 | 0 |
| 218 | kernel32.dll | EnumResourceNamesW | fn-missing | 3 | 3 | 0 | 0 |
| 219 | kernel32.dll | EscapeCommFunction | fn-missing | 3 | 3 | 0 | 0 |
| 220 | kernel32.dll | FindFirstFileExA | fn-missing | 3 | 3 | 0 | 0 |
| 221 | kernel32.dll | GetCommModemStatus | fn-missing | 3 | 3 | 0 | 0 |
| 222 | kernel32.dll | GetCommState | fn-missing | 3 | 3 | 0 | 0 |
| 223 | kernel32.dll | GetCurrencyFormatEx | fn-missing | 3 | 3 | 0 | 0 |
| 224 | kernel32.dll | GetDateFormatEx | fn-missing | 3 | 3 | 0 | 0 |
| 225 | kernel32.dll | GetGeoInfoW | fn-missing | 3 | 3 | 0 | 0 |
| 226 | kernel32.dll | GetMaximumProcessorCount | fn-missing | 3 | 3 | 0 | 0 |
| 227 | kernel32.dll | GetMaximumProcessorGroupCount | fn-missing | 3 | 3 | 0 | 0 |
| 228 | kernel32.dll | GetNumberFormatEx | fn-missing | 3 | 3 | 0 | 0 |
| 229 | kernel32.dll | GetPackagePathByFullName | fn-missing | 3 | 3 | 0 | 0 |
| 230 | kernel32.dll | GetPackagesByPackageFamily | fn-missing | 3 | 3 | 0 | 0 |
| 231 | kernel32.dll | GetPrivateProfileStringW | fn-missing | 3 | 3 | 0 | 0 |
| 232 | kernel32.dll | GetProcessInformation | fn-missing | 3 | 3 | 0 | 0 |
| 233 | kernel32.dll | GetSystemPowerStatus | fn-missing | 3 | 3 | 0 | 0 |
| 234 | kernel32.dll | GetThreadGroupAffinity | fn-missing | 3 | 3 | 0 | 0 |
| 235 | kernel32.dll | GetThreadTimes | fn-missing | 3 | 3 | 0 | 0 |
| 236 | kernel32.dll | GetTimeFormatEx | fn-missing | 3 | 3 | 0 | 0 |
| 237 | kernel32.dll | GetUserDefaultUILanguage | fn-missing | 3 | 3 | 0 | 0 |
| 238 | kernel32.dll | GetUserGeoID | fn-missing | 3 | 3 | 0 | 0 |
| 239 | kernel32.dll | GetVolumePathNameW | fn-missing | 3 | 3 | 0 | 0 |
| 240 | kernel32.dll | GlobalLock | fn-missing | 3 | 3 | 0 | 0 |
| 241 | kernel32.dll | GlobalSize | fn-missing | 3 | 3 | 0 | 0 |
| 242 | kernel32.dll | GlobalUnlock | fn-missing | 3 | 3 | 0 | 0 |
| 243 | kernel32.dll | HeapLock | fn-missing | 3 | 3 | 0 | 0 |
| 244 | kernel32.dll | HeapUnlock | fn-missing | 3 | 3 | 0 | 0 |
| 245 | kernel32.dll | LCIDToLocaleName | fn-missing | 3 | 3 | 0 | 0 |
| 246 | kernel32.dll | LocaleNameToLCID | fn-missing | 3 | 3 | 0 | 0 |
| 247 | kernel32.dll | OpenThread | fn-missing | 3 | 3 | 0 | 0 |
| 248 | kernel32.dll | ProcessIdToSessionId | fn-missing | 3 | 3 | 0 | 0 |
| 249 | kernel32.dll | PurgeComm | fn-missing | 3 | 3 | 0 | 0 |
| 250 | kernel32.dll | ResolveLocaleName | fn-missing | 3 | 3 | 0 | 0 |
| 251 | kernel32.dll | RtlAddFunctionTable | fn-missing | 3 | 3 | 0 | 0 |
| 252 | kernel32.dll | RtlDeleteFunctionTable | fn-missing | 3 | 3 | 0 | 0 |
| 253 | kernel32.dll | SetCommState | fn-missing | 3 | 3 | 0 | 0 |
| 254 | kernel32.dll | SetCommTimeouts | fn-missing | 3 | 3 | 0 | 0 |
| 255 | kernel32.dll | SetProcessInformation | fn-missing | 3 | 3 | 0 | 0 |
| 256 | kernel32.dll | SwitchToFiber | fn-missing | 3 | 3 | 0 | 0 |
| 257 | kernel32.dll | UnregisterWait | fn-missing | 3 | 3 | 0 | 0 |
| 258 | kernel32.dll | WTSGetActiveConsoleSessionId | fn-missing | 3 | 3 | 0 | 0 |
| 259 | winmm.dll | midiInAddBuffer | fn-missing | 3 | 3 | 0 | 0 |
| 260 | winmm.dll | midiInClose | fn-missing | 3 | 3 | 0 | 0 |
| 261 | winmm.dll | midiInGetDevCapsW | fn-missing | 3 | 3 | 0 | 0 |
| 262 | winmm.dll | midiInGetNumDevs | fn-missing | 3 | 3 | 0 | 0 |
| 263 | winmm.dll | midiInOpen | fn-missing | 3 | 3 | 0 | 0 |
| 264 | winmm.dll | midiInPrepareHeader | fn-missing | 3 | 3 | 0 | 0 |
| 265 | winmm.dll | midiInReset | fn-missing | 3 | 3 | 0 | 0 |
| 266 | winmm.dll | midiInStart | fn-missing | 3 | 3 | 0 | 0 |
| 267 | winmm.dll | midiInUnprepareHeader | fn-missing | 3 | 3 | 0 | 0 |
| 268 | winmm.dll | midiOutClose | fn-missing | 3 | 3 | 0 | 0 |
| 269 | winmm.dll | midiOutGetDevCapsW | fn-missing | 3 | 3 | 0 | 0 |
| 270 | winmm.dll | midiOutGetNumDevs | fn-missing | 3 | 3 | 0 | 0 |
| 271 | winmm.dll | midiOutLongMsg | fn-missing | 3 | 3 | 0 | 0 |
| 272 | winmm.dll | midiOutOpen | fn-missing | 3 | 3 | 0 | 0 |
| 273 | winmm.dll | midiOutPrepareHeader | fn-missing | 3 | 3 | 0 | 0 |
| 274 | winmm.dll | midiOutReset | fn-missing | 3 | 3 | 0 | 0 |
| 275 | winmm.dll | midiOutShortMsg | fn-missing | 3 | 3 | 0 | 0 |
| 276 | winmm.dll | midiOutUnprepareHeader | fn-missing | 3 | 3 | 0 | 0 |
| 277 | winmm.dll | waveInGetNumDevs | fn-missing | 3 | 3 | 0 | 0 |
| 278 | winmm.dll | waveOutClose | fn-missing | 3 | 3 | 0 | 0 |
| 279 | winmm.dll | waveOutGetNumDevs | fn-missing | 3 | 3 | 0 | 0 |
| 280 | winmm.dll | waveOutOpen | fn-missing | 3 | 3 | 0 | 0 |
| 281 | winmm.dll | waveOutPause | fn-missing | 3 | 3 | 0 | 0 |
| 282 | winmm.dll | waveOutPrepareHeader | fn-missing | 3 | 3 | 0 | 0 |
| 283 | winmm.dll | waveOutReset | fn-missing | 3 | 3 | 0 | 0 |
| 284 | winmm.dll | waveOutRestart | fn-missing | 3 | 3 | 0 | 0 |
| 285 | winmm.dll | waveOutUnprepareHeader | fn-missing | 3 | 3 | 0 | 0 |
| 286 | winmm.dll | waveOutWrite | fn-missing | 3 | 3 | 0 | 0 |
| 287 | ws2_32.dll | FreeAddrInfoExW | fn-missing | 3 | 3 | 0 | 0 |
| 288 | ws2_32.dll | GetAddrInfoExCancel | fn-missing | 3 | 3 | 0 | 0 |
| 289 | ws2_32.dll | GetAddrInfoExW | fn-missing | 3 | 3 | 0 | 0 |
| 290 | ws2_32.dll | WSADuplicateSocketW | fn-missing | 3 | 3 | 0 | 0 |
| 291 | ws2_32.dll | WSAEnumProtocolsW | fn-missing | 3 | 3 | 0 | 0 |
| 292 | ws2_32.dll | WSAGetOverlappedResult | fn-missing | 3 | 3 | 0 | 0 |
| 293 | ws2_32.dll | WSALookupServiceBeginW | fn-missing | 3 | 3 | 0 | 0 |
| 294 | ws2_32.dll | WSALookupServiceEnd | fn-missing | 3 | 3 | 0 | 0 |
| 295 | ws2_32.dll | WSALookupServiceNextW | fn-missing | 3 | 3 | 0 | 0 |
| 296 | ws2_32.dll | WSASetServiceW | fn-missing | 3 | 3 | 0 | 0 |
| 297 | ole32.dll | CoCreateInstance | fn-missing | 2 | 8 | 3 | 3 |
| 298 | advapi32.dll | SetNamedSecurityInfoW | fn-missing | 2 | 7 | 3 | 5 |
| 299 | advapi32.dll | GetNamedSecurityInfoW | fn-missing | 2 | 6 | 3 | 5 |
| 300 | advapi32.dll | GetSecurityDescriptorDacl | fn-missing | 2 | 6 | 3 | 5 |

### 10.1 The kernel32 gap, grouped (292 distinct; 227 in electron.exe's load-time set)

| group | functions (electron.exe load-time set unless noted) | needs | effort |
|---|---|---|---|
| SList / Rtl forwarders | `InitializeSListHead`, `InterlockedFlushSList`, `InterlockedPushEntrySList`; `RtlAddFunctionTable`, `RtlDeleteFunctionTable` (in Shizuku ntdll already), `RtlCaptureStackBackTrace` | ntdll `RtlInitializeSListHead`/`RtlInterlockedFlushSList`/`RtlInterlockedPushEntrySList` + kernel32 forwarders; `RtlCaptureStackBackTrace` walks the unwind data ntdll already has | S |
| NLS / locale | `CompareStringW`, `LCMapStringW`, `GetStringTypeW`, `GetLocaleInfoW`/`Ex`, `EnumSystemLocalesW`/`Ex`, `IsValidLocale`, `GetUserDefaultLCID`/`LangID`/`LocaleName`/`UILanguage`, `GetSystemDefaultLCID`, `GetThreadLocale`, `GetThreadPreferredUILanguages`, `LCIDToLocaleName`, `LocaleNameToLCID`, `ResolveLocaleName`, `GetDateFormatW`/`Ex`, `GetTimeFormatW`/`Ex`, `GetNumberFormatEx`, `GetCurrencyFormatEx`, `GetGeoInfoW`, `GetUserGeoID`, `lstrcmpW`/`lstrcmpiW` (30) | Own. A single documented locale (en-US, LCID 0x0409) with the real `CompareStringW` semantics (`CompareStringOrdinal` exists; the linguistic form needs the Unicode collation subset Chromium's ICU does not need — Chromium calls `CompareStringW` from `base::i18n` fallbacks and the CRT). Called during the complete `--version` run under Wine: `CompareStringW` 484×, `LCIDToLocaleName` 568×, `LCMapStringW` 16×, `GetStringTypeW` 9× (section 9). ReactOS `dll/win32/kernel32/winnls/string/*` and Wine `dlls/kernelbase/locale.c` are the reference excerpts if the tables are taken rather than written. | M (single locale), L (real tables) |
| File mapping / sections | `CreateFileMappingA`/`W`, `OpenFileMappingW`, `MapViewOfFile`/`Ex`, `UnmapViewOfFile`, `FlushViewOfFile` (6) | Kernel64 section objects (`NtCreateSection`/`NtMapViewOfSection`/`NtUnmapViewOfSection`, none exported today) with page-cache-backed file views and named shared sections between processes (Mojo shared memory, `resources.pak`/`icudtl.dat`/V8 snapshot are memory-mapped). `CreateFileMappingW`/`MapViewOfFile`/`UnmapViewOfFile` were called 48×/48×/46× during the complete `--version` run under Wine. | L (kernel) |
| Named pipes | `CreateNamedPipeA`/`W`, `CreatePipe`, `ConnectNamedPipe`, `DisconnectNamedPipe`, `PeekNamedPipe`, `TransactNamedPipe`, `WaitNamedPipeW`, `SetNamedPipeHandleState`, `GetNamedPipeHandleStateW`, `GetNamedPipeClientProcessId`/`ServerProcessId` (12) | Kernel64 pipe file objects (`NtCreateNamedPipeFile`, `NtFsControlFile` for connect/peek) with overlapped completion; Mojo's Windows channel is a named pipe per process pair. | L (kernel) |
| I/O completion / overlapped | `CreateIoCompletionPort`, `GetQueuedCompletionStatus`/`Ex`, `PostQueuedCompletionStatus`, `SetFileCompletionNotificationModes`, `GetOverlappedResult`, `CancelIo`/`Ex`, `CancelSynchronousIo`, `ReadDirectoryChangesW`, `DeviceIoControl` (11) | Kernel64 completion objects (`NtCreateIoCompletion`/`NtSetIoCompletion`/`NtRemoveIoCompletion`) and overlapped semantics on files, pipes and sockets; `base::MessagePumpForIO` (every Chromium IO thread) is built on IOCP. Called during the complete `--version` run under Wine: `CreateIoCompletionPort` 5×, `GetQueuedCompletionStatus` 19×, `PostQueuedCompletionStatus` 15×, `CreateNamedPipeA` 1×, `SetNamedPipeHandleState` 1×. | L (kernel) |
| Process / thread / job | `OpenProcess`, `OpenThread`, `CreateRemoteThread`, `GetProcessId`, `GetThreadId`, `GetProcessTimes`, `GetThreadTimes`, `Get/SetPriorityClass`, `Get/SetThreadPriorityBoost`, `GetThreadGroupAffinity`, `SetThreadInformation`, `Get/SetProcessInformation`, `Get/SetProcessMitigationPolicy`, `GetProcessHandleCount`, `GetProcessIoCounters`, `QueryFullProcessImageNameW`, `ProcessIdToSessionId`, `QueryProcessCycleTime`, `QueryThreadCycleTime`, `GetThreadContext`, `Wow64GetThreadContext`, `IsWow64Process`, `CheckRemoteDebuggerPresent`, `DebugBreak`, `CreateToolhelp32Snapshot`, `Process32FirstW`/`NextW`, `K32EnumProcessModules`, `K32GetModuleInformation`, `K32GetModuleBaseNameW`, `K32GetPerformanceInfo`, `K32GetProcessMemoryInfo`, `K32QueryWorkingSetEx`, `ReadProcessMemory`, `WriteProcessMemory`, `VirtualProtectEx`, `VirtualQueryEx`, `VirtualFreeEx`, `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute`, `DeleteProcThreadAttributeList`, `CreateJobObjectW`, `AssignProcessToJobObject`, `SetInformationJobObject`, `QueryInformationJobObject`, `TerminateJobObject`, `RegisterApplicationRestart`, `SetProcessShutdownParameters`, `WTSGetActiveConsoleSessionId` (52) | Query functions over the existing `NtQueryInformationProcess`/`NtOpenProcess` (M); handle-inheritance attribute lists are the way Chromium passes pipes to children (M); job objects are a new kernel object (L); mitigation policies can honestly report "not enabled" (S). | M–L |
| Files, volumes, links | `FindFirstFileExA`/`W`, `GetFileInformationByHandle`/`Ex`, `SetFileInformationByHandle`, `GetFileAttributesExW`, `SetFileAttributesW`, `GetFileTime`, `SetFileTime`, `GetFinalPathNameByHandleW`, `GetLongPathNameW`, `GetShortPathNameW`, `GetDriveTypeW`, `GetDiskFreeSpaceA`/`W`/`ExW`, `GetVolumeInformationW`, `GetVolumePathNameW`, `CreateHardLinkW`, `CreateSymbolicLinkW`, `ReplaceFileW`, `ReOpenFile`, `LockFile`/`Ex`, `UnlockFile`/`Ex`, `GetTempFileNameA`, `NeedCurrentDirectoryForExePathW`, `AreFileApisANSI`, `GetPrivateProfileStringW`, `ExpandEnvironmentStringsA`/`W` (31) | Own over the existing file syscalls (`FindFirstFileW` exists; the `Ex` forms add info levels); links on FAT are explicit failures (`ERROR_NOT_SUPPORTED`); byte-range locks need a kernel lock table (M). `GetFileAttributesExW` was called 57× during the complete `--version` run under Wine. | M |
| Resources | `FindResourceA`/`W`, `LoadResource`, `LockResource`, `SizeofResource`, `EnumResourceNamesW` (6) | Own PE resource-directory walker over the mapped `.rsrc` (the loader already maps it). Called during the complete `--version` run under Wine (`FindResourceW` 10×, `LoadResource` 10×, `SizeofResource` 4×). | S |
| Console | `AllocConsole`, `AttachConsole`, `GetConsoleScreenBufferInfo`, `SetConsoleTextAttribute`, `SetConsoleCursorInfo`/`Position`, `GetConsoleCursorInfo`, `SetConsoleTitleW`, `FillConsoleOutputAttribute`/`CharacterW`, `ReadConsoleW`, `ReadConsoleInputW`, `WriteConsoleInputW`, `GetNumberOfConsoleInputEvents`, `SetConsoleCtrlHandler`, `GetErrorMode` (16) | Own over the serial console object (an 80×25 model is enough for `GetConsoleScreenBufferInfo`; `SetConsoleCtrlHandler` was called 5× during the complete `--version` run under Wine). | S–M |
| Heap / memory info | `HeapCompact`, `HeapLock`, `HeapUnlock`, `HeapWalk`, `HeapSetInformation`, `HeapQueryInformation`, `GetProcessHeaps`, `GlobalLock`/`Unlock`/`Size`, `DiscardVirtualMemory`, `PrefetchVirtualMemory`, `VirtualLock`/`Unlock`, `GetLogicalProcessorInformation`/`Ex`, `GetActiveProcessorCount`, `GetMaximumProcessorCount`/`GroupCount`, `GetCurrentProcessorNumber` (20) | Own; the processor-topology functions describe one processor honestly. | S–M |
| Synchronisation / threads | `InitOnceBeginInitialize`, `InitOnceComplete`, `CreateWaitableTimerExW`, `SetWaitableTimer`, `RegisterWaitForSingleObject`, `UnregisterWait`/`Ex`, `QueueUserWorkItem`, `FreeLibraryAndExitThread`, `IsThreadAFiber` (+ fibers: `ConvertThreadToFiberEx`, `ConvertFiberToThread`, `CreateFiberEx`, `DeleteFiber`, `SwitchToFiber` in chrome.dll) (15) | Own; waitable timers and wait registrations need a kernel timer object or a thread-pool thread; `InitOnce*` ports from `src/m98_initonce.c`. | M |
| Time zone / version / packaging | `GetDynamicTimeZoneInformation`, `SystemTimeToTzSpecificLocalTime`, `TzSpecificLocalTimeToSystemTime`, `VerSetConditionMask`, `VerifyVersionInfoW`, `GetProductInfo`, `GetCurrentPackageFullName`, `GetPackageFamilyName`, `GetPackagePathByFullName`, `GetPackagesByPackageFamily`, `GetComputerNameExW`, `GetSystemPowerStatus`, `PowerCreateRequest`/`SetRequest`/`ClearRequest`, `SetDefaultDllDirectories`, `GetModuleHandleExA`/`W`, `GetHandleInformation`, `SetHandleInformation`, `FormatMessageA`/`W` (22) | Own; the packaging functions return `APPMODEL_ERROR_NO_PACKAGE` (the honest answer for a non-packaged process, which Chromium checks first). `VerifyVersionInfoW`/`GetProductInfo`/`GetModuleHandleExW` were called under Wine. | S–M |
| Serial ports | `ClearCommError`, `EscapeCommFunction`, `GetCommModemStatus`, `GetCommState`, `PurgeComm`, `SetCommState`, `SetCommTimeouts` (7) | Own explicit failures (`ERROR_INVALID_HANDLE` unless a COM device exists). | S |

## 11. Loader features the images need, against Kernel64 today

All 63 measured images: PE32+, `DYNAMIC_BASE`, `NX_COMPAT`, `HIGH_ENTROPY_VA`, `GUARD_CF`, a load-config directory, a
security cookie, base relocations, an exception directory; no bound imports, no CLR header, no dependent-load flags.
Per-product counts:

| feature | electron | vscodium | chromium |
|---|---:|---:|---:|
| delay_load_dir | 1/7 | 20/39 | 5/17 |
| tls_dir | 7/7 | 24/39 | 15/17 |
| exception_dir | 7/7 | 39/39 | 17/17 |
| guard_cf | 7/7 | 39/39 | 17/17 |
| high_entropy_va | 7/7 | 39/39 | 17/17 |
| dynamic_base | 7/7 | 39/39 | 17/17 |
| nx_compat | 7/7 | 39/39 | 17/17 |
| large_image | 1/7 | 1/39 | 1/17 |
| clr_header | 0/7 | 0/39 | 0/17 |
| resources | 6/7 | 38/39 | 15/17 |
| bound_imports | 0/7 | 0/39 | 0/17 |
| authenticode | 2/7 | 10/39 | 1/17 |
| cet_compat | 2/7 | 11/39 | 11/17 |
| relocations | 7/7 | 39/39 | 17/17 |
| load_config | 7/7 | 39/39 | 17/17 |
| security_cookie | 7/7 | 39/39 | 17/17 |
| ordinal_imports | 1/7 | 3/39 | 2/17 |
| tls_callbacks_total | 7 | 20 | 55 |
| unwind_entries_total | 546318 | 717845 | 738342 |
| max_size_of_image | 247459840 | 223600640 | 336244736 |
| max_stack_reserve | 8388608 | 8388608 | 8388608 |
| max_sections | 15 | 14 | 14 |
| os_versions | 10.0, 6.0 | 10.0, 6.0 | 10.0 |
| dependent_load_flags | none | none | none |
| guard_flags_seen | cf_export_suppression_info_present, cf_function_table_present, cf_instrumented, cf_longjump_table_present, delayload_iat_in_its_own_section, eh_continuation_table_present, protect_delayload_iat | cf_export_suppression_info_present, cf_function_table_present, cf_instrumented, cf_longjump_table_present, delayload_iat_in_its_own_section, eh_continuation_table_present, protect_delayload_iat | cf_export_suppression_info_present, cf_function_table_present, cf_instrumented, cf_longjump_table_present, delayload_iat_in_its_own_section, eh_continuation_table_present, protect_delayload_iat |
| large images | electron.exe | VSCodium.exe | chrome.dll |

| image | SizeOfImage | sections | image base | stack reserve | TLS (callbacks) | unwind entries | guard flags | CFG functions | delay-load DLLs | resources | CET | signed | reloc dir bytes |
|---|---:|---:|---|---:|---|---:|---|---:|---:|---|---|---|---:|
| electron/electron.exe | 236.0 MiB | 15 | 0x140000000 | 8.0 MiB | yes (6) | 465,616 | 0x10500 | 207,090 | 48 | 0.1 MiB | False | False | 1,226,016 |
| vscodium/VSCodium.exe | 213.2 MiB | 14 | 0x140000000 | 8.0 MiB | yes (7) | 452,551 | 0x10500 | 192,173 | 47 | 0.2 MiB | False | False | 1,158,256 |
| chromium/chrome.dll | 320.7 MiB | 14 | 0x180000000 | 1.0 MiB | yes (6) | 617,442 | 0x10500 | 271,827 | 55 | 0.1 MiB | True | False | 2,056,472 |
| chromium/chrome.exe | 3.1 MiB | 12 | 0x140000000 | 8.0 MiB | yes (6) | 5,840 | 0x10500 | 1,671 | 10 | 0.2 MiB | True | False | 9,936 |
| chromium/chrome_elf.dll | 1.6 MiB | 13 | 0x180000000 | 1.0 MiB | yes (6) | 3,075 | 0x10500 | 782 | 5 | 0.0 MiB | True | False | 6,672 |

| # | feature | evidence in the images | Kernel64 / ntdll today (SOURCE) | work |
|---|---|---|---|---|
| L1 | **Write the IAT of images whose import table lives in a read-only section** | MSVC-linked images keep the IAT in `.rdata` (0x40000040): verified for `electron.exe` (IAT RVA 0xe26c3b0), `VSCodium.exe` (0xcb3ceb0), `chrome.dll` (0x13416228), `chrome.exe` (0x285468) and `chrome_elf.dll` (0x15efd0). The mingw-built test images put it in a writable `.idata` (0xc0000040), which is why this never surfaced. | `import_cb` writes each resolved address with `uwrite64` (ldr.c:327) → `copy_to_user` → `user_page(write=1)` → `user_fault_in`, which rejects writes to a `PAGE_READONLY` VAD (vad.c:359: only `READWRITE`/`WRITECOPY`/`EXECUTE_READWRITE`/`EXECUTE_WRITECOPY` may be written) → `STATUS_ACCESS_VIOLATION` → the image fails to link. Relocations already bypass this by writing through the physical mapping (ldr.c:236-245). | **Blocker for every MSVC image, independent of API coverage.** Write the IAT the way relocations are written (physical page via `vm_lookup`), or map the image's sections writable until linking is done and re-protect afterwards, as Windows does. S. |
| L2 | Large images and their memory | `SizeOfImage` 236 MiB (`electron.exe`), 213 MiB (`VSCodium.exe`), 321 MiB (`chrome.dll`); `.text` alone 192 MB in electron.exe | `map_module` allocates and copies every page of every section (ldr.c:207-217) while the whole `WIN64.IMG` archive stays resident as the initrd (main.c:25-26, `fs_load_archive`) — at least 2× the image in RAM before the heap; the standalone runner boots with `-m 256` (run_k64_standalone.py:77); the archive format caps entries at 4096 and paths at 119 bytes (fs.c:175,183; build.py:190) | Boot with ≥ 2 GiB for Electron, ≥ 3 GiB for chrome.dll + renderer; better, a file-backed image mapping that pages `.text` in on demand and keeps one copy (the initrd bytes) — L. A disk image (FAT) instead of the initrd for the application tree — M. |
| L3 | DLL search order and full paths | `electron.exe` delay-loads `ffmpeg.dll` from its own directory; `chrome.exe` loads `chrome.dll` with an absolute path built next to the executable; VSCodium loads 24 `.node` addons from `resources/app/...`; `SetDefaultDllDirectories`/`LOAD_LIBRARY_SEARCH_*` are used by all three | `locate_file` searches only `\SHZ\SYS64\` and the root (ldr.c:124-144); `base_name` discards the directory part of any name (ldr.c:98-114); `LoadLibraryExW` ignores its flags (k32_mem.c:137-144); the module name buffer is 47 characters and the path buffer 127 (ldr.c:18-19) — `resources/app/node_modules.asar.unpacked/@vscode/os-proxy-resolver-win32-x64-msvc/os_proxy_resolver.node` is 105 characters before any prefix | Application directory first, then absolute paths, then the system directory; longer name/path buffers. S–M. |
| L4 | Delay-load imports | 1/7, 20/39, 5/17 images; electron.exe defers 747 imports over 52 delay-import descriptors (`ffmpeg.dll`, 44 system DLLs, 7 API-set contracts); the CRT helper is inside the image and imports `LoadLibraryExA`, `GetProcAddress`, `VirtualProtect` (all exported); the delay IAT is in `.data` (writable); guard flag `protect_delayload_iat` is **not** set on the three main images (`GuardFlags` 0x10500) | The loader ignores the delay-import directory, which is correct: nothing to do at load time. `GetProcAddress` by ordinal must be right (section 7) and `LoadLibraryExA` must find the DLL (L3). | none beyond L3 and section 7 |
| L5 | TLS directory and callbacks | every image; 6 callbacks in electron.exe, 7 in VSCodium.exe, 6 in chrome.dll; ~2 KB of TLS data each | Static TLS is implemented: index assignment and validation at link (ldr.c:339-363), per-thread blocks built at thread creation (ldr.c:508-534, proc.c:167), callbacks run by ntdll (ntdll_main.c:319-330). Gap: a DLL loaded at run time gets a new `tls_index` (link_module) but the TLS arrays of threads that already exist are not grown — Windows grows them (`LdrpHandleTlsData`). | Needed for run-time-loaded DLLs with `.tls`: VSCodium's addons (24 of 39 images have a TLS directory) and any Shizuku DLL that gains static TLS; not needed for electron.exe itself. M. |
| L6 | Exception directory / x64 unwind | every image; 465,616 `RUNTIME_FUNCTION` entries in electron.exe, 617,442 in chrome.dll; V8 registers JIT unwind data through `RtlAddFunctionTable`/`RtlDeleteFunctionTable`, imported from **kernel32** by electron.exe and chrome.dll | Loader needs nothing; ntdll exports `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `RtlUnwindEx`, `RtlAddFunctionTable`, `RtlDeleteFunctionTable`, `RtlPcToFileHeader`, `RtlCaptureContext`, `RtlRestoreContext`, `KiUserExceptionDispatcher`; kernel32 forwards seven of them (build.py:101) but not `RtlAddFunctionTable`/`RtlDeleteFunctionTable`/`RtlCaptureStackBackTrace` | Add the two forwarders and `RtlCaptureStackBackTrace` (S). Verify `RtlLookupFunctionEntry` is a binary search and that dynamic tables are consulted (not measured here). |
| L7 | Control-flow guard / load config | `GuardFlags` 0x10500 (`cf_instrumented`, `cf_function_table_present`, `cf_longjump_table_present`) on the main images, 207,090 guarded functions in electron.exe; `eh_continuation_table_present`, `protect_delayload_iat` and `delayload_iat_in_its_own_section` appear only on the Microsoft-built DLLs (`d3dcompiler_47`, `dxil`, `msalruntime`, ConPTY) | The loader neither reads nor rejects the load-config directory, so images keep their compiler-supplied no-op `__guard_check_icall_fptr`. Correct; CFG enforcement is an OS opt-in. | none; keep it that way |
| L8 | High-entropy VA, image bases, relocation volume | exe base 0x140000000, every DLL prefers 0x180000000 (so every second DLL relocates); reloc directory 1,226,016 bytes in electron.exe, 2,056,472 in chrome.dll (`DIR64` entries only) | `USER_TOP` 0x7ffffffef000 (k64.h:20) covers both; `pe_walk_relocs` accepts `ABSOLUTE`/`HIGHLOW`/`DIR64` (pe_parse.c); relocation is per-entry `vm_lookup` + write (ldr.c:236-245) | Works; ~250k entries per large image cost time under TCG but no new feature. |
| L9 | Resources | 6/7, 38/39, 15/17 images; 99 KB in electron.exe (manifest, version, icons) | `.rsrc` is mapped like any section; no resource API in kernel32 (`FindResourceW`, `LoadResource`, `LockResource`, `SizeofResource`, `EnumResourceNamesW` all imported at load time by electron.exe) | Own resource walker (S). |
| L10 | CLR header | none among the AMD64 images (the PSReadLine assemblies are PE32/i386 and belong to PowerShell) | rejected with `PE_E_CLR` (pe_parse.c:97) | none |
| L11 | Authenticode / checksum | 2/7, 10/39, 1/17 images signed (the Microsoft-built ones); electron.exe/chrome.dll unsigned with checksum 0 | ignored | none |
| L12 | CET shadow stack marker | 2/7, 11/39, 11/17 images carry `IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT` | no shadow stacks in Kernel64 | none (opt-in) |
| L13 | Ordinal imports | 1/7, 3/39, 2/17 images; 18 ordinals into 9 DLLs (section 7) | `pe_walk_imports` passes ordinals; export lookup by ordinal is implemented (pe_find_export); Shizuku exports are not numbered like Windows' | pin ordinals in `build.py` (S) |
| L14 | GUI subsystem and std handles | `electron.exe`, `VSCodium.exe`, `chrome.exe` are subsystem 2 (GUI); `--version` prints through the CRT to the process' standard output handle | `ldr_create_process` gives every process std handles 4/8/12 on the serial console object (ldr.c:626-633) regardless of subsystem | none; the M2 output reaches the serial log |
| L15 | Loader database limits | electron.exe alone reaches 7 load-time + up to 48 delay-loaded system DLLs; VSCodium adds 24 addons | `publish_all` publishes at most 128 modules per call (ldr.c:467), `MAX_DEPTH` 24 (ldr.c:14), `WIN64_MAX_APPS` 64 in the self-test harness | adequate for M1–M4; raise when Chromium's multi-process set is loaded |
| L16 | System information the images read at start-up | `NumberOfProcessors`, physical memory, OS version | PEB reports 10.0 build 22631 and one processor (ldr.c:652-656); `NtQuerySystemInformation` class 0 reports 8192 physical pages = 32 MiB (sysx.c:341), which `GlobalMemoryStatusEx` feeds to Chromium's memory heuristics | report the real page count (S) |

## 12. Phased plan with measurable milestones

Each milestone has a static gate (this tool, runnable in CI without QEMU) and a guest gate (a run under
`shizukudos/tests/run_k64_standalone.py`-style harness, QEMU TCG, serial log as evidence). Effort classes as in §2.
Order matters: L1 is first because nothing else can be observed until an MSVC image links.

### Phase 0 — harness (prerequisite for every guest gate) — M

* An "application profile" for the standalone runner: pack an application tree under `\APPS\<NAME>\` (a FAT disk image
  rather than the initrd once the tree exceeds a few hundred MB — L2), start `\APPS\ELECTRON\ELECTRON.EXE <args>` from
  `kmain` after the self-tests (the `win64_run_others` pattern in tests.c:154-200 already runs arbitrary `\SHZ\TESTS\T_*.EXE`
  with a timeout and reports exit code and fault), boot with `--memory 2048`, and copy the process' console output to the
  serial log (already the case through the console object).
* CI static gate: `import_coverage.py electron=<tree> --summary-dir …` and assert
  `load_closure["electron.exe"]["system_dlls"][*]["unresolved"] == 0` once M1 is reached, plus
  `apiset_unmapped` and `ordinal-unpinned` counts that must not grow.

### Phase 1 — **M1: every load-time import of electron.exe resolves** — kernel32 track + loader team

Static gate: `coverage/electron.json` → `load_closure.electron.exe.system_dlls`: seven entries, `have_dll` true and
`unresolved` 0 for each (today 297 across kernel32 227, winmm 28, crypt32 28, ws2_32 11, ntdll 2, dwrite 1). The same
gate for `VSCodium.exe` is satisfied by the same work (identical breakdown; its kernel32 names differ from electron.exe's
only in `IsThreadAFiber`/`lstrcmpiW`). For Chromium: `chrome.exe`+`chrome_elf.dll` 100 → 0 (all kernel32), and
`chrome.dll` 287 → 0 (its kernel32 set has the 25 names listed in §3 that electron.exe lacks, e.g. `FoldStringW`,
`LCMapStringEx`, the volume enumeration functions and `Module32FirstW`/`NextW`).
Guest gate: `ldr_create_process` returns `STATUS_SUCCESS` for `\APPS\ELECTRON\ELECTRON.EXE`, the serial log contains no
`K64 ldr: … imports … ->` line, and the first user-mode instruction of ntdll's `ShzProcessStart` is reached
(a `K64 ldr` "started" line with the PID).

Work items: L1 (S, first), L2 memory (M), L3 search path (S–M), L6 forwarders (S), L13 ordinals (S); kernel32 +227 by
group (§10.1; the explicit-failure and query groups are S–M each, the file-mapping/pipe/IOCP groups can be
explicit-failure *at M1* and real at M3); winmm +28 (S); crypt32 new (M); ws2_32 +11 (M); ntdll +2 (S); dwrite new (S at
M1). Realistic total: L (weeks), dominated by kernel32 breadth.

### Phase 2 — **M2: `electron.exe --version` exits 0 with output** — runtime behaviour

Gate: with the Phase 0 harness, running `ELECTRON.EXE --version` produces a line containing `44.4.5` (Electron prints
the content of its `version` file; under Wine it printed `v44.4.5`) on the serial log and the process exit code is 0, within
the harness timeout (60 s in tests.c; raise for TCG). Secondary: no `K64` fault line, all pages returned after exit
(the existing evidence slot 22 pattern).

What runs before the print: the static CRT (`_initterm`, TLS callbacks, security cookie), C++ static initialisers of a
236 MiB image, `wWinMain` → Electron's Windows main (`base::CommandLine`, `SetDefaultDllDirectories`,
`SetProcessMitigationPolicy`, sandbox broker set-up) → `content::ContentMain` → `ElectronMainDelegate::BasicStartupComplete`
which handles `--version`. The exact set of system calls on that path is not knowable statically; section 9 shows the
135 imported functions Wine observed electron.exe calling on this host during a complete `--version` run, of which
**43 are unresolved today** (42 kernel32 + `DWriteCreateFactory`) — start there, then iterate on the guest: run, read
the first unimplemented call or fault in the serial log, implement,
repeat. Explicit-failure implementations are acceptable at M2 only where Chromium checks the result (it does for
`GetProcessMitigationPolicy`, `GetLogicalProcessorInformationEx`, `GetProductInfo`, `GetPackageFamilyName`); anything on
the print path itself (console/file output, heap, TLS, locale queries by the CRT) must work. Effort: M–L of iteration.

### Phase 3 — **M3: headless/`--disable-gpu` page load of a local file** — kernel objects + DWrite subset

Gate (Electron): an application directory `\APPS\M3\` with `package.json` + `main.js` that creates a hidden
`BrowserWindow`, loads `file:///…/index.html` (`<title>M3</title>`), and on `did-finish-load` prints
`M3 <title>` via `webContents.executeJavaScript('document.title')` to stdout and calls `app.exit(0)`. Pass = the serial
log contains `M3 M3` and exit code 0. Gate (Chromium): `chrome.exe --headless=new --disable-gpu --no-sandbox
--dump-dom file:///…/index.html` writes the DOM containing `<title>M3</title>` to stdout, exit 0.

Recommended first configuration: `--no-sandbox --disable-gpu --in-process-gpu --single-process
--enable-features=NetworkServiceInProcess` to stay in one process; Electron documents `--single-process` as
unsupported/experimental, so treat it as a stepping stone and expect to need the multi-process path.
Needed beyond M2: file mapping (L, kernel), named pipes and IOCP (L, kernel; Mojo + `MessagePumpForIO`),
`CreateProcessW` with handle inheritance via `UpdateProcThreadAttribute` and the same image launched as
`--type=renderer`/`gpu-process`/`utility` (M), job objects (L, can be explicit-failure with `--no-sandbox`),
`iphlpapi` (M), the DWrite factory subset (L–XL — the font path has no fallback, see §6.2), `crypt32` in its M3 form
(M), `winhttp` proxy answers (S), the resource API (S), and enough of `user32`/`gdi32` for the software compositor's
off-screen surfaces (GUI track). This is the largest phase: XL overall, with the kernel objects and DWrite on the critical
path.

### Phase 4 — **M4: a window on the Kernel64 framebuffer** — GUI track + DWrite

Gate: `BrowserWindow({show: true, width: 640, height: 480})` loading a page whose `<body>` is solid `#ff0000`; the
host-side framebuffer capture of the GUI test harness (the pixel verification used by the GUI track's existing tests)
shows ≥ 90 % `#ff0000` pixels inside the window's client rectangle within 60 s of process start, and the process stays
alive for a further 10 s without a fault.

Needed beyond M3: the remaining `user32`/`gdi32` names electron.exe delay-loads (110 user32 and 40 gdi32 on
`integ2-dryrun` today), the software output path (`CreateDIBSection`, `StretchDIBits`/`SetDIBitsToDevice`, `BitBlt`,
window DCs), text through the DWrite subset, `dwmapi`/`uxtheme`/`imm32`/`comctl32`/`shcore` answers (S each), input via
window messages, and a message pump that survives `MsgWaitForMultipleObjectsEx` (present on the GUI branch). L on top of M3.

## 13. What could not be measured, and caveats

* No guest run of any of the three products exists; nothing in this document is `GUEST_RUN`. The container has no KVM,
  so a run would be TCG-only and the Phase 0 harness does not exist yet.
* Static import tables say which names must resolve, not which are called, in which order, or with which arguments;
  the Wine trace in §9 is the only call-level evidence and was produced on Linux with Wine's own DLLs, so code paths
  that depend on the reported OS/environment can differ on Kernel64.
* Coverage counts export names only. A provided function may still misbehave; the per-module test suites
  (`shizukudos/win64/tests/t_u_*.c`) are the behavioural evidence, and none of them covers the Electron call patterns.
* The Chromium snapshot is a developer build (`interactive_ui_tests.exe`, unsigned images, checksum 0); release
  builds add code signing but the import sets are the same class.
* `user32`/`gdi32` numbers for the GUI track come from a regex over that branch's sources, not from a build of it.
* The `.node` addons and helper executables were counted as part of VSCodium because the editor loads or spawns
  them; whether a given feature (terminal, search, authentication) needs them is a product decision, not a measurement.
