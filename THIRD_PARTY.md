# Source and license record

The subsequent NTWin32Wrapper9x exception and static-TLS work references ReactOS
revisions [`cae3c053d47024545c773148185319075eae0202`](https://github.com/reactos/reactos/tree/cae3c053d47024545c773148185319075eae0202)
for the earlier handler registry and
[`9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8`](https://github.com/reactos/reactos/tree/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8)
for loader TLS and `RtlpAddVectoredHandler`. Per-file notes are in
[ntwin32/exception/PROVENANCE.md](ntwin32/exception/PROVENANCE.md),
[ntwin32/tls/PROVENANCE.md](ntwin32/tls/PROVENANCE.md) and
[ntwin32/loader/PROVENANCE.md](ntwin32/loader/PROVENANCE.md). Wine was compared
and not copied. One-Core-API `ldrinit.c` at
`9eb3c31de9460c1ccce3f6a10c9c4a704f032514` was not copied.

Project source code and the KernelEx ABI adaptation are distributed under GPL-2.0-only. The Unicode mapping data and adapted Wine algorithms retain their LGPL-2.1-or-later notices; see [Wine license](licenses/Wine-LGPL-2.1.txt). Source versions were pinned on 2026-09-23 and 2026-09-24.

| Project | Version and source | Use here | License |
| --- | --- | --- | --- |
| KernelEx | [`31cdfc3560fc116637ee8ed7be31b12f3aacf5d1`](https://github.com/metaxor/KernelEx/tree/31cdfc3560fc116637ee8ed7be31b12f3aacf5d1) | API library ABI, `core.ini` integration, installed Unicode W-provider table review, historical Wine Unicode table source, and experimental UXTHEME KnownDLL base | GPL-2.0-only for the relevant original `uxtheme.c`; `locale_casemap.c` data and `auxiliary/uxtheme/metric.c` are LGPL-2.1-or-later |
| Wine | [`df15af3652511150490934682202d45af892f887`](https://github.com/wine-mirror/wine/tree/df15af3652511150490934682202d45af892f887) | `CompareStringOrdinal` and `RtlCompareUnicodeStrings` comparison flow; processor-group selection; no-package return behavior; named-locale NLS and threadpool work reviewed without copying | LGPL-2.1-or-later |
| ReactOS | [`9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8`](https://github.com/reactos/reactos/tree/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8) | `RtlInitializeCriticalSectionEx` flag validation adapted for single-CPU Win9x; DEP reporting, named-locale NLS, and work-object lifecycle reviewed without copying | `sdk/lib/rtl/critical.c` and `dll/win32/kernel32/client/dep.c` under GPL-2.0-or-later; per-file notices apply to the reviewed NLS/threadpool sources |
| One-Core API | [`9eb3c31de9460c1ccce3f6a10c9c4a704f032514`](https://github.com/shorthorn-project/One-Core-API-Source/tree/9eb3c31de9460c1ccce3f6a10c9c4a704f032514) | Reference only; no code imported because its XP/2003 NT dependencies require separate porting | Per-file license review required |
| LodePNG | [`ed6fe5825c6a4fbb7f58ab35a4231c7543cd452a`](https://github.com/lvandeve/lodepng/tree/ed6fe5825c6a4fbb7f58ab35a4231c7543cd452a) | PNG decoding inside the experimental COMCTL32 icon provider; local `lodepng.c` is the upstream C-compatible `lodepng.cpp` source with line endings normalized and a renamed extension | zlib-style license retained in [`src/vendor/lodepng/LICENSE`](src/vendor/lodepng/LICENSE) |
| pycdlib | [`1.20.0`](https://github.com/clalancette/pycdlib) | Optional host-side Joliet test CD creation; installed separately, not bundled | LGPL-2.1-only |

## Per-file trace

- `src/kex_abi.h`: minimal 32-bit structures from [KernelEx `common/kexcoresdk.h`](https://github.com/metaxor/KernelEx/blob/31cdfc3560fc116637ee8ed7be31b12f3aacf5d1/common/kexcoresdk.h).
- `src/wine_uppercase.c`: `wine_casemap_upper` generated data copied from [KernelEx `locale_casemap.c`](https://github.com/metaxor/KernelEx/blob/31cdfc3560fc116637ee8ed7be31b12f3aacf5d1/apilibs/kexbases/Kernel32/locale_casemap.c), which carries a Wine LGPL 2.1 notice through its companion [`locale_unicode.h`](https://github.com/metaxor/KernelEx/blob/31cdfc3560fc116637ee8ed7be31b12f3aacf5d1/apilibs/kexbases/Kernel32/locale_unicode.h).
- `src/m98wrap.c`: `m98_CompareStringOrdinal` adapts [Wine `kernelbase/locale.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/locale.c#L4938-L4958) and [Wine `ntdll/locale.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/ntdll/locale.c#L652-L679). CPU group branching adapts [Wine `kernel32/process.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernel32/process.c). Package-identity return codes follow [Wine `kernelbase/version.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/version.c#L1558-L1603). Critical-section validation adapts [ReactOS `sdk/lib/rtl/critical.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/sdk/lib/rtl/critical.c).
- `src/m98wrap.c`: NUMA available-memory and extended topology responses, and the legacy-clock fallback for `GetSystemTimePreciseAsFileTime`, are original Win98-specific adaptations of the [Microsoft NUMA API contracts](https://learn.microsoft.com/en-us/windows/win32/procthread/numa-support) and [time API contract](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime). They do not copy code from Wine or ReactOS; the limitations are listed in `docs/COMPATIBILITY.md`.
- `src/m98wrap.c`: `GetCurrentPackageInfo` and the three process-handle package queries extend the existing no-package behavior. The return code follows [Wine `kernelbase/version.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/version.c#L1558-L1623) and the [Microsoft package API contracts](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackageid); Win98-specific process-handle validation is new code. [`GetPackagePath`](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagepath) takes a package ID rather than a process handle and is intentionally not implemented.
- `src/m98wrap.c`: `GetProcessGroupAffinity`, `GetFirmwareType`, and `GetSystemDEPPolicy` are new Win98-specific implementations of the [Microsoft process-group](https://learn.microsoft.com/en-us/windows/win32/api/processtopologyapi/nf-processtopologyapi-getprocessgroupaffinity), [firmware](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwaretype), and [DEP policy](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getsystemdeppolicy) contracts. Wine's [`GetProcessGroupAffinity`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/process.c#L886-L894) is a stub and was not copied. Wine and ReactOS obtain DEP policy from NT shared data ([Wine](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernel32/process.c#L547-L553), [ReactOS](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/client/dep.c#L16-L24)); the Win98 result is the OS policy `AlwaysOff`.
- `src/m98wrap.c`: the SRW lock state transitions were analyzed against [Wine `dlls/ntdll/sync.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/ntdll/sync.c) and [ReactOS `sdk/lib/rtl/srw.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/sdk/lib/rtl/srw.c). This code is a new Win98-specific atomic implementation using the same public pointer-sized ABI; it does not copy the NT keyed-event or address-wait machinery. The exact limitations and concurrency tests are in `docs/COMPATIBILITY.md` and `tests/smoke.c`.
- `src/m98_initonce.c` and `src/m98_initonce.h`: independently written `InitOnceInitialize`, `InitOnceBeginInitialize`, `InitOnceComplete`, and `InitOnceExecuteOnce` with a shared Win98 interlocked state machine. Pinned [Wine `ntdll/sync.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/ntdll/sync.c), [Wine `kernelbase/sync.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/sync.c), [ReactOS `rtl/runonce.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/sdk/lib/rtl/runonce.c), and [ReactOS InitOnce API tests](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/modules/rostests/apitests/kernel32/InitOnce.c) were read alongside Microsoft contracts and native-host comparisons. NT keyed events were replaced with interlocked publication and yielding Win98 waits; no upstream implementation was copied. New project code is GPL-2.0-only. Shared-state contracts, 192-worker tests, and the invalid-use exception difference are documented in `docs/INITONCE_PORT.md`.
- `src/m98wrap.c`: `InitializeConditionVariable`, `SleepConditionVariableSRW`, `WakeConditionVariable`, and `WakeAllConditionVariable` are independently written for Win98 after analyzing pinned [Wine `dlls/ntdll/sync.c` `RtlSleepConditionVariableSRW` and wake routines](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/ntdll/sync.c#L701-L821) and [ReactOS `sdk/lib/rtl/condvar.c` waiter-list, `InternalSleep`, and `InternalWake`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/sdk/lib/rtl/condvar.c#L259-L523). The original Win98 `CreateEventA`/`SetEvent`/`WaitForSingleObject` primitives replace upstream NT address-wait and keyed-event facilities; no upstream code was copied. ABI, queue semantics, limits, and bounded tests are in `docs/NPP_CONDITION_PORT.md`.
- `src/m98nls_ex.c` and `src/m98nls_ex.h`: independently written named-locale `CompareStringEx` and `LCMapStringEx` adapters after reviewing pinned [Wine `dlls/kernelbase/locale.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/locale.c), [ReactOS `winnls/string/locale.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/winnls/string/locale.c), and pinned KernelEx [`kexbases` locale implementation](https://github.com/metaxor/KernelEx/blob/31cdfc3560fc116637ee8ed7be31b12f3aacf5d1/apilibs/kexbases/Kernel32/locale.c) and [API-table ABI](https://github.com/metaxor/KernelEx/blob/31cdfc3560fc116637ee8ed7be31b12f3aacf5d1/common/kexcoresdk.h). The adapter calls the installed KernelEx Unicode W functions for supported legacy flags; no upstream implementation or NLS data was copied. Its restricted flags, provider selection, and guest-test boundary are in `docs/NLS_EX_PORT.md`.
- `src/m98_threadpool.c` and `src/m98_threadpool.h`: independently written work-object lifecycle and fixed worker pool using native Win98 primitives after reviewing pinned [Wine `ntdll/threadpool.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/ntdll/threadpool.c), [Wine `kernelbase/thread.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/thread.c), [ReactOS `rtl/threadpool.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/sdk/lib/rtl/threadpool.c), and [ReactOS Kernel32 work API front end](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/kernel32_vista/threadpool.c). No upstream code was copied. The four-worker limit, unsupported environments, callback lifetime, and direct-guest verification are in `docs/THREADPOOL_WORK_PORT.md`.
- `src/m98wrap.c`: `GetTimeFormatEx` is an independent Win98 NLS adaptation after reviewing pinned [Wine locale code](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/locale.c) and [ReactOS locale code](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/winnls/string/lcformat.c); see `docs/TIMEFORMAT_PORT.md`. `GetProductInfo` is an independently written desktop compatibility profile after reviewing pinned [Wine version code](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/ntdll/version.c), [ReactOS Kernel32 exports](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/kernel32.spec), and the [Microsoft API contract](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo); see `docs/PRODUCTINFO_PORT.md`. No upstream implementation was copied for either function.
- `src/m98wrap.c`: `GetDateFormatEx` is an independent Win98 NLS adaptation after reviewing pinned [Wine locale code](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/locale.c), [ReactOS locale code](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/winnls/string/lcformat.c), and [Microsoft's date API contract](https://learn.microsoft.com/en-us/windows/win32/api/datetimeapi/nf-datetimeapi-getdateformatex). No upstream code was copied; guest evidence and limits are in `docs/DATEFORMAT_PORT.md`.
- `src/m98wrap.c`: `GetLocaleInfoEx` is an independent Windows 98 NLS bridge after reviewing pinned [Wine locale code](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/locale.c), pinned [ReactOS GetLocaleInfoEx](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/kernel32_vista/GetLocaleInfoEx.c), and [Microsoft's API contract](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getlocaleinfoex). No upstream code was copied; supported data forms and bounded host and Windows 98 guest verification are in `docs/LOCALEINFO_PORT.md`.
- `src/m98wrap.c`: `FindFirstStreamW` is new Win98-specific code for the documented failure on an existing local FAT/FAT32 file. Pinned [Wine stream functions](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/file.c#L1500-L1508) and [ReactOS stream enumeration](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/client/file/find.c#L957-L1151) were reviewed; neither implementation was copied. The precise failure-only scope and guest test boundary are in `docs/FIRSTSTREAM_PORT.md`.
- `src/m98wrap.c`: `GetApplicationRestartSettings`, `RegisterApplicationRestart`, and `UnregisterApplicationRestart` are original Win98 no-restart-service responses after reviewing pinned [Wine Get](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/process.c#L3454-L3468), [Wine Register/Unregister](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernel32/process.c), [ReactOS Vista restart stubs](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/kernel32_vista/vista.c#L1967-L2075), the [ReactOS export list](https://raw.githubusercontent.com/reactos/reactos/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/kernel32.spec), and [Microsoft's query contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getapplicationrestartsettings). No upstream code was copied. They provide the correct unregistered query result and explicit registration failure, not Windows Error Reporting restart behavior; see `docs/NPP_RESTART_PORT.md`.
- `src/m98wrap.c`: `QueryFullProcessImageNameA/W` is new Win98-specific code after reviewing pinned [Wine `kernelbase/debug.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/debug.c#L1730-L1821) and pinned [ReactOS `kernel32_vista/vista.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/kernel32/kernel32_vista/vista.c#L24-L129). Both upstream implementations depend on NT process image queries absent from Win98. No upstream code was copied. This bridge only returns the current process image's DOS path after proving the handle belongs to that process; native NT paths and other processes fail explicitly. The exact behavior and verification are in `docs/NPP_PROCESSPATH_PORT.md`.
- `src/m98advapi.c`: `RegGetValueA/W` are new Win98-specific code using native registry calls. Pinned [Wine `dlls/kernelbase/registry.c` A/W paths](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/kernelbase/registry.c#L1687-L1961) and [ReactOS `dll/win32/advapi32/reg/reg.c` A/W paths](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/advapi32/reg/reg.c#L1727-L1982) were reviewed without copying; the behavior limits are in `docs/ADVAPI_REGGETVALUE_PORT.md`.
- `src/dbghelp_shim.c`: the original Korean Windows 98 SE `IMAGEHLP.DLL` from `WIN98_29.CAB` exports `ImageNtHeader` (file SHA-256 `60b564852ca292d523b48e1152ea61a7f1f169dcb3d4cdf970907efdb4eaee23`). The new `DBGHELP.DLL` bridge resolves that system export for Notepad++'s sole direct DbgHelp import. Wine's [`imagehlp/access.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/imagehlp/access.c) and ReactOS's [`imagehlp/access.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/imagehlp/access.c) were consulted for PE-header handling; no code from either is copied into this bridge.
- `src/dwmapi_shim.c`: the app-local no-compositor result follows Microsoft's [`DwmSetWindowAttribute` contract](https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/nf-dwmapi-dwmsetwindowattribute). Pinned [Wine](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/dwmapi/dwmapi_main.c) and [ReactOS](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/dwmapi/dwmapi_main.c) placeholders were reviewed; no code was copied. This is a Win98-specific failure response, not a compositor.
- `src/bcrypt_shim.c`: the seven Notepad++ direct imports were checked against pinned [Wine `dlls/bcrypt/bcrypt_main.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/bcrypt/bcrypt_main.c), [ReactOS `dll/win32/bcrypt/bcrypt_main.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/bcrypt/bcrypt_main.c), and [Microsoft's CNG contracts](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptcreatehash). The four implemented [algorithm pseudo-handles](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-pseudo-handles) follow Microsoft's published integer values. New portable SHA-256, MD5, and HMAC code follows FIPS 180-4 and RFC 1321/2104; no Wine or ReactOS source code was copied. Unsupported algorithms and properties return explicit failures.
- `src/m98shell.c`: the PIDL-backed `IShellItem`, `SHCreateItemFromParsingName`, and `SHParseDisplayName` design was checked against pinned Wine [`shellitem.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/shell32/shellitem.c) and [`pidl.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/shell32/pidl.c), and ReactOS [`CShellItem.cpp`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/shell32/CShellItem.cpp) and [`wine/pidl.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/shell32/wine/pidl.c). Those LGPL-2.1-or-later sources were consulted, not copied. The implementation uses original Windows 98 Shell interfaces and new project code; limits are recorded in `docs/SHELL_ITEM_PORT_DRAFT.md`.
- `src/m98shell_openfolder.c`: the `cidl == 0` filesystem-item case was checked against pinned Wine [`shlfolder.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/shell32/shlfolder.c) and ReactOS [`shlfolder.cpp`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/shell32/shlfolder.cpp), both LGPL-2.1-or-later. The implementation uses native Windows 98 Explorer `/select` documented by [Microsoft KB Q130510](https://jeffpar.github.io/kbarchive/kb/130/Q130510/), not Wine's private Explorer message. No upstream source was copied.
- `src/uxtheme_shim.c`: no-theme responses, animation fallback, and parent painting were checked against pinned Wine [`draw.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/uxtheme/draw.c) and [`buffer.c`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/uxtheme/buffer.c), and ReactOS [`draw.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/uxtheme/draw.c) and [`buffer.c`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/uxtheme/buffer.c). The upstream files are LGPL-2.1-or-later. No upstream source was copied; this new GPL-2.0-only bridge models the Windows 98 no-theme state and does not provide visual styles.
- `tools/build-uxtheme-known.ps1`: an experimental combined UXTHEME DLL compiles pinned KernelEx [`auxiliary/uxtheme/uxtheme.c`](https://github.com/metaxor/KernelEx/blob/31cdfc3560fc116637ee8ed7be31b12f3aacf5d1/auxiliary/uxtheme/uxtheme.c) (GPL-2.0) and [`metric.c`](https://github.com/metaxor/KernelEx/blob/31cdfc3560fc116637ee8ed7be31b12f3aacf5d1/auxiliary/uxtheme/metric.c) (LGPL-2.1-or-later) alongside new `src/uxtheme_shim.c`. It retains the original export names and adds the pinned Notepad++ imports. The public preview ZIP includes this combined DLL, the corresponding pinned source files and notices.
- `src/uxtheme_sysfont.c`: independent Win98 ANSI-to-Unicode repair of one KernelEx KnownDLL export after reviewing pinned [Wine](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/uxtheme/metric.c) and [ReactOS](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/uxtheme/metric.c) metrics implementations. No upstream source was copied. The combined binary still retains KernelEx LGPL object code; see `docs/UXTHEME_SYSFONT_PORT.md`.
- `docs/VXKEX_SOURCE_AUDIT.md`: VxKex was analyzed as an external reference at a pinned i486 mirror commit. The examined Git tree did not contain a license grant; no VxKex code, binary, or submodule is redistributed here.
- `docs/PUBLIC_KERNELEX_VARIANTS.md`: public KernelEx, Kext, Kex22, Wine, ReactOS, and VxKex materials are inventoried as references for API priorities and implementation review. Forum attachments and modified KernelEx binaries are not bundled, and their redistribution rights are not inferred from their public availability.
- `src/m98_clipboard.c` and `src/m98user.c`: original GPL-2.0-only Win98 clipboard backend after reviewing pinned Wine `dlls/win32u/clipboard.c`, `server/clipboard.c`, and `dlls/user32/tests/clipboard.c`, plus pinned ReactOS `win32ss/user/user32/windows/clipboard.c` and `win32ss/user/ntuser/clipboard.c`. No upstream implementation body is copied. Wine uses server-managed window and clipboard state; the examined ReactOS versions of the three modern entry points are unimplemented. The Win98 implementation uses native window properties, viewer-chain messages and clipboard enumeration; its bounded ownership/lifetime differences are recorded in `docs/CLIPBOARD_PORT.md`.
- `src/m98_comctl_ordinals.c`, `src/m98_icon_choice.c`, and `src/m98_icon_png.c`: original GPL-2.0-only Win98 adapters for two COMCTL32 ordinal routes. The PNG decoder is the separately licensed pinned LodePNG source under `src/vendor/lodepng/`, with its notice intact. Pinned Wine and ReactOS icon paths were reviewed; their implementation bodies were not copied. The tested contract and remaining limits are in `docs/COMCTL_ORDINAL_PORT.md`.
- `integration/core.ini`: copy of KernelEx [`apilibs/core.ini`](https://github.com/metaxor/KernelEx/blob/31cdfc3560fc116637ee8ed7be31b12f3aacf5d1/apilibs/core.ini), its default `contents` extended with the project KERNEL32, Shell, and ADVAPI API libraries, and explicit named-locale, Shell, and ADVAPI routes added in three compatibility profiles. It is a source example, not a replacement for an installed guest's entire configuration.

Wine and ReactOS are not bundled as complete runtimes. Their NT/Unix kernel dependencies are incompatible with direct use in Windows 98. The ISO and installation key supplied for testing remain outside version control.

## Optional modern theme and transport components

- `src/uxtheme_engine*` and the additive `ntth_query_part` are independently
  authored GPL-2.0-only adapters around the existing project painter. Pinned
  Wine and ReactOS UXTHEME contract references are recorded in the native
  source; their implementation bodies were not copied. This opt-in provider
  does not replace the existing KernelEx KnownDLL automatically.
- `src/m98_tls13*` and `tools/build_tls13.py` use official Mbed TLS 4.2.0 with
  bundled TF-PSA-Crypto 1.2.0. Both exact LICENSE files offer Apache-2.0 OR
  GPL-2.0-or-later; this build selects GPL version 2. The upstream archive hash,
  source verification, license hashes and build receipts are kept by the build
  tool. Upstream code remains in ignored `build/tls13/upstream/`; a distributed
  linked binary must include the selected license notices and corresponding
  pinned source/build configuration. See `docs/MODERN_THEME_TLS_APPS.md`.
- `ntwin32/secure_transport/` separately links verified official Mbed TLS
  3.6.7 for its LTS transport and explicit SSPI adapter. The upstream license
  is Apache-2.0 OR GPL-2.0-or-later; this combination selects GPL version 2.
  Its archive identity, original adapter code, compiler-helper notices and
  redistribution requirements are recorded in
  `ntwin32/secure_transport/PROVENANCE.md`. Upstream sources and private test
  certificates remain in ignored build storage. This optional TLS backend is
  an external dependency of that component, separate from the independently
  authored platform sources below.

## Optional Trident script extension

The original `src/m98_trident_script*` embedding and
`src/m98_trident_automation*` adapter use GPL-2.0-only project code. The real
interpreter is [QuickJS 2026-06-04](https://bellard.org/quickjs/), pinned to the
official archive SHA256
`b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a`.
Its MIT license credits Fabrice Bellard and Charlie Gordon; upstream copyright
and license notices remain in the ignored, verified source and build output.
Distributing a linked binary requires including those notices. Platform changes
and original embedding sources remain separate from the pinned upstream input.
This extension does not replace Microsoft's MSHTML implementation or copy it.
`tests/trident_es2026_selected.js` is original semantic-test code based on the
linked public ECMAScript2026 specification; it is not a copied Test262 suite
and does not certify full ECMAScript or browser conformance.

The portability build also selects the mathematical source subset from official
[musl revision c4e1bb3994c14ed5112c894d15a451bf00f0d501](https://git.musl-libc.org/cgit/musl/commit/?id=c4e1bb3994c14ed5112c894d15a451bf00f0d501),
archive SHA256
`b124fa46818a524d373a176b3262a9c26f421d5972073110f3fe51690a9ac4f1`.
Original source copies and COPYRIGHT remain beside the prepared local source;
the umbrella MIT grant and applicable Sun, FreeBSD and Arm per-file notices all
remain required. Local helper names and platform declarations are adapted in
prepared copies, with exact hashes and build recipes recorded separately.
No complete musl runtime or prebuilt musl binary is linked. The original project
formatting adapter is GPL-2.0-only; native basic math uses explicitly audited
installed-system CRT exports. Host math and original Windows CRT results require
separate execution evidence.

## Optional current Wasm execution component

`src/m98_wasm*` and its original build/test adapters are GPL-2.0-only project
code. The selected interpreter uses official WebAssembly Micro Runtime revision
`f5f57c09aee623436f5fb87a90798fdd2cdf39fd`, archive SHA256
`620d40c4c67269f371a46ef4923d398ef96cdf569a7f66e6aab70788e235f907`.
All 2,001 original regular files, the original archive and the complete
Apache-2.0 WITH LLVM-exception license remain in private build storage. The
original exception explicitly discusses GPLv2 combined software; plain
Apache-2.0 compatibility is not assumed. Prepared portability patches and exact
original/prepared hashes remain separate. This work publishes no combined binary.
See `docs/TRIDENT_WASM_RUNTIME.md` for the tested profile and unfinished features.

The selected numeric tests retain official WebAssembly specification sources at
`bc030375d734de845aa2246b783ca6a7ee865eb4` with their original license and notices.
Pinned WABT 1.0.42, archive SHA256
`84895407a6bbb80e918f33b16b2fb2206021c150b6bc9ff6f761263a745ab131`,
is a host-only fixture compiler with its original license retained. Neither
foreign test scripts nor a WABT runtime are linked into the Win98 DLL. Exact
selected tests, exclusions and results are in `docs/TRIDENT_WASM_SPEC_SELECTED.md`.

## Optional Mesa fragment execution component

`src/m98_softpipe_shader*` and the original port/build/test adapters are
GPL-2.0-only project code. The selected genuine TGSI interpreter/build/parser
and scalar helpers use official Mesa 26.2.3, archive SHA256
`1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f`.
The original archive, complete selected source snapshot, MIT and BSL-1.0 license
texts and applicable per-file notices remain in private build storage. Prepared
allocation/binding/scalar portability changes preserve the originals separately.
The pinned enum generator is executed as a build dependency with its exact
command and output retained. No complete Mesa driver is bundled, and the typed
TGSI fragment component does not establish GLES, WebGL or WebGPU support.
See `docs/MESA_SOFTPIPE_PORT_FEASIBILITY.md` and `src/m98_softpipe_HANDOFF.md`.

## Independent platform path

The original CSS token/variable core retains selected WPT raw fixtures and their
full BSD-3-Clause license at revision `5cd8e3fa0a6c4ca11fa565f7c0956802c8e0045d`
under `benchmarks/wpt-css-selected-v1/`. Small project-authored oracle vectors
record exact raw-source hashes; the foreign browser scripts are not executed.
Three original CSSWG Bikeshed references at revision
`f505fd10877a9c915b5d4a4028c2ad83c76d006f` remain under their W3C document license,
with original URIs/status/editor attribution and an accompanying copyright notice
in `benchmarks/css-standards-source-v1/NOTICE.md`. These are reference documents,
not linked implementation code. The original component and bounded MSHTML
consumer are GPL-2.0-only project code; neither constitutes full CSS support.

`tools/build_trident_test262_selected.py` separately obtains selected official
Test262 fixtures from revision `7ab7fafa0003f73fc85c1b95d88094d33f7eb8bd`, pinned
archive SHA256 `1d497a1e7430094a41d06f38db775df4a63db5d587b2a8b08aba6fad5de19585`.
Its BSD license and all selected per-file notices remain unchanged in private
build storage, alongside the complete original archive. This test-only input
is not linked into the native runtime or bundled here. The original GPL-2.0-only
host adapter provides a limited synchronous fixture protocol; its exact scope
and preserved failures are recorded in `docs/TRIDENT_TEST262_SELECTED.md`.

The new `ntwrapper/`, `ntwin32/`, `ntwddm/`, `drivers/pcie/`,
`shizukudos/uefi/`, `shizukudos/uefi32/` and `platform/` sources are independently authored project
code under GPL-2.0-only. The independent build does not link the legacy
KernelEx/Wine/ReactOS/LodePNG providers listed above. Public ABI specifications and
component provenance are recorded in their respective directories. Compiler
headers and external test firmware/tools are build/test dependencies, not
project-authored implementations. Existing third-party notices above continue
to apply to the historical source files and their builds.

The NTWDDM theme painter reviewed One-Core-API
[`dll/win32/uxtheme/draw.c`](https://github.com/shorthorn-project/One-Core-API-Source/blob/9eb3c31de9460c1ccce3f6a10c9c4a704f032514/dll/win32/uxtheme/draw.c)
at `9eb3c31de9460c1ccce3f6a10c9c4a704f032514` (LGPL-2.1-or-later, the Wine/ReactOS
painter in that tree), together with the pinned ReactOS and Wine `draw.c` files
cited above. No line of those files was copied. The software present path
follows the public Vista `D3DKMT` device/context/present contracts without
copying `d3dkmthk.h`. Per-file differences are in
[`ntwddm/PROVENANCE.md`](ntwddm/PROVENANCE.md). This does not change the
historical KernelEx UXTHEME bridge above.

## Native Shizuku GOP display package

`drivers/shizuku_gop/build.py` pins MIT-licensed VMDisp9x at
`d778a911035d414dea9ac852a638a7052c21c400` and the MIT-licensed fixlink
tool at `a2a74447daea3197255f3a4fb5cfb0c5a453dcc8`. The native display
frontend and MiniVDD retain the upstream copyright and license notices.
The GOP descriptor parser and framebuffer backend are original GPL-2.0-only
project code. The combined development ZIP includes complete frozen compiled
sources, the source-adaptation patch, GPL/MIT notices and the linked Open
Watcom runtime's Sybase Open Watcom Public License notice. See
`drivers/shizuku_gop/NOTICE.md` and the exact build receipt for file provenance.
Neither Microsoft's DIBEngine binary nor any Windows disk is redistributed.

## VLC geographical compatibility data

`src/m98_vlc_geo.inc` contains factual GEOID/name/region records extracted
from Wine11.0 [`tools/make_unicode`](https://github.com/wine-mirror/wine/blob/wine-11.0/tools/make_unicode),
SHA256 `f0284d8eee7f213cb5ff1db1264fd90d689fe3a36358451574a0511fa019e637`.
The input retains Alexandre Julliard's copyright and LGPL2.1-or-later notice.
ISO alpha3/numeric facts come from the pinned system iso-codes
`iso_3166-1.json`, SHA256
`f01b812b57fba9f31ff621bf33e7c7570a01964dbeb5be2167e94decf538c89f`.
Only literal factual records are extracted; neither upstream Perl generator
nor downloaded code is executed or incorporated as implementation code.
The exact301-record output and extraction receipt are documented in
`docs/VLC_COMPATIBILITY.md`. `tools/generate_vlc_geo.py` and the bounded
locale parser, Win98 registry/version/NLS adapters are independently written
GPL2.0-only project code. The source and data attribution remain in the table
header; supported lookup fields do not imply full modern geography/NLS support.

## Private modern graphics and Korean font corpus

- `ntwddm/graphics_backend/` links the selected real Mesa 26.2.3 TGSI and
  scalar support sources from a SHA-pinned official archive. Its fresh build
  copies the complete reviewed selected originals, prepared source and
  applicable Mesa MIT, SoftFloat BSD and BSL notices into ignored build storage.
  Original resource/FP/consumer code uses GPL-2.0-only. This is a private rendering
  prerequisite; it does not include a complete GL/Vulkan driver or establish
  DirectX device support. See `docs/DIRECTX_GRAPHICS_CONTINUATION_6970.md`.
- `tools/dwrite_font_corpus.py` obtains unmodified official Noto Sans CJK KR
  font bytes from an immutable notofonts/noto-cjk publisher commit, with exact
  publisher Git blob and local SHA-256 identities. It retains the SIL Open Font
  License 1.1 and publisher README in private ignored build storage. No font is
  installed or registered by the corpus tool. See
  `docs/DIRECTWRITE_FONT_CORPUS_6970.md`.
