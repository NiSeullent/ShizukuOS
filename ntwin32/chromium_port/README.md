# Native browser delay import substrate

`delay_runtime.c` implements bounded lazy resolution of one PE32 delay import
slot with real caller supplied module services. It copies import names into
owned context storage, validates all descriptors and ordinary/delay IAT overlap
before opening any DLL, and retains module references until explicit quiescent
disposal. Failed symbol lookup leaves the mapping unchanged. Failed rollback
retains ownership and prevents further resolutions until cleanup succeeds.
Concurrent lookups share the caller's lock and publish each slot once. With a
recursive native critical section, reentry during a resolver callback fails
explicitly instead of opening or disposing a second reference recursively.
Owned descriptor, IAT and module-handle slots are checked again after every
load/export/close callback. Callback mutation stops publication and releases any
newly opened reference; cleanup refuses to overwrite unexpected caller bytes.
Pointer publication uses a single aligned x86 32-bit store, so linker dispatch
outside the resolver lock cannot observe a partly written function address.
An unaligned mapping is rejected before any callback or write.

This is an additive source port component. It is not yet wired into Chromium's
linker helper, the existing native loader, a browser process, or an NT exception
dispatcher. Existing proven runtime profiles remain unchanged. The caller must
provide a writable mapping with correctly relocated delay linker trampolines,
serialize callbacks, preserve the context, and join all target threads before
disposal. Bound delay state, unload tables, external module handle mutation and
unavailable imports fail explicitly. Notification hooks and delay helper SEH
recovery are not implemented.
The public interface uses C linkage for a C++ browser caller. The builder links
and runs a separate C++ consumer against C compiled objects to verify that ABI.

The interface follows the documented [Microsoft delay helper contract](https://learn.microsoft.com/en-us/cpp/build/reference/understanding-the-helper-function?view=msvc-170)
and [PE32 delay import descriptor layout](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#delay-load-import-tables-image-only).
The original code is licensed under GPL-2.0-only; it contains no copied runtime
implementation or proprietary application bytes.

```text
python3 ntwin32/chromium_port/build_delay.py --out build/chromium-delay-core-NEW
```

The builder freezes source files, runs actual ASan/UBSan host fault and
concurrency controls, validates the two preserved official Chromium roots'
original delay tables in private host mappings, and compiles `CHDLY.EXE` as i486 PE32/Win98 4.10 with
native OEM import gates. It launches no VM or application. The native probe
uses real Kernel32 library references, GetProcAddress, GetTickCount, lstrlenA,
critical sections and two native workers; its fresh log path is
`C:\VXDLAB\CHDLY.LOG`. A separate native VM run, fresh readback and process
exit observation are required before reporting native success. `CHDSUIT.EXE`
is a separate native child supervisor: it creates `CHDLY.EXE`, waits at most
30 seconds and records its real exit in fresh `CHDSUIT.LOG`. Timeout or forced
termination always fails. Its own OS exit remains a separate observation.

`prepare_delay.py --build-receipt RESULT --build-sha SHA256 --out NEW_BUILD`
checks the exact successful compile receipt, frozen/current sources, compilers,
and both binaries before producing a diagnostic input manifest. Its two inputs
and two fresh outputs remain within the existing private `VXDLAB` guard. It
launches no VM and installs no application, driver or global configuration.

On 2026-09-30, preserved official Chromium **157.0.8080.0 x86**, snapshot
1707946, has 116 delayed imports in `chrome.exe` and 39 in `chrome_elf.dll`.
Its independent TLS, load configuration, modern imports, process, sandbox,
graphics, `chrome.dll` size and version contract work remain unresolved.
Resolver fixture success cannot establish application startup or rendering.

The newly requested application targets are [Legcord 1.3.0](https://github.com/Legcord/Legcord/releases/tag/v1.3.0),
the latest release pinned independently from its development branch;
[LibreOffice 26.8.0](https://www.libreoffice.org/download/), currently published
for Windows x86-64 and ARM64; and the current Steam client. Valve's [32-bit
support notice](https://help.steampowered.com/en/faqs/view/49A1-B944-48B8-FF00)
says future client versions require 64-bit Windows. Those architecture and API
requirements need explicit source ports or an actual guest-owned 64-bit
execution bridge; the 32-bit Windows98 loader does not satisfy them by changing
a reported version. No execution of these applications is claimed here.
