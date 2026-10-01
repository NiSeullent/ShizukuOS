# Zetscape for Windows 98 SE

Zetscape is the requested standalone, small native browser host. It replaces
the direct Chromium full-source-build task. Legcord, current LibreOffice,
Steam, original Windows 98 IO.SYS UEFI/GOP work and IE's real WebKit integration
remain separate required work.

The host supplies native address, navigation, history, resize, focus and status
controls. It requires the genuine shared WebCore/JavaScriptCore provider used
by the independent IE project. The pinned ABI is copied byte-for-byte from
commit `dd93262508ecec2969d3267b9d6d831d66fcd489`; its BSD-2-Clause notice is
in `upstream/LICENSE`. Zetscape-owned host/extension sources are GPL-2.0-only,
under the repository's `LICENSE`. Fixture sources carry their MIT notices.

## Build and installation contract

From the repository root:

```text
python3 -B apps/zetscape/build.py --syntax-only
python3 -B apps/zetscape/build.py --output build/zetscape-private-new
```

The first command uses the real x86 Windows compiler and creates no object or
application. The second freezes the selected source bytes and produces a
native `ZETSCAPE.EXE`, exact compiler dependency inventory and PE/import receipt
in a new private directory. It preserves the unchanged 20 GiB disk reserve,
256 MiB start margin, 8 MiB output allowance, 45 CPU-second compiler limit,
2 MiB per-file compiler limit and disabled core dumps. It starts no browser,
server or guest, changes no client configuration and downloads nothing.
Compiler headers are pinned before/after compilation. This is not complete
compiler-selected startup/archive source closure or native execution proof.

The actual shared provider must be installed adjacent to the executable as
`ZETWEB.DLL`, exporting `IEWebKitGetEngineV1`. This is the deployment filename
for the same real engine used by IE's `iewebkit-engine.dll`; receipts must bind
the actual corresponding provider bytes. No such provider has been built yet.
Missing/incomplete providers leave the browser controls disabled and show an
installation error. There is no fallback rendering path.

The normal launch targets exact native Windows 98 SE 4.10.2222 and x86. It
allows a real software renderer for general 98SE. `ZETSCAPE.EXE --shizuku`
requires the optional extension's initialized hardware-device/compositor/WebGL
observations and rejects a software flag or missing device/driver identity.
The switch selects a requirement; it does not detect the installed edition or
independently establish acceleration. Shizuku's installer/driver integration,
ongoing device-loss handling and actual GPU evidence are still missing.

## Lifetime and navigation

Only the outer application loop invokes provider entrypoints. Window messages
and borrowed engine callbacks queue work; callbacks copy their exact URL,
method and POST bytes. Nested message loops can request a close without
destroying a view or unloading a DLL still on the stack. Cleanup occurs after
outer dispatch and queued service return; the provider must quiesce all work
when `destroy` returns. Real history is optional and retains engine-owned
document/POST state with a fresh navigation ID. The host never replaces it
with replaying old URL strings.

The current copied-POST interface accepts at most 16 MiB per request, 32 MiB
queued bytes and 16 pending actions. A complete browser needs a real streaming
upload path to handle larger bodies without copying them into this host.
Native ANSI address/title controls convert to/from UTF-8; page text, font
coverage and Unicode rendering remain the real engine's responsibility.
The engine owns canonical URLs, origins, cookies, TLS and subresources.
Address-bar text does not certify an origin or connection security.

## Actual state and acceptance

The current native host build after lifetime fixes is 77,872 bytes, i386 PE32
GUI with OS/subsystem 4.0. All 77 normal/delay import rows matched the retained
Win98 media export baseline. Its receipt is
`build/zetscape-83bd/native-host-v4/receipt.json`; the earlier 76,803-byte
artifact/receipt remain historical. That size excludes the renderer, fonts, TLS, ICU and
all other required deployment files. A complete Zetscape size/memory/startup
comparison with Chromium has not been measured.

The genuine shared engine currently has WTF/allocator/ICU/runtime artifacts,
an incomplete JSCOnly build and no WebCore view/provider DLL. Its actual
Win98 trial displayed abnormal termination in `WTFNAT.EXE`; closed-handle
phase/abort diagnostics have been built with the genuine WTF and allocator
archives. The next native trial must actually reach and launch them before
their runtime can be assessed. A later boot attempt reached the GOP driver's
initialization but showed no desktop and produced none of the selected logs;
it does not further localize the earlier engine failure.
The current C_LOOP/JIT_OFF/WASM_OFF bring-up configuration cannot satisfy
the full modern-web target. See `tools/iewebkit_port/core_shared_engine_README.md`.

The separate `tests/` payload performs actual DOM/layout/ES module/Promise/
Unicode/Canvas/SVG/WebGL/input assertions when executed by the real provider.
`fixtures/modern_web_acceptance.json` identifies required full-target gaps,
native evidence, network/security, WPT/test262 and GPU acceptance. Source
syntax controls do not execute the page. A subset result cannot certify all
modern websites. General 98SE native browsing, Shizuku hardware acceleration
and full modern-web coverage remain unverified.

The GPU extension reports device/driver identity and frame counters only.
Acceptance additionally requires real initialized driver provenance, command
submission/completion, rendering readback and native presentation tied to the
same process, page and fresh trial. A renderer name, capability bits or GOP
framebuffer copies cannot certify hardware acceleration.
