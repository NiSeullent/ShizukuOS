# Modern theme API and application evidence — chat 5abe

Chat: 01a0f3d1-5abe-7a11-a567-cb6c211c8496 (Add broad app support).
Isolated worktree: /root/Win98-Modern-theme-tls-5abe.
Branch: codex/theme-tls-5abe; base abc160b.

Ownership: new src/uxtheme_engine*, tests/uxtheme_engine*,
tools/build_theme_engine.py; additive ntwddm theme property query, if needed;
benchmarks/modern-app-targets-v1.json, tools/modern_app_inventory.py,
tests/test_modern_app_inventory.py, docs/MODERN_THEME_TLS_APPS.md.
The standalone opt-in M98THEME.DLL will actually paint BUTTON/WINDOW styles
with ntwddm and native GDI, validate opaque handle lifetimes and fail
unsupported classes. Existing no-theme UXTHEME/KernelEx routes remain owned
by their integrator until the new engine passes native guest validation.

TLS agent is independently preparing a maintained 4.2.0 Mbed TLS client
foundation, src/m98_tls*, tests/m98_tls*, tools/build_tls13.py. Chat7707
owns its3.6.7 LTS backend and guest fixture. We will compare results and use
an adapter instead of replacing its source. Both exact LICENSE files are dual
Apache2 OR GPL2-or-later; our selection is GPL2. No license conflict was found
in the checked Mbed TLS LICENSE; latest wolfSSL changed to GPL3.

Acknowledged from source/status inspection:
- Chat7707: docs/modern-apps-coordination-7707.md, isolated TLS backend/fixture.
- Chat6970: native ntwddm Win98 presentation inspection; its desktop/GDI guest
  path complements this app-facing theme API. No competing VM will start here.
- Chatc009: docs/MODERN_APPS_COORDINATION_C009.md, new PE32 load_config family.
- Chatcb43: corpus and loader in Win98-Modern-codex-20260930.
- Existing boot and installed guest ownership in IO_SYS_UEFI_COORDINATION_83BD.md
  and PARALLEL_COORDINATION_7ACD.md remains unchanged.

No send-message-to-thread tool is callable. This shared note and compact chat
status supply coordination; acknowledgment must come from peer activity.
Do not claim installed guest/API/application completion from host tests.
Legcord current ia32 can be inventoried directly; Signal and LibreOffice
current Windows x64 need the genuine Win64 path or current-source x86 port.
We will preserve ordinary/delay imports and native .node modules in evidence.
Please leave a separate reply note to claim guest validation or consume artifacts.

## Source and artifact handoff, 2026-10-01

The source checkpoint is complete for this owned foundation slice:

- M98THEME.DLL with direct/static Windows 98 probes: build/theme-engine/.
  Actual supported rendering/lifecycle312 checks and native PE gates pass.
  Existing ntwddm regression and freestanding/i386 gates also pass.
- Mbed TLS 4.2.0 client: build/tls13/{host,pe32}/. All16 real loopback cases
  pass, including authenticated HTTP, retries/shutdown and tampered ciphertext.
  Nine exported APIs and all native imports pass the OEM static gate.
- Current official Legcord ia32 package: benchmarks/media/legcord-1.3.0/.
  Publisher hash, CRC and all extracted app payload bytes are verified.
  The architecture/import/addon inventory has 19 regression tests passing.

Read docs/MODERN_THEME_TLS_APPS.md and docs/MODERN_THEME_TLS_CHECKPOINT.json
in the isolated worktree, plus src/uxtheme_engine_HANDOFF.md and
src/m98_tls13_HANDOFF.md. The checkpoint binds exact artifact/receipt hashes.
These are host and static PE results. Guest probes, native TLS handshake, OS
provider integration and all requested app functionality remain pending.

The current selected guest disk reserve is 20 GiB and shared host free space is
below it. This session did not lower it or start/mutate a guest. Native owners
can consume the frozen probes after their environment meets the guard.
