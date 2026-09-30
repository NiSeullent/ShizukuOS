# Combined modern themes, TLS and app checkpoint

This private integration branch is `codex/tls13-7707`, based on `abc160b`.
It contains transport commit `2c5e2a6` and peer theme/client/inventory commit
`a12a4a9`, imported as `9560069`. Existing peer worktrees, runtime/kernel
branches, boot images and running guests were not modified by this integration.
The shared ownership ledger acknowledged by peer 5abe is
`/root/Win98-Modern-boot/docs/modern-apps-coordination-7707.md`.

The user target remains actual persistent themes, current Legcord/Discord,
Signal, current open-source Office suites, broad modern applications and
OS TLS 1.3. This is a reproducible source/build checkpoint. It supplies no
new Windows 98 theme, OS TLS or application functional pass.

## Components available together

| Component | Actual behavior | Integration boundary |
| --- | --- | --- |
| `M98THEME.DLL` | Native GDI plus ntwddm Classic/Modern BUTTON/WINDOW rendering, text, theme handles, query properties and style changes | Opt-in application provider; full shell/control interception, settings persistence, all theme classes and guest checks remain pending |
| `M98TLS13.dll` | Mbed TLS 4.2.0/TF-PSA-Crypto 1.2.0 authenticated TLS 1.3 client | Caller-owned CSPRNG, UTC clock, transport and trust anchors; latest client path for adapter work |
| `M98TLS.dll` / `TLS13PROB.exe` | Maintained Mbed TLS 3.6.7 LTS TLS 1.3 client/server and native ANSI CryptoAPI/UTC bridge | Separate backend and offline guest fixture; no automatic OS provider installation |
| `modern_app_inventory.py` | Publisher-bound application tree, PE/import/delay import/static TLS/native addon evidence | Describes requirements; does not execute or score app compatibility |

The two TLS backends have different RNG/status/clock/lifetime contracts.
`m98_tls13` entropy returns **1** on full success; `ntwst` randomness returns
**0** on full success. Their similarly numbered error values are not a common
ABI. Each requires external serialization, no callback reentry and exclusive
ownership of its linked PSA state. Do not silently cast callbacks, combine
static PSA implementations in one program, or infer concurrent connection
support. Use a reviewed adapter or separately loaded components, then test
the actual application/provider path.

Use [m98_tls13_HANDOFF.md](../src/m98_tls13_HANDOFF.md) for the latest client,
[uxtheme_engine_HANDOFF.md](../src/uxtheme_engine_HANDOFF.md) for theme drawing,
and [secure transport README](../ntwin32/secure_transport/README.md) for the
LTS/native fixture, exact source pin, reproducible build and handoff verifier.
Both selected Mbed TLS license options are GPL version 2; full upstream and
toolchain notices remain required for a later binary distribution. No binary
release or global DLL/provider configuration was performed here.

## Combined-branch verification

Fresh builds in this branch passed 312 theme checks normally and under
ASan/UBSan, three theme PE/import gates, 16 authenticated TLS 1.3 loopback
cases against OpenSSL, the latest TLS client PE/import gate, and 19 application
inventory regression tests. The LTS transport's frozen eleven-case host result,
three PE artifacts, thirteen DLL exports, real x86 relocation entries and eight
staged DOS inputs were independently reverified. Six deliberately modified
handoffs were rejected, including changed EXE/certificate, mismatched nonce
and delayed exit observation.

The inherited ntwddm regression passed 308,637 core checks, 88 theme checks,
53 presentation checks, and both native and i386 freestanding symbol checks.
These are host/static checks. No new guest/application capability follows.

The exact **new combined-branch** receipts and artifacts are bound by
[secure-transport-checkpoint-7707.json](../benchmarks/secure-transport-checkpoint-7707.json).
The imported `MODERN_THEME_TLS_CHECKPOINT.json` retains the original peer
branch's evidence; its relative receipt hashes should be resolved in that
peer's recorded worktree rather than treated as the new build's receipts.

## Actual acceptance still required

The exact current package pins and meaningful checks are in
[MODERN_APP_REQUIREMENTS_7707.md](MODERN_APP_REQUIREMENTS_7707.md) and its
[machine-readable contract](../benchmarks/modern-app-requirements-7707.json).
ONLYOFFICE remains required alongside LibreOffice. Current source ports must
retain upstream version/patch/library/architecture identity.

Guest owners must first test native DLL loading/relocation, actual entropy,
clock, CRT shutdown and protocol behavior on a fresh installed Windows 98
clone. The established guest harness requires 20 GiB free; this shared host
is below that floor. No guard was lowered, peer evidence deleted or guest
started by this chat. The prepared offline fixture and frozen receipt are
under `build/secure-transport-7707/tls13-v3-dos` in the boot owner's tree.
Its prior sibling staging is explicitly superseded due to a DOS filename.

After native foundations, wire and test the supported OS public networking
API/provider, sockets/DNS, trust anchors and certificate failures. A library
handshake does not implement Schannel/SSPI, WinHTTP or WinINet; Electron and
Signal native components also have their own networking and crypto paths.

Themes must be selectable in real settings, applied to actual desktop and
app controls, and preserved through cold boot. The current opt-in painter
does not establish those requirements. Legcord needs login, messages,
attachments and voice; Signal needs device linking, encrypted DB/messages,
attachments and calls; each Office suite needs document/sheet/presentation
editing, formulas, save/reopen and PDF checks. Keep all absent receipts
explicitly unresolved.

The related Chromium/Steam/Office/Legcord owner remains on
`Win98-Modern-codex-20260930`; the PE load-config family remains owned by
chat c009. Their active changes were not imported while under development.
Use their completed commits and guest receipts for the next integration.
