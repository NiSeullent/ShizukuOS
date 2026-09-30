# Modern application and TLS 1.3 requirements — chat 7707

This is a **requirements contract, not a test result**. Latest-version primary sources were checked on **2026-10-01, Asia/Seoul**. The source snapshot was recorded at 06:12:06 KST. No package download, binary PE inspection, app execution or functional pass is supplied by this document. The machine-readable companion is [modern-app-requirements-7707.json](../benchmarks/modern-app-requirements-7707.json).

The user's broad goal remains functioning themes, current Legcord/Discord and Signal, current open-source Office suites, broad modern-app and Office-family operation, and OS TLS 1.3. The existing full Windows API compatibility aspiration also remains. This finite set of checks is a mandatory starting gate; it does not reduce that goal to four apps or prove every modern application.

## Ownership and integration

[The shared coordination ledger](/root/Win98-Modern-boot/docs/modern-apps-coordination-7707.md) assigns this chat (`01a0f3d1-7707-7d10-962d-26c937d2743b`) the `codex/tls13-7707` secure-transport worktree at `/root/Win98-Modern-tls13-7707`. This chat owns new transport/backend/fixture files and this contract. Peer chats own themes, Chromium/Electron, Office and application implementation. Their kernel, display, wineport and runtime sources and existing running VMs/disk images are outside this chat's edits. Hand off transport artifacts and receipts to the established guest/app owners.

`ntwin32/tls` concerns thread-local storage. It is not a secure TLS transport backend. A direct library handshake, a system API handshake and an application's actual network path are separate acceptance levels.

## Newly required latest stable inputs

Architecture entries below are publisher package labels, not PE headers inspected by this task. Build-time Node requirements do not mean users separately install that Node version to run the packaged app.

| Application | Source snapshot | Published Windows architecture / minimum | Selected version-pinned input |
| --- | --- | --- | --- |
| Legcord | [1.3.0](https://github.com/Legcord/Legcord/releases/tag/v1.3.0), published 2026-07-26 | ia32/x64/ARM64. [Electron 43.2.0](https://raw.githubusercontent.com/electron/electron/v43.2.0/README.md) supports ia32 but requires Windows 10+. [Tag package](https://raw.githubusercontent.com/Legcord/Legcord/v1.3.0/package.json) specifies Electron 43.2.0 and build Node >=26. | [ia32 ZIP](https://github.com/Legcord/Legcord/releases/download/v1.3.0/Legcord-1.3.0-win-ia32.zip), 153,902,184 bytes |
| Signal Desktop | [8.28.0](https://github.com/signalapp/Signal-Desktop/releases/tag/v8.28.0), published 2026-09-23 | x64/ARM64 only in [Windows update metadata](https://updates.signal.org/desktop/latest.yml), minimum 10.0.10240. [Requirements](https://support.signal.org/hc/en-us/articles/360008216551-Installing-Signal) say Windows 10/11. [Tag package](https://raw.githubusercontent.com/signalapp/Signal-Desktop/v8.28.0/package.json) pins Electron 44.1.0 and build Node 24.19.0. | [x64 EXE](https://updates.signal.org/desktop/signal-desktop-win-x64-8.28.0.exe), 141,981,864 bytes |
| LibreOffice | [26.8.0](https://www.libreoffice.org/download/), current stable shown by the official download page | Windows x86-64/ARM64. [Current requirements](https://www.libreoffice.org/system-requirements/) say Windows 10/11. | [x64 MSI](https://download.documentfoundation.org/libreoffice/stable/26.8.0/win/x86_64/LibreOffice_26.8.0_Win_x86-64.msi), 374,906,880 bytes; publisher last-modified 2026-08-24 |
| ONLYOFFICE Desktop Editors | [9.4.0](https://github.com/ONLYOFFICE/DesktopEditors/releases/tag/v9.4.0), published 2026-05-19 | x86/x64/ARM64. [Requirements](https://helpcenter.onlyoffice.com/desktop/installation/desktop-sys-reqs-windows.aspx) list XP as the lowest 32-bit Windows and Vista as the lowest 64-bit Windows. | [x86 ZIP](https://github.com/ONLYOFFICE/DesktopEditors/releases/download/v9.4.0/DesktopEditors_x86.zip), 582,858,718 bytes |

Publisher digests are retained exactly:

- Legcord ia32 ZIP SHA-256: `f348283e64cb1aaaccb7fd3a4d7851c3c95131eef38fa087dc243dbbb604341c`. Source: [release metadata](https://api.github.com/repos/Legcord/Legcord/releases/latest).
- Signal x64 EXE SHA-512, Base64: `jCEuerFSe9HiVtES7y40Wk+VmrzI7VOCpuB61WRLeZRv3JJdn7KN15ZRnWMItFGE+35QyAOoIPPE4LlLBHvmgw==`. Source: [Windows update metadata](https://updates.signal.org/desktop/latest.yml), releaseDate `2026-09-23T21:40:14.407Z`. Retain the metadata body when acquiring the pinned EXE because `latest.yml` moves.
- LibreOffice x64 MSI SHA-256: `4aa6c6e1895f4055104effcb556bd3362d20c6ad707c149543304f395ef9db95`. Source: [publisher artifact metadata](https://download.documentfoundation.org/libreoffice/stable/26.8.0/win/x86_64/LibreOffice_26.8.0_Win_x86-64.msi.mirrorlist).
- ONLYOFFICE x86 ZIP SHA-256: `5eba4b785c5366023de6deaba478da1d18624211561f0a8306da4ca9bd053e1a`. Source: [release metadata](https://api.github.com/repos/ONLYOFFICE/DesktopEditors/releases/latest).

Signal additionally pins native `libsignal-client 0.100.0`, `ringrtc 2.71.0` and `sqlcipher 4.1.0` in its tag package. [Electron 44.1.0 platform policy](https://raw.githubusercontent.com/electron/electron/v44.1.0/README.md) provides Windows x64/ARM64, unlike Electron 43's ia32 path. The native cryptography, encrypted DB and calling modules must actually run; an Electron window alone cannot satisfy Signal.

Recheck latest stable versions before release, record the new source snapshot and explicitly update pins. A source port must identify the same upstream version/revision, port patches, library versions/licenses and resulting artifact hashes. Record official binaries and source ports as different execution paths. Never substitute an older app for the required latest version.

## Existing corpus remains required

Retain [TARGET_APPS.md](TARGET_APPS.md)'s Chromium 156.0.8076.0 x86 r1705698, Supermium 144.0.7559.256 R5, VLC 3.0.24, Notepad++ 8.9.8 and official VS Code 1.138.0. Keep Chromium 150 r1639845 as its historical probe lineage. Also retain [the later Electron corpus](shizukudos10/ELECTRON_TARGET.md) and [E1 inputs](shizukudos10/reports/E1.md): Chromium 157.0.8079.0 x64 r1706750, Electron 44.5.0, VSCodium 1.135.06055 and the older Electron 44.4.5 static fixture. The JSON retains their archive hashes and source documents without claiming fresh upstream-version verification.

Official Discord and Steam remain tracked: [E1](shizukudos10/reports/E1.md) has no official Discord input, and [the screenshots corpus](shizukudos10/screenshots/README.md) explicitly lists Steam as not running. Their exact app/feature pins still need owner completion. E1's observed VS Code 1.139.1 tag does not replace the official pinned artifact automatically. VSCodium is a separate application and cannot count as official VS Code success. Broad modern-app and Office-family targets require an expanding versioned matrix.

## Mandatory real guest checks

Each app needs its complete pinned tree, real responsive UI, Korean/emoji keyboard and IME interaction, pointer/focus/resize, ordinary UI shutdown with helper processes exiting, and a cold-boot reopen of saved data/settings. Capture the Windows 98 identity and any companion Kernel64 domain explicitly. A standalone Kernel64 or Linux-host run is useful evidence for its own domain, but does not establish integration with the Windows 98 desktop.

| Area | Minimum required behavior |
| --- | --- |
| Theme | Select and apply at least two supported themes in actual guest settings; verify desktop/title bars and native buttons, edits, menus, checkbox/radio, scrollbars and file dialogs in applicable normal/hover/pressed/focus/disabled states. Verify saved selection survives app relaunch and guest cold boot, and new controls repaint correctly. Check actual app windows, separately identifying custom-rendered content and native chrome. |
| Legcord/Discord | Actual login with approved test credentials; bidirectional unique Korean/emoji messages with an approved counterpart; fixture attachments with received hashes; usable voice session; normal shutdown/relaunch and cold reopen retaining login, conversation, settings and theme. A login page alone is incomplete. |
| Signal | Complete live QR linking with an approved mobile test device; bidirectional unique encrypted messages and hashed fixture attachments; functioning native encrypted DB/libsignal; real RingRTC call; cold reopen retaining link/history/theme and ability to message again. |
| Each Office suite | Create/open, edit, save and cold reopen DOCX/ODT document fixtures with Korean/table/layout; XLSX/ODS sheets with recalculated formulas and charts; PPTX/ODP decks with images and actual slideshow. Export/reopen PDFs and inspect output. Exercise actual New/Open/Save As to a new path and verify files on guest storage. |
| Retained browsers | Actual rendered known local page, JavaScript, real input, controlled HTTPS fixture and clean shutdown. Loader progress and DOM-only milestones remain separate evidence. |
| Retained VLC/editor apps | Actual audio/video playback/seek/plugin discovery; Notepad++ new-file Save As/edit/reopen/clean exit; official VS Code and separate VSCodium editing/save/cold reopen, terminal and supported extension. |

These checks do not claim untested features work. Maintain a feature matrix for additional suite components, device functions and modern apps; preserve unsupported features as unresolved requirements.

## TLS 1.3 acceptance and OS integration

Use an independent controlled TLS server offering **TLS 1.3 only** and a guest client built against the actual transport path. Record endpoint/server implementation, trust root, SNI/hostname, guest clock, negotiated `TLSv1.3`, certificate verification result, cipher, exchanged payload hashes and normal close. Confirm the library's RNG uses a real guest entropy source and retain its policy and artifact provenance.

Negative trials must independently reject untrusted roots, wrong hostname/SAN, expired certificates, not-yet-valid certificates, corrupted chain signatures and tampered encrypted records. No unverified application bytes may be delivered. A TLS-1.3-constrained client must reject a TLS-1.2-only peer. Tests must not disable certificate/hostname checking to get a passing handshake.

A direct pinned-library/native fixture pass establishes only that path. **OS TLS 1.3 requires a separate client using the supported public OS transport API/provider**, with the same successful exchange and certificate failures. Then identify each app's actual path: Electron's bundled stack and Signal native modules may not use the OS provider. Verify those paths independently. Keep all three layers incomplete until their corresponding guest receipts exist.

## Current known gaps and evidence rules

The inspected worktree contains newer [Kernel64 and Chromium guest evidence](shizukudos10/STATUS.md): direct UEFI/TCG Win64 fixture execution and Chromium 157 x64 startup/crashpad child execution are recorded. [K4](shizukudos10/reports/K4.md) and [K5](shizukudos10/reports/K5.md) still stop before browser functionality. Some earlier overview paragraphs retain older no-execution wording; use versioned reports for the specific trial and do not promote startup into a browser pass.

[E1](shizukudos10/reports/E1.md)'s recorded Electron/VSCodium trials stop at load-time imports; the missing set depends on the tested revision and must be remeasured after peer merges. [NTWin32Wrapper9x](../ntwin32/README.md)'s PE32 preparation rejects PE32+, so it cannot directly load the official Signal/LibreOffice x64 payloads. The [theme painter](../ntwddm/include/nttheme.h) is a source implementation with limited parts; it is not a persistent actual-desktop/native-control receipt. Historical Notepad++ editing/save results and its Save As/shutdown failures stay in their own lineage.

This contract supplies **no new app, theme, transport or OS-level GUEST_PASS**. Export counts, static import closure, compiler success, host tests, observer exit 0 and a visible window remain preliminary evidence. Forced process termination is a failed clean-exit gate.

A completion receipt must identify contract/check, expected and observed behavior, result (`NOT_RUN`, `BLOCKED`, `FAIL`, `GUEST_PASS`), actual guest/execution domain and cold boot, architecture, app/archive/executed-file hashes, core/provider/library/port revisions and hashes, launch flags, fixture/endpoint identity, timestamps and evidence paths/digests. All applicable app and global gates must have reproducible guest passes before the corresponding completion claim. Missing and blocked checks remain incomplete.
