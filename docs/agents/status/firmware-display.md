# Firmware/display implementation status

## Assigned scope and ownership

Owner: Firmware/Display Lead, branch `codex/pma-integration-20261002`, isolated worktree `/root/Win98-Modern-pma-20261002`, initial base `a648e9b`.

Owned source: `shizukudos/uefi/{efi.h,boot.h,boot.c,test.c,main.c,test_qemu.py}` and GOP selection/logging call sites only in `shizukudos/supervisor/loader/loader.c`. No Kernel64 scheduler, framebuffer backend, Supervisor domain/scheduler, NT wrapper, native Windows driver or historical receipt was edited. Root serializes commits; commit SHA is pending root review and commit.

Windows 98 remains the product OS and owns VMM/USER/GDI/Explorer. This change establishes shared firmware selection and component framebuffer execution, not the DOS replacement or actual Windows GUI acceptance gate.

## Architecture decisions

- `sd_gop_select()` reuses the unchanged `SD_FRAMEBUFFER` and RGBX/BGRX handoff. GOP QueryMode/SetMode and boot-service handle lookup now have explicit x64 EFI ABI types, with checked offsets.
- A safe original framebuffer is required before changing hardware. Enumeration covers every mode for firmware counts up to 1024; larger counts retain the validated original without enumeration. Geometry is capped at 8192 in each dimension, pitch fits a 32-bit byte count, and visible bytes are capped at 64 MiB. A same-sized native backbuffer is consequently also bounded to 64 MiB.
- EDID_ACTIVE is read only on a handle that provides the exact selected GOP instance. Unrelated controller/display EDID is ignored. Missing active EDID on a combined-output handle falls back to the resolution ladder; no controller topology is invented.
- The parser accepts EDID 1.3/1.4 with valid header, version, advertised extent and block checksums, then uses the first noninterlaced detailed timing's active geometry. EDID 1.3 requires its preferred bit. EDID 1.4's first detailed timing remains preferred even when its native-format bit is clear. No clock or sync timing is programmed from EDID.
- Supported EDID geometry takes precedence over 3840x2160, 2560x1440, 1920x1080, 1600x900, 1366x768, 1280x720 and 1024x768; otherwise the validated firmware mode is retained. Duplicate geometry favors the smaller valid pitch.
- RGBX/BGRX remain supported. PixelBitMask is accepted only for exact canonical 8-bit RGB/BGR masks with an 8-bit reserved high byte, then normalized into the existing handoff. Arbitrary packed masks and PixelBltOnly remain unsupported.
- Every QueryMode allocation and optional handle-list allocation is freed before memory-map acquisition. Each successful SetMode is revalidated for geometry, pitch, layout and actual framebuffer extent. After review correction F1, every rejected attempted switch actively restores and revalidates the original, even when published Mode metadata did not change, including a potentially relocated aperture. Failed restoration returns an error; available-but-invalid GOP stops the direct loader rather than falling through to a physical VGA mode change.
- Selected geometry/pitch/layout/query count is logged before ExitBootServices. The focused OVMF harness now requires one live selection record, compares it with the post-exit screenshot geometry and enforces independent pitch/budget bounds.

## Public source provenance

The implementation and fixtures were independently authored; no third-party implementation code was copied.

- [UEFI Specification 2.10, chapter 12](https://uefi.org/specs/UEFI/2.10/12_Protocols_Console_Support.html), sections 12.9.2.1 (QueryMode and callee-allocated information), 12.9.2.2 (SetMode), 12.9.2.5 (EDID_ACTIVE layout/GUID) and 12.10 (GOP/active-output handle relationship). QueryMode/SetMode signatures, mode information, pixel layouts and firmware interfaces follow this specification.
- [UEFI Specification 2.10, chapter 7](https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html), HandleProtocol and LocateHandleBuffer interfaces; existing ExitBootServices ownership contract is preserved.
- [VESA Enhanced EDID Standard, Release A Revision 2](https://glenwing.github.io/docs/VESA-EEDID-A2.pdf), a public mirror of the VESA-authored standard: section 3.6.4 preferred timing semantics, sections 3.10/3.12 detailed timing fields, base block extent/checksum fields. The parser reads offsets 18/19, 24, 54..71 and 126/127; it does not synthesize display timings.

## Initial implementation tests and results

All commands ran from this isolated worktree. The tools were already installed; no download, client configuration change, original disk/media change or service startup was performed.

| Command | Observed result |
|---|---|
| `python3 shizukudos/uefi/test.py` before edits | PASS: 354 existing checks |
| Same command after adding selector tests, before selector implementation | Expected failure: absent `sd_gop_select` at then-line 317 |
| Same command after adding stale-current QueryMode regression | Expected failure: selected mode disagreed with required mode at then-line 308; preserved in `shizukudos/uefi/build/host-tests-red-query-original.log` |
| `python3 shizukudos/uefi/test.py` after correction | PASS: 889 UEFI handoff, fault injection, framebuffer and bounds checks |
| `python3 shizukudos/uefi/test.py --cc clang --sanitize` | PASS: same 889 checks under ASan/UBSan; no sanitizer diagnostics |
| `python3 shizukudos/uefi/build.py` | PASS: original freestanding AMD64 PE32+ EFI application, relocations present, no DLL imports, deterministic timestamp; 19,456 bytes |
| `python3 shizukudos/uefi/test_qemu.py --qemu /usr/libexec/qemu-kvm --firmware-code /usr/share/edk2/ovmf/OVMF_CODE.fd --firmware-vars /usr/share/edk2/ovmf/OVMF_VARS.fd --timeout 45` | PASS twice, each with fresh disposable ESP/VARS and network disabled; final strict receipt described below |
| `git diff --check -- shizukudos/uefi shizukudos/supervisor/loader/loader.c` | PASS: no whitespace errors |

The host suite checks valid associated EDID preference, unrelated/malformed/missing/truncated EDID, unsupported revision, interlaced timing, extension checksums, QueryMode errors and short records, allocation cleanup, pitch overflow/budget, unsupported masks/BltOnly, canonical bitmask normalization, SetMode errors and actual extent rejection, recovery after hardware changed on an error, failed recovery, safe-current fallback, excessive mode count and stale QueryMode(current mode) geometry. Existing map/exit/pitch/padding and RGB/BGR pixel tests continue to run.

Initial strict live evidence is `shizukudos/uefi/build/ovmf-9cn_le9y/{result.json,serial.log,handoff.png,handoff.ppm}`. The serial record is:

```text
GOP selection: mode 28 2560x1440 pitch 10240 BGRX queried 30 EDID=unavailable selected
```

QMP confirms KVM enabled. The real post-ExitBootServices screen is 2560x1440 and matches five independent proof pixels. QEMU PID 941244 stopped with exit code 0 after 18.517 seconds. The receipt contains selected mode/pitch/layout/query count and test harness hash. The live guest had no active EDID, so EDID selection is host-contract evidence, not physical display or live EDID evidence.

| Evidence | SHA256 |
|---|---|
| `shizukudos/uefi/build/BOOTX64.EFI` | `991de7057f927f08f9168b37f4e77fc8912648099f460b5b562b236cced57f3f` |
| OVMF CODE input | `090b9b1872b725cd698d41d9d8987ad3d08ffbe6ea5dab28b973ad7f7b846498` |
| `shizukudos/uefi/test.c` | `ff527bc0aaafd66141e8c3bbfbf874f877b9d1f1b475e677c7cbc8b760e2241b` |
| `shizukudos/uefi/test_qemu.py` | `78654d594237d04bd2d6e67d00cb3bcec0a211b9ee1e06e468bd6a6869c5e3de` |
| Final live `result.json` | `122bfc9cc36dc6fc056b335d8eb9c04c1f2d87f24bef015575b97db3ffd89689` |
| Final live framebuffer screenshot | `e11b73e4edfc135199a124cd69a893260160e2f372c5cb0475b19336dc1724e6` |

The EFI build receipt records individual source hashes. Host logs and the first OVMF run (`ovmf-dl3ul9s2`) remain local and distinct from the final strict run. No recorded historical validation file was rewritten.

## Review correction F1 and fresh verification

The independent review found that a failed SetMode could partially change the physical display while leaving all published Mode metadata unchanged. The earlier conditional recovery could then return a successful stale fallback. This was a real remaining defect in the initial implementation; the earlier passing tests did not exercise separate hardware and metadata state.

The firmware fixture now tracks `physical_mode` independently from published Mode. The new regression failed before the fix at `test.c:314` (`display.physical_mode == mode`); the exact failing output remains in `shizukudos/uefi/build/host-tests-red-f1-physical-state.log`. It covers an 800x600 original with no remaining candidate, an original mode that itself appears later in the resolution ladder, and an original restoration that fails while metadata still claims the original mode.

`sd_gop_select()` now always calls SetMode(original) after any rejected attempted switch, then requires successful restoration and full framebuffer revalidation before another attempt or fallback. The relocated-aperture update is preserved. This fix round changed only `uefi/boot.c`, `uefi/test.c` and this status document; no index or other subsystem was changed.

Fresh verification after the fix:

| Command | Observed result |
|---|---|
| `python3 shizukudos/uefi/test.py` | PASS: 966 checks |
| `python3 shizukudos/uefi/test.py --cc clang --sanitize` | PASS: 966 checks; no ASan/UBSan diagnostics |
| `python3 shizukudos/uefi/build.py` | PASS: 19,456-byte freestanding AMD64 EFI, no imports, relocations present |
| `python3 shizukudos/uefi/test_qemu.py --qemu /usr/libexec/qemu-kvm --firmware-code /usr/share/edk2/ovmf/OVMF_CODE.fd --firmware-vars /usr/share/edk2/ovmf/OVMF_VARS.fd --timeout 45` | PASS: fresh isolated KVM/OVMF boot; mode28, 2560x1440, pitch10240, BGRX, queried30, EDID unavailable; selection agrees with post-exit screenshot and five proof pixels |

Current live evidence: `shizukudos/uefi/build/ovmf-7uxc7z2p/{result.json,serial.log,handoff.png,handoff.ppm}`. QEMU PID 1089275 stopped with exit code 0 after 11.007 seconds. These are component checks; they do not establish physical firmware failure recovery or actual Windows 98 acceptance. Root independently compiled the previous Supervisor version; final source-bound integration remains root's responsibility.

| Current source/artifact | SHA256 |
|---|---|
| `shizukudos/uefi/boot.c` | `2fbd2884fca0ee0f1fc064b0685932a1f702f49142bbaf5d835d4debff306124` |
| `shizukudos/uefi/test.c` | `c2cd281b6788e1f8f9ec85e40f85de5e047bcb1cca4ec2030a5a9a8881939273` |
| `shizukudos/uefi/build/BOOTX64.EFI` | `157c50c12acb05d4e117c7b845535b102faafc0ac3c422ec2800b125b04bbe6f` |
| F1 RED log | `d561d02f18b88491e0ad1a169ab357fe8b0710446f5c6a895fa8b511ef708b37` |
| Current live `ovmf-7uxc7z2p/result.json` | `9c8a426b35cfd144f7a32545b3710e3d9cd0fd5ec42b6a7edc88c47f2be68fc7` |

## Dependencies, blockers and remaining work

Root handles the full Supervisor build and `run_k64_gop.py` integration tests after its kernel/Win64/DOS build inputs exist. The initial worktree lacked Supervisor `images.h`/EFI, DOS16 images and native-driver/private toolchain inputs. Kernel32/64 artifacts have since been built by root, but this lead has not claimed Supervisor linkage or Kernel64 GUI execution from that fact.

The separate `csmwrap/loader/uefi_collect.c` still snapshots raw GOP PixelFormat into its own ABI. This change normalizes only the existing SD_FRAMEBUFFER path; canonical PixelBitMask support in that separate CSMWrap consumer or the native SHZGOP1 driver is not claimed. Native-driver default scope remains its exact retained BGRX framebuffer.

Remaining actual Windows gates: two owned cold boots through the real ShizukuDOS DOS-to-VMM replacement path; retained native GOP descriptor/PCI/pitch/format agreement through VMM; actual SHZGOP load and USER/GDI rendering; actual keyboard/mouse input; file creation/save/reopen with independent bytes/flush/readback. No physical firmware, live EDID, hardware GPU acceleration, high-resolution dynamic shell, per-process legacy VGA/SVGA or actual VMM/PMA display ownership integration is established by this component result.
