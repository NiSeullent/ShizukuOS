# FD5C legacy text renderer

- Assigned scope: bounded safety, CP437 glyph reuse and BIOS cursor rendering in the existing Supervisor 80x25 legacy text path.
- Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52`.
- Worktree: `/root/Win98-Modern-pma-integration-fd5c-20261002`.
- Owned files: `shizukudos/supervisor/src/video.c`, minimal CP437 linkage/receipt changes in `shizukudos/supervisor/build.py`, `shizukudos/supervisor/native_win98/tests/{video_host.c,test_video_host.py}`, this status file.
- Code commit: `149dec3`; root integrated after independent review. This agent did not change the Git index or create a commit.

## Decisions and dependencies

Reuse `csmwrap/video/cp437.c`, its header and existing public-domain font; do not copy a second glyph implementation. The Supervisor payload links that source and its build receipt hashes the three-file glyph closure. Per root review, the receipt also includes the existing payload dependency `abi/shz_ipc.h`. CP437 symbols remain the existing documented compact approximations, not a new exact VGA ROM font claim.

Require the complete 4,000-byte guest text page before any INT10 text operation. Reject invalid initial AH13 DH/DL coordinates, incomplete guest-source spans and zero count without changing text or cursor. Source offsets obey real-mode ES:BP 64-KiB wrap, with all needed spans checked before mutation. Valid strings retain complete processing: attributes, BEL/BS/CR/LF, wrapping and scrolling through the existing teletype/scroll primitives; AL bit 0 controls the final cursor update. AH13 scrolling fills its exposed row with 07h. Existing AH0E retains its previous fill-attribute behavior. No valid string is silently truncated at the last row.

Compatibility reference inspected locally: pinned primary SeaBIOS `vgasrc/vgabios.c`, `handle_1013` and `write_teletype`, plus `vgafb.c` scroll/fill behavior in `/root/Win98-Modern-main-integration-20261001/build/upstream/csmwrap/seabios`. No third-party implementation was copied. Existing CSMWrap INT10 does not implement AH13; its own teletype/scroll and CP437 renderer remain unchanged.

Honor BIOS cursor disable bit and start/end scanlines within the 16-line font. Cursor shape changes invalidate the render signature. Reset cache/shape on video initialization; include framebuffer base, size, dimensions, pitch, format and guest RAM identity in cache validity. Validate RGB/BGR framebuffer bounds before drawing, including 64-bit pitch arithmetic. Arbitrary masks remain explicitly unsupported in this renderer.

Clang UBSan exposed existing misaligned uint16 stores in BIOS data words at odd addresses 0463h/0485h. Byte-wise little-endian stores preserve the same BDA bytes and remove the undefined C accesses.

## Evidence

Initial production video.c SHA256: `c4c25e1e050a25c6c5f4eb316917fe7dab3fbf01314151826ba59c203002b03a`.

Actual RED fixtures were executed before production changes. Initial combined-run evidence is preserved in `build/pma-fd5c-video/red.log`; isolated behavioral groups plus BIOS wrap/scroll/control and complete-page cases are preserved in `red2.log` (SHA256 `e32f99aa01dcd35b22bd69a93cb3fd166b3b59f31dd7cee563754f9e5609ff15`). GCC/Clang native failed nine behavioral groups; Clang ASan/UBSan additionally diagnosed the odd-address BDA stores. The valid attribute-string case was a passing baseline control.

Verification commands:

```sh
python3 -B shizukudos/supervisor/native_win98/tests/test_video_host.py
python3 -B shizukudos/csmwrap/test_int10.py
git diff --check
```

Fresh freestanding GCC object compilation uses the actual `CFLAGS` loaded from `supervisor/build.py`, then `ld -r` links video.o and cp437.o. `nm -u` must contain only the expected Supervisor global `G`; the CP437 symbol must resolve. Exact commands and source hashes are retained in `build/pma-fd5c-video/freestanding-result.json` and `freestanding-final-result.json`. The later receipt-only addition of `abi/shz_ipc.h` does not change these compile flags or the video/glyph object sources; root's full payload build will verify the combined final build closure.

GCC native, Clang native and Clang ASan/UBSan passed all ten behavioral groups with no sanitizer diagnostics. The initial GREEN run had 329,655 checks per mode, recorded in `green.log`. The final run after the byte-layout assertions passed 329,657 checks per mode and is recorded separately in `green-final.log`. Existing CSMWrap INT10 regression passed (`csmwrap-int10.log`). This is actual host execution of production C, not firmware/guest/Windows acceptance.

## Blockers and remaining work

GCC sanitizer execution is a visible environment SKIP: installed GCC linker scripts refer to absent `/usr/lib64/libasan.so.8.0.0` and `/usr/lib64/libubsan.so.1.0.0`. No package was installed. Clang ASan/UBSan runs the same actual C path.

Root integrated the fixture into the existing native `run_host.py`; its seven cases passed GCC and Clang ASan/UBSan (14 executions,362215 checks/compiler). Independent core reviewer approved the actual source. Fresh complete Supervisor payload and EFI loader compile/link passed. Root initially omitted the required payload argument in its loader wrapper call; the corrected call passed. This lane does not change device ports/EPT, provide direct CRTC cursor integration, create per-process/on-demand VGA contexts, implement graphics/VBE modes, or establish Win98 VMM/USER/GDI desktop acceptance. DOS and installed-Win98 legacy profiles currently share this serialized compatibility renderer and remain mutually exclusive. The existing FNV render signature remains probabilistic; this change fixes its omitted cursor/target state, not hash collisions.

Normal product target remains actual Windows 98. This existing legacy text framebuffer is a compatibility/diagnostic path and does not replace its desktop.
