# Display safety lane — c957

## Assignment and ownership

Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52`.
Worktree: `/root/Win98-Modern-pma-c957-display-20261002`.
Branch: `codex/pma-c957-display-20261002`.
Code/test commit: `092c4fe5b27559e23781ab3484f707a37a4796d8`.

Owned changes:

- `shizukudos/kernel64/main.c`: only `k64_boot_framebuffer` validation.
- `shizukudos/kernel64/gfx_fb.c`: only `gfx_fb_present` clipping.
- `shizukudos/tests/test_k64_boot_framebuffer.c`.
- `shizukudos/tests/test_gfx_present_rect.c`.
- `shizukudos/tests/test_display_contract.py`.
- This status document.

The concurrent 163f lane owns GOP EDID/mode selection. This lane does not modify
that worktree, firmware selection, shared ABI definitions, or scheduler code.

## Architecture and implementation

Windows98 remains the product OS and Windows execution authority; its real
VMM/USER/GDI/desktop remain the normal product target. These fixes protect the
existing Shizuku Kernel64 framebuffer backend and do not introduce another
desktop, hardware owner, graphics subsystem, or scheduler.

The current baseline already implements a native GOP backend, adopted display
dimensions, a backbuffer, damaged-rectangle presentation, RGBX/BGRX conversion,
and existing OVMF std/ramfb tests. This work extends its safety contracts:

- `k64_boot_framebuffer` rejects null output, unaligned framebuffer bases,
  physical span overflow, and byte pitches that cannot address complete 32-bit
  pixels. Existing dimension, extent, format, and producer-size checks remain.
  Every rejected handoff preserves the caller's output bytes.
- `gfx_fb_present` forms and intersects rectangle endpoints in 64-bit signed
  arithmetic. Nonpositive, offscreen, and empty requests never reach a backend
  or affect presentation statistics. Valid requests reach the backend with
  bounded, nonempty coordinates; dimensions exceeding its signed-int coordinate
  contract fail closed.

In the existing ABI, `fb_format` precedes `fb_bpp`, so `HAS(fb_bpp)` already covers
both fields. Tests verify truncation before `fb_format`, inside `fb_bpp`, and a
valid tail ending immediately after `fb_bpp`. There was no uncovered format
over-read to repair, and the wire layout is unchanged.

## Verification and evidence

The tests exercise production functions rather than copied implementations:

- The handoff test includes production `main.c` to access its private copied
  boot information. Function/data sections and linker garbage collection discard
  the kernel entry and unrelated privileged code.
- The clipping test links production `gfx_fb.c`. A recording backend observes
  the actual forwarded rectangle and statistics; an independent per-pixel
  coverage oracle checks 50,625 combinations of boundary coordinates/extents,
  including `INT_MIN` and `INT_MAX`.

Commands executed from the owned worktree:

```text
python3 -B shizukudos/tests/test_display_contract.py --out shizukudos/build/display-contract-c957/red
python3 -B shizukudos/tests/test_display_contract.py --sanitize --out shizukudos/build/display-contract-c957/red
python3 -B shizukudos/tests/test_display_contract.py
python3 -B shizukudos/tests/test_display_contract.py --sanitize --cc clang
git diff --check
```

Before the production edits, default host tests reproduced both bugs: the
decoder accepted a 69-byte pitch and presentation forwarded an overflowing
offscreen rectangle. The first sanitizer attempt could not link because the
installed GCC runtime scripts referenced absent ASAN/UBSAN shared libraries.
The installed Clang runtime was used subsequently; no tools were installed.

Fresh default GCC and Clang ASAN/UBSAN runs both pass **40 handoff checks** and
**156,579 clipping/statistics checks**, with exit status zero. Whitespace checks
also pass. Logs, source hashes, exact compiler commands and result receipts are
in this worktree's ignored `shizukudos/build/display-contract-c957/`; original
failure evidence remains in its `red/` subdirectory.

The runner writes only local build binaries/logs/receipts. It does not boot a
kernel, access devices, download dependencies, start network services, or alter
client-global configuration.

## Dependencies, limits and remaining work

No unresolved implementation blocker in this lane. Root integration owns the
full kernel build, Supervisor compile, independent review and combined changes.
Those checks were not executed by this lane and must be assessed separately.

These are host contract tests, not evidence of physical firmware compatibility,
Windows98 desktop boot, arbitrary GOP `PixelBitMask` support, VBE/planar VGA,
per-process legacy video lifecycle, or a Windows98 GDI display bridge. Those
remain separate integration work. Existing frozen receipts and historical
architecture/audit documents were not rewritten.
