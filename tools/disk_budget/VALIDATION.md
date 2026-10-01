# Validated original Wine source sharing

The exact reviewed v2 plan completed successfully on 2026-10-01. It changed
allocation only in 895 unmodified tracked Wine source files in the boot cache,
using the corresponding original files in the apps cache.

- Kernel-compared bytes shared: **27,828,224 bytes (26.5390625 MiB)**.
- Independently summed destination exclusive pages released: **27,828,224 bytes**.
- All 895 full SHA-256/Git blob checks and original pathname bindings passed.
- Device, inode, size, mode, uid, gid, link count, mtime and atime stayed equal.
  Change time also stayed equal in all 895 files; allocation counts were logged.
- No file was deleted, replaced, renamed or changed logically. Generated and
  patched sources, Git objects, VM images and other owners' build artifacts were
  excluded.
- The installed Linux UAPI fixture passed all six C11 static assertions; the
  path/range validation passed 27 guard cases. The ABI fixture invokes no ioctl.

Execution lasted **3134.226855 seconds (52 minutes 14 seconds)**, from
`2026-10-01T06:13:31.093447+00:00` to
`2026-10-01T07:05:45.320302+00:00`. The pass used fresh process checks and durable
per-file receipts while the host had substantial concurrent disk/page I/O waits.

The evidence directory consumed **3,395,584 allocated bytes**, including both
plans, the completed JSONL receipt, ABI executables and the frozen summary.
This measurement precedes the separate follow-up audit report. The initial
and final whole-filesystem free-space readings were 23,449,845,760 and
22,283,636,736 bytes. That **−1,166,209,024-byte concurrent filesystem delta** is
not the savings of this pass. The local destination extent maps establish the
27,828,224-byte release; the evidence files also consume their recorded space.

Frozen evidence under `/root/Win98-Modern-boot/build/disk-c009/`:

| File | SHA-256 |
| --- | --- |
| `wine-source-plan-v2.json` | `e4c26a58831ec90c46186f5abba4a6dae12c08cdd212ddb1024417e737514f5d` |
| `wine-source-apply-v2.jsonl` | `b6bf19703a62b5c0ef71c9b6e719ff75af3dc8a8038104f669478f71e1a72abc` |
| `wine-source-summary-v2.json` | `cdc8fe4bee877975672a8b1529f78aaf2f61339899560daf989632908e1d707a` |

The applied utility hash is
`1f240dc1cf59d15e7e0c7f599d36d460d6cd85579919b66c771f95d3ce257e51`.
All three cached Wine HEADs stayed
`db11d0fe6a169c457e23d007e20404643d067aa8`. The complete original v1 plan is
retained; its exact file/range/identity/hash/HEAD list equals v2.

This proves source-cache storage preservation. It does not establish native
Windows 98 execution of Chromium, Legcord, Steam or LibreOffice.
