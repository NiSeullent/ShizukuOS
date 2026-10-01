# Windows 98 IO.SYS / GOP integration evidence

The target is Microsoft's installed Windows 98 SE and its original IO.SYS.
The cooperating `shizukudos/iosys_uefi` module supplies an opt-in UEFI-loaded
capsule, patches the loaded IO.SYS entry in memory, consumes the validated GOP
snapshot and resumes original MSLOAD. This module adds the early BIOS text
contract that MSLOAD and subsequent Windows startup use on that framebuffer.
SeaBIOS supplies the later BIOS services; native Windows GUI acceptance remains
separate from entry acceptance.

## Implemented and integrated

- Legacy mode03 uses an 80x25 logical text viewport, 8x16 font and 4096-byte
  BDA text page. The physical 1280x800 BGRX framebuffer and 5120-byte pitch remain
  available to the native display driver.
- The original diagnostic MBR guards those properties, the selected active FAT
  partition, EDD disk geometry, and the signed Windows VBR before chain entry.
  Only its first 440 bytes replace code on a new private clone. Disk identity,
  partitions, original Windows VBR and IO.SYS remain intact.
- `build.py` archives the explicitly pinned git objects and submodules, freezes
  all patches and the baseline build script, and compiles a separate firmware.
  `--direct-io-sys` applies the cooperating entry patch after the GOP patch.
- `test_qemu.py` runs the authored firmware contract and actual Windows clones.
  `direct_boot.py` freezes the cooperating native entry runner, including its
  corrected local GDB dump commands. Neither modifies the peer's source.

## Completed checks

Host validation: 21 tests passed: six immutable-source/pin checks, three tests
compiling and executing the actual patched SeaVGABIOS functions, and 12 MBR
preparation/partition-identity tests. Both normal and test probes assemble into
signed 512-byte sectors, with executable code confined to 440 bytes.

The ordinary firmware build is
`build/shizukudos/csm-ios-gop-7acd/CSMWRAP.EFI`, SHA-256
`26ba2da3befc8051839ae7a05c57af21cd2e270fe295fb63ce8d1b0fbf0af5cd`.
The combined entry/text firmware is
`build/shizukudos/csm-ios-gop-7acd-direct/CSMWRAP.EFI`, SHA-256
`1579f656414a93899e197cf173590c0680c373045eea89496ee0b8b47b0e7505`.
Each build records its actual frozen inputs and patched source hashes.

The patched firmware contract run
`build/shizukudos/csm-ios-gop-7acd-contract-20260930T144753-patched/result.json`
passed ordered `IOGOP:S/T/D/C` and exited 33 through the authored test-only debug
device. The existing GOP firmware control
`build/shizukudos/csm-ios-gop-7acd-contract-20260930T144801-control/result.json`
was correctly rejected before `T`, with failure marker `F` and exit 35. These are
firmware interface tests, with no Microsoft kernel or replacement DOS runtime.

Actual Windows run
`build/shizukudos/csm/run-ios-gop-7acd-20260930T144900/result.json`
passed the same early contracts on the retained Windows disk and reached its
SYSTEM.INI/mshbios missing-device prompt. The final screenshot is independently
bound in `visual-review.json`. The persistent F-segment locator passed the six
later captures; the first capture preceded a complete locator observation.

On a subsequent new cold clone,
`build/shizukudos/csm/run-ios-gop-7acd-20260930T145428/result.json`, an Enter sent
after reviewing the actual prompt continued startup to a USER.EXE failure.
`manual-visual-review.json` and read-only `plain-text/BOOTLOG.TXT` retain that
result. The log loaded DISPLAY.drv and vga.drv before USER.EXE failed. It also
records mshbios, VPD and GULIM.TTC failures; their causal relationship is not
established. This trial loaded the VGA display path and proves no GOP desktop.
Original archives and each retained clone source remained unchanged.

The first combined direct trial
`build/shizukudos/iosys-uefi-port/runs/run-ios-gop-7acd-direct-01/iosys-entry-result.json`
observed `IO98:GOP-CONSUMED` and hardware-breakpoint registers at original
`0070:0208`, but failed its complete acceptance because GDB treated quoted dump
filenames literally. Keep that failed record. The next trial uses the frozen
corrected peer capture runner.

The new cold trial
`build/shizukudos/iosys-uefi-port/runs/run-ios-gop-7acd-direct-02/iosys-entry-result.json`
passed all 10 checks: the hardware-breakpoint capture completed, the redirected
entry consumed GOP, original MSLOAD resumed at `0070:0208` with the expected
registers, the in-memory entry jump and descriptor matched, the original Windows
VBR/stack/INT1E state matched, and the consumed marker bound the GOP geometry
and checksum. The immutable archive and original IO.SYS file were independently
unchanged, and the emulator exited normally. The executed peer runner is retained
at `build/shizukudos/csm-ios-gop-7acd-direct/inputs/run-ios-gop-7acd-direct-02/`.
This PASS certifies the actual IO.SYS entry port, not a native Windows desktop.

## Reproduce

From `/root/Win98-Modern-boot`, use a new output name for each firmware build:

```sh
python3 -B shizukudos/csm/ios_gop/build.py --jobs 2 --direct-io-sys --out build/shizukudos/csm-ios-gop-7acd-direct-new
python3 -B -m unittest discover -s shizukudos/csm/ios_gop -p test_profile_build.py
python3 -B -m unittest discover -s shizukudos/csm/ios_gop/tests -p test_mode03_geometry.py
python3 -B -m unittest discover -s shizukudos/csm/ios_gop/boot_probe -p test_boot_probe.py
```

Use the guest commands retained in each run receipt to reproduce its exact
checkpoint, firmware, capsule and cold hardware. Guest networking is disabled.
Run names beginning `run-ios-gop-7acd-` belong to this integration chat; existing
driver and direct-entry chats retain their own source and guest ownership.
