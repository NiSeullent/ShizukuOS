# FD5C2 laptop/common driver implementation

Verified2026-10-02 06:09UTC in the root-owned laptop/security worktree, frozen
baseline`5e2f125ad1de9f5e2d47fae432e5c0d97c49f359`. This handoff owns only new
`drivers/common/`, `drivers/shz_laptop/` and this status document. No existing
core, peer checkout/index, VM, private media, service or publication was changed.

## Production interfaces

- `drivers/common/device.h`: immutable owner/generation bind, start/admit/complete,
  stop/suspend/resume. Sixteen tracked generation/slot/sequence tickets prevent
  replay and stale completion. Stop closes admission before callbacks and waits
  for outstanding tickets. Close failure or revocation before/after close
  quarantines context; release/rebind/start remain denied until a real successful
  close. A failed start also goes through real close.
- `drivers/common/native_sessions.h`: lease-checked adapters to the **existing
  production** AHCI open/read/write/flush/close and xHCI open/no-op/close. Each
  MMIO/sync boundary validates ownership. Allocation ownership is not lost when
  a grant changes. Read output is private until completion/final validation;
  session/DMA aliases and wrapping output ranges are rejected before I/O.
- `drivers/shz_laptop/laptop.h`: complete declared-table checksum/length/GAS
  validation for FADT/ECDT; fixed ACPI SCI enable, enabled event read, W1C ack
  preserving DWORD-only enable halves and advertised reset; exclusive EC
  RD_EC/WR_EC/QR_EC handshakes with one elapsed transaction budget.
- EC failures poison admission and retain ownership. Frozen/reversed clocks,
  stuck IBF/OBF, stale output and revocation are explicit errors. Recovery needs
  a trusted provider to resynchronize real hardware and a clean status read.
- HID-over-I2C descriptor, SET_POWER/RESET, bounded old-input discard, new reset
  acknowledgement, report descriptor, direct input read and drain/power/drain
  stop/suspend/resume. Unknown command descriptors are never used for teardown.
  Only an actual controller/IRQ/drain provider can create these sessions.
- Bounded HID short-item parser derives bit fields from actual descriptors:
  signed mouse motion/buttons, up to5 complete-frame finger contacts, contiguous
  keyboard array selectors and generic variable sensor usage/value outputs.
  Invalid lengths, mappings, report IDs/ranges and partial contact frames fail.
- Typed ACPI `_STA`/`_BIF`/`_BST`, `_RTV`/`_TMP`/`_LID`/`_PSR` provider decoding.
  Current battery charge-limit state and unknown-capacity semantics are retained.
  Relative thermal values are explicitly unsupported. Absent optional methods
  use `SHZ_NOT_FOUND`, distinct from an unsupported evaluator. EC sensor offsets,
  scales and limits require a verified OEM binding; no guessed default exists.

## Verification

```sh
python3 drivers/shz_laptop/test.py --build-dir /dev/shm/fd5c-laptop-driver-validation-20261002
```

The final full command exited0. Seven actual production C suites passed under
GCC, Clang and Clang ASan/UBSan:21 host executions. The AHCI/xHCI suites invoke
their existing complete native models, not forwarding stubs.

| Suite | Assertions per compiler profile |
| --- | ---: |
| Common lifecycle |72|
| Actual AHCI core plus session |15,292,704|
| Actual xHCI core plus session |3,032,878|
| ACPI fixed tables/power |23|
| EC protocol and checked sensor |51|
| HID/I2C, including12,800 descriptor mutations |12,965|
| ACPI battery/thermal/lid/AC |64|

Meaningful negative cases were observed RED before implementation, including
missing lifecycle/table/EC/HID/provider operations, shifted array selectors,
stale RESET acknowledgement, DWORD-only event access, close-time revocation,
modern charge-limit/relative temperature handling and AHCI DMA/context aliases.
Tests verify actual output preservation, DMA retention, release count, admission
closure, timeout/error transitions and controller effects.

Both GCC and Clang linked all nine production C objects as freestanding i486
ELF with **zero undefined runtime symbols**. GCC object45,336bytes;
Clang object48,140bytes. Largest frames are3,012/3,076bytes in report parsing.
Conservative sums of every emitted internal frame are16,268/12,837bytes,
including the reused native cores. **A native worker stack must add its provider
callback and caller frames to this bound; do not bind parsing to a small IRQ
stack.** Neither sum proves a configured native stack is sufficient.

The public source receipt is copied unchanged to
`drivers/shz_laptop/validation/test-result.json` (48,154bytes), SHA256
`2bff63a10943565c8a75a5096353c73a0f70200c6594a87b681f93c708d14f57`.
Its29 source hashes were independently recomputed against the final worktree.

## Native boundaries that remain open

This is implemented and host-verified common driver/protocol support. It is
**not** actual Windows98 driver installation, physical hardware execution,
universal contemporary `.sys` compatibility, or full security isolation.
Real firmware custody/resource ownership, AML namespace/evaluator, laptop I2C
host and GPIO IRQ, native Windows98 input/power bridges, provider stack bounds
and hardware-specific testing remain required. The xHCI adapter does not add
USB HID interrupt endpoints. Multitouch frame aggregation/gestures, fan and
backlight control, system S3/S4/hibernation and ACPI Global Lock support remain
unsupported. Existing WDM/KMDF providers were preserved.

No resource guard was relaxed; no VM, large media copy, driver download or
private-media input was used. Root can include the source and receipt in the
public add-on ISO while retaining these native gates explicitly.
