# Windows 98 Shizuku's Second Edition — device foundations

Date: 2026-09-27. This checkpoint adds original USB descriptor validation and
an application-owned GDI presentation adapter, and corrects the NTWin32
contention backoff. It builds on the actual AHCI and PCI-E/xHCI execution
recorded in the [previous checkpoint](XHCI_CHECKPOINT.md).

The 15-export `NTW32.DLL` now uses a finite positive Sleep during contention.
The previous DLL failed an explicit higher-priority-waiter model after eight
zero-delay yields. The corrected DLL executes 406 checks and 147 actual PE32
calls at each of two load addresses, including three contended SRW combinations
and pending InitOnce completion. The service model does not validate native
Win98 scheduling or timer latency. Details and exact hashes are in the
[ABI execution record](../platform/abi32/README.md).

The new [GDI adapter and probe](../ntwddm/win98/) link the original software
renderer to an application-owned, top-down 32-bit DIB. `NTWGPROB.EXE` builds
as a 12,800-byte i486/PE32 program with classic KERNEL32, USER32 and GDI32
imports, original compiler memory support, and no CRT or KernelEx dependency.
Its SHA-256 is
`4b6fa2dad7ccc3dd3efa39917354b30cc7bad77ba4d9d167aaa8fc5646e89b53`.
Host and sanitizer runs each pass 398,287 pixel, failure and ownership checks.
The native program reports DIB pixels, GDI calls and cleanup separately, and
shows a bounded five-second window. Native Windows execution remains unverified.

The [USB descriptor core](../drivers/usb_native/) validates complete device and
configuration buffers using fixed-size storage, with no allocation or libc.
Failure leaves the output unchanged. Its declared USB2 subset checks bounds,
interface/alternate relationships, endpoint ownership, speed-specific fields
and resource limits. Independent mutation and generated-input tests run under
GCC, Clang and ASan/UBSan; freestanding i486 objects require zero undefined
symbols. This parser performs no device enumeration, transfers or class I/O.
Its own README and source-bound test receipt define the exact supported subset.

The [original compiler memory support](../platform/freestanding/) implements
`memset`, `memcpy`, `memmove` and `memcmp`. Each host/compiler/sanitizer variant
passes 1,024,736 assertions, and both i486 implementations link with no external
helpers. Test-only names keep the oracle and sanitizer's host libc separate.
This support also resolves compiler-generated PCI initialization calls in CI.

The private [installation harness](../platform/win98lab/) now has 32 host
storage tests. Before allocating a RAM working copy it requires enough disk
space to copy back even the unchanged image, retaining the 20-GiB reserve and
128-MiB margin. Later writes still require their own capacity and integrity
checks. The supplied Windows 98 installation remains stopped at its durable
file-copy checkpoint while disk headroom is insufficient. No native wrapper
or graphics test has been counted as passed.

The optional original probe CD contains `NTW32.DLL`, `NTWPROBE.EXE`,
`NTWRAP9X.VXD`, `NTWQUERY.EXE` and `NTWGPROB.EXE`, with instructions and hashes.
Its construction verifies the build receipts and re-extracts every file for
byte comparison. Media construction is preparation, not guest execution.

The new source/artifact package is named
`windows98-shizuku-second-edition-device-foundation-checkpoint.zip`.
Earlier ZIPs remain historical snapshots, including their exact older DLLs.
Package checks bind current sources, artifacts and host results to the retained
AHCI/xHCI guest evidence. Windows media, keys, guest installation disks, firmware
binaries and external implementation sources are excluded.

The next native driver steps remain ownership and version-correct CONFIGMG,
VMM and IOS contracts described in
[the integration note](NATIVE_DRIVER_INTEGRATION.md). WDDM/D3D/GPU drivers,
USB transfers, Win98 storage integration, physical hardware support and
UEFI-to-Windows GUI boot are not established by this checkpoint.
