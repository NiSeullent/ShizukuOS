# Common device lifecycle and native controller sessions

These are independently authored, freestanding C components. They extend the
existing PCIe/AHCI/xHCI cores; they do not replace the existing Kernel64 WDM/KMDF
providers or install a Windows98 driver. Actual Windows98 remains the product.

`device.h` supplies a common lifecycle for a **trusted, serialized** resource
owner. Bind requires a nonzero immutable owner and a strictly newer generation.
Admission creates one of16 tracked operation tickets. A completion must match
the generation, slot and unique sequence, so duplicate and stale completions
cannot retire another operation. Stop/suspend closes admission before invoking
any callback. In-flight work must complete before the real controller is closed.
Resume calls the real start callback after a successful suspend close.

Every start failure is followed by a real close attempt because a failing start
may already have published DMA. A failed close or revoked lease quarantines the
device. **Retain the device object, callback context and all core-owned backing**;
never reset/copy/rebind/free them to clear quarantine. Only a later close that
verifies ownership and actually drains/stops the controller permits release.
The optional release callback runs once after a completed stop, and never while
suspended or quarantined. The resource manager must serialize PnP, IRQ and worker
calls; this component does not supply locks or an IOMMU.

`native_sessions.h` binds this lifecycle to the actual production `ahci_open`,
read/write/flush/close and `xhci_open`, no-op/close paths. Wrappers validate the
owner's lease before and after each MMIO/sync boundary. Native allocation
success still transfers ownership when a grant is revoked, so shutdown can
retain or safely release that allocation according to the existing core's DMA
publication state. AHCI reads use a bounded private buffer and publish data
only after completion and final lease validation. Session/owned DMA aliases
are rejected before controller I/O. The session does not expose
an unverified virtual address as a DMA bus address.

The xHCI adapter currently wraps the existing controller command path. USB2 EP0
enumeration is implemented separately in `drivers/xhci_usb`; neither adapter
currently binds HID interrupt endpoints to native Windows98 USBD.

Run the combined actual C verification from the repository root:

```sh
python3 drivers/shz_laptop/test.py --build-dir /dev/shm/fd5c-laptop-driver-validation-20261002
```

The test invokes the existing whole AHCI/xHCI models plus the session tests,
injects stop failures and mid-operation lease revocation, and verifies retained
DMA and unchanged failed-read outputs. GCC, Clang and Clang ASan/UBSan runs plus
GCC/Clang freestanding i486 linked objects are recorded in `test-result.json`.
These are host component results; physical hardware and actual Win98 binding
remain separate validation gates.
