# NTWrapper9x PCI/PCIe core

This is an original, portable C component of **Windows 98 Shizuku's Second
Edition**. It provides discovery and validation contracts for future NTWrapper9x
bus ownership. It is not an installed Windows 98 PCI bus driver. The code neither
imports KernelEx/Wine/ReactOS implementations nor issues hardware I/O itself.

## Implemented contracts

| Interface | Behavior |
| --- | --- |
| `ntw_pci_read` | Injected 8/16/32-bit configuration reads, BDF/alignment/256-or-4096-byte range checks, explicit transport failures, output preservation on failure. An absent function is a successful read returning vendor `0xffff`; a failed read is never treated as absence. |
| `ntw_pci_parse_mcfg` | Byte-wise, endian-independent revision-1 MCFG parsing; signature, length, checksum, reserved fields, bus interval, overflow, physical-window overlap and same-segment bus overlap checks. Validates before writing any output. At most 256 allocations, with bounded pairwise overlap checks. |
| `ntw_pci_ecam_address` | Validated 64-bit physical-address calculation using the MCFG **bus-zero-relative** base, including allocations whose first bus is nonzero. Does not dereference or map the result. |
| `ntw_pci_scan` | Breadth-first discovery through firmware-configured type-1 PCI bridges, function-zero/multifunction handling, segment propagation, bus/function budgets, ancestor bounds, duplicate-target and sibling-window rejection. Disabled bridges are reported without traversal. |
| `ntw_pci_classify` | Exact AHCI `01:06:01`, xHCI `0c:03:30`, NVMe `01:08:02`, display class `03`, and PCI bridge `06:04` recognition. A classification is a binding candidate, not a working driver. |
| `ntw_pci_capabilities` | Conventional lists, including the CardBus pointer location, and PCIe extended lists. Rejects bad offsets, malformed headers and cycles; checks the entire list even when output capacity is exhausted. Supports a count-only query and all 960 extended header positions. |
| `ntw_pci_decode_bar` | Decodes I/O and 20/32/64-bit memory BAR snapshots, prefetchability and consumed slots; rejects reserved encodings, truncated 64-bit pairs and requests for an upper half. An address of zero is unassigned, not proof of an absent BAR. |
| `ntw_pci_bar_resource` | Checks externally supplied size, power-of-two alignment, address-width limits, inclusive end overflow, and a caller-supplied bus resource window. Never infers BAR size from its base. |
| `ntw_pci_dma_segment` | Computes a valid initial segment under device address-mask, alignment, maximum segment-size and boundary constraints. A range above a 32-bit DMA mask is rejected; a crossing range is shortened to the representable prefix. Does not perform DMA mapping or promise a bounce buffer. |

The API is in `include/ntw_pcie.h`; compile `src/ntw_pcie.c` into the owning
environment. There is no heap allocation, OS API dependency, inline port I/O, or
global mutable state. The source needs fixed-width C integer types. Compiler
generated memory-clear helpers may still need the freestanding runtime's own
implementation.

The owner supplies a serialized configuration transport and ensures topology
stability, readable table-buffer lifetime, and nonoverlapping input/output buffers.
The callback must supply exactly the requested read or an error. A 256-byte legacy
transport cannot read extended capabilities. An all-ones first extended header
means no accessible extended list, not proof that the function implements none.
The scanner accepts already numbered, increasing secondary bus intervals; it does
not repair firmware topology. It starts at one explicitly supplied root per call;
MCFG allocation starts are **not** automatically all PCI root buses. Returned
capability arrays and scan results are partial on failure and must not authorize
device binding. Visitors should only collect discovery data; hardware activation
must wait until the full scan and resource validation succeed.

MCFG acceptance requires at least 1 MiB base alignment. This validates the generic
per-bus ECAM arithmetic, not all chipset-specific ECAM quirks or physical-address
limits. The owner must additionally validate the actual address width and reserved
firmware resources before mapping an ECAM window. Parsing a table alone does not
reserve that region or confer ownership.

## Build and host validation

From the repository root:

```sh
make -C drivers/pcie test
make -C drivers/pcie sanitize CC=clang
```

These commands write only ignored files under `drivers/pcie/build/` and execute
mock-memory tests. No device files, PCI configuration ports, physical memory,
services, network downloads, or installed Windows guests are accessed.

On 2026-09-27, GCC 14.3.1 passed strict C11 compilation with
`-Wall -Wextra -Werror -Wpedantic -Wconversion -Wshadow`; Clang 21.1.8 passed the
same suite under AddressSanitizer and UndefinedBehaviorSanitizer. The initial
suite reports **38,766 assertions**, including mock callback invariants, every
read-failure position in a representative topology/capability traversal, and
4,096 deterministic malformed-input mutations. The count is not a device or
hardware-compatibility count. This host's GCC sanitizer link failed because its
`libasan.so.8.0.0`/`libubsan.so.1.0.0` targets were absent; installed Clang runtimes
were used successfully without installing packages.

The tests cover nested bridges, multifunction function 7, a hidden function on a
single-function device, disabled bridges, visitor stop, enumeration budgets,
invalid/overlapping bridge intervals, truncated and corrupted MCFG tables,
nonzero-start-bus arithmetic, overlapping ECAM address ranges, 64-bit address
overflow, conventional/extended cycles and malformed tails, 4 KiB configuration
boundaries, BAR upper-half and width handling, and DMA segments at 4 GiB and
`UINT64_MAX` boundaries. Sanitizer results establish host memory/arithmetic
behavior for these inputs, not Win98 execution or physical device compatibility.

## Integration still required

- Windows 98 VxD loading, ring-0 configuration access, CONFIGMG device nodes and
  resource arbitration, root discovery from ACPI `_SEG`/`_BBN`/`_CRS`, mapping and
  reservation of ECAM, and coordination with the existing PCI enumerator.
- BAR sizing while decoding is safely disabled, bridge apertures, address
  translation, rebalance/assignment, hotplug/removal, power transitions, ARI and
  SR-IOV. The scanner follows existing firmware assignments only.
- INTx routing (`_PRT`), IRQ ownership, interrupt handlers, MSI/MSI-X programming,
  synchronization and teardown. Finding a capability header does not implement
  its interrupt or device behavior.
- Locked DMA pages, IOMMU/physical-to-device translation, bounce buffers for
  narrower devices, cache coherency, lifetime management and bus-master enable.
  Segment validation is only one prerequisite.
- Actual AHCI command lists/FIS/interrupt completion, xHCI rings/contexts/USB
  transfers, NVMe admin and I/O queues/namespaces, and vendor GPU command submission.
- Installed Win98 guest and physical PCIe-device tests. Any separate UEFI/QEMU
  discovery smoke test demonstrates only that independent environment; it does
  not establish CONFIGMG binding or functioning Windows 98 storage/USB/graphics.

## Source lineage and references

All code and tests in this directory are newly authored, **GPL-2.0-only**, under
the repository's `LICENSE`. No third-party implementation, SDK headers or binary
driver has been copied. Public register layouts and documented contracts informed
the interfaces and tests:

- [UEFI 2.10, PCI Bus Support](https://uefi.org/specs/UEFI/2.10/14_Protocols_PCI_Bus_Support.html): separation of PCI bus ownership, BAR resources and DMA services.
- [Linux kernel documentation, ACPI considerations for PCI host bridges](https://docs.kernel.org/PCI/acpi-info.html): bus-zero-relative MCFG bases, ACPI root resources and why MCFG alone does not reserve address space. Documentation only; no Linux implementation was reused.
- [Microsoft, accessing PCI device configuration space](https://learn.microsoft.com/en-us/windows-hardware/drivers/pci/accessing-pci-device-configuration-space): configuration-space ownership and unavailable extended reads.
- [Microsoft, PCIe extended capability header](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_pci_express_enhanced_capability_header): ID, version and next-offset fields.
- [PCI-SIG, SATA class code](https://pcisig.com/PCIConventional/ECN/Base/SATAClassCode): exact AHCI class/interface match.
- [Intel, xHCI specification](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf), section 5.2.2: xHCI class/interface fields.
- [NVM Express 1.3b](https://nvmexpress.org/wp-content/uploads/NVM-Express-1_3b-2018.05.04-ratified.pdf), section 2.1.5: NVMe class/interface fields.
- [PCI-SIG code and ID specification listing](https://pcisig.com/PCIExpress/Spec/Base/CodeandIDAssignment_1.17): class/capability assignment authority.

These references describe interfaces, not a claim of PCI-SIG compliance or
certification. Win98 bindings must preserve their own source/license provenance.
