# Observed UEFI storage origin

The production UEFI loader captures the actual `LoadedImage.DeviceHandle` used
for `OpenVolume`. Both kernel and initial archive are opened from that same root.
The observer obtains its DevicePath and BlockIO media, resolves the controller
through `LocateDevicePath(PCI_IO)` and `PCI_IO.GetLocation`, and finds exactly one
non-partition BlockIO handle whose physical path is the volume's ancestor.
No raw firmware hardware access, configuration-file identity or user approval
flag substitutes for a protocol observation.

Only bounded single-instance ACPI/PCI/SATA and ACPI/PCI/NVMe paths are supported.
SATA direct port/LUN and NVMe namespace/EUI are retained together with segment,
BDF, whole geometry and firmware media ID. Segment zero matches today's kernel
PCI enumerator. USB, RAID, vendor, ambiguous, malformed, unidentified and
multi-instance paths refuse. Firmware media IDs are not runtime generations.
Observation occurs before file reads, after complete reads and immediately before
ExitBootServices. A change or failure clears the capability-bearing handoff;
ordinary desktop startup remains possible. No firmware protocol is called after
ExitBootServices. This is provenance, not file authentication or a hotplug lease.

An independently versioned 144-byte tail extends bootinfo from 472 to 616 bytes.
All previous offsets and the IPC1.1 version remain unchanged. Older writers,
partial tails, unsupported formats, unknown devices and failed archive parsing
cannot bind install roles. Actual AHCI/NVMe drivers record their own PCI
locations and port/namespace/geometry; NVMe additionally supplies IDENTIFY EUI.
`k64_boot_storage_bind` runs after the actual archive parser and registry scan,
requires unique matching whole devices and calls the existing kernel authority.
No registry index, BIOS drive number or guessed RAM exemption is used. ATA serial
is not presently supplied by the native AHCI core, and generic firmware BlockIO
provides no serial; this increment does not claim durable media identity.

## ISO limitation and next concrete route

Native AHCI currently exposes ATA, not ATAPI. An observed boot CD can therefore
have a real, valid firmware locator with no registered Kernel64 block device.
The current binder **refuses** in that case. A host test of a modeled matching
ATA device is not proof of install authority from a real ISO.

Next, retain a kernel-owned immutable *external backing* record for the actual
observed readonly/removable CD and the accepted archive origin, even when its
physical whole is outside the runtime registry. Require every candidate target's
actual registered driver locator and exclude the same controller/port/LUN (or
namespace) independent of geometry. Missing or ambiguous origin must still
refuse; do not fabricate a boot blk pointer. Source import then needs a separately
typed immutable archive-range/fsnode capability, independent byte hash and
producer/lease custody. Existing raw `blk_authority_source_t` represents only
registered devices and cannot express that archive source. A kernel-owned
versioned process bridge must expose retained claimed I/O to `native_provider`.
An actual read-only ATAPI driver is an alternative; neither route is complete
in this increment. Installed Windows98, GOP, x64, persistence and applications
still require actual private-media acceptance.

## Verification

`python3 -B shizukudos/boot_profile/storage/tests/test_provenance.py` compiles
the actual observer with explicitly modeled firmware protocol responses.
`NATIVE_HOST_COMPILER=/usr/bin/clang` adds ASan/UBSan. Tests include truncation,
ambiguous ancestors, wrong PCI resolution, partition-only geometry, missing
media, changed media, unsupported paths, reserved NVMe identifiers and CD media.
The actual binder is also compiled into the production registry/authority host
test (`kernel64/host/test_blk_authority.py`). Kernel entry tests model disk and
archive boundaries; native AP calls fail if unexpectedly entered. No guest is
started by these tests.

Primary references:
- [UEFI Loaded Image](https://uefi.org/specs/UEFI/2.10/09_Protocols_EFI_Loaded_Image.html)
- [UEFI Device Path](https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html)
- [EDK2 public PCI IO declaration](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/PciIo.h)
- [EDK2 public Block IO declaration](https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/BlockIo.h)

The implementation uses independent minimal interface declarations, not linked
EDK2 implementation code. Protocol ABI offsets are statically asserted.
