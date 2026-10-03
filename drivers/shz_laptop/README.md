# Laptop protocol adapters

The implementation is portable freestanding C, with all hardware access routed
through explicit trusted callbacks. It provides reusable production protocol
paths, not a report that unknown hardware is installed or working. Actual
Windows98 retains its VMM/USER/GDI/Explorer environment.

| Component | Implemented behavior | Required native binding |
| --- | --- | --- |
| ACPI FADT/ECDT | Declared-length/checksum validation, supported GAS decoding, legacy and extended fixed registers, EC namespace path | Firmware table custody and verified MMIO/I/O resource mapping |
| Fixed ACPI power | SCI enable handshake, enabled event read, masked W1C acknowledgement, advertised reset register write | Serialized fixed-register owner and real monotonic clock |
| Embedded controller | RD_EC0x80, WR_EC0x81, QR_EC0x84, IBF/OBF handshake, one elapsed transaction budget | Exclusive EC resources, SCI/GPE routing and real clock |
| HID over I2C | Descriptor read, SET_POWER/RESET, new reset acknowledgement, report descriptor, input, stop/suspend/resume | Verified I2C/GPIO resources,7-bit controller transport, drain and interrupt provider |
| Mouse/touchpad | Descriptor-derived bit fields, signed relative motion, buttons, up to5 complete-frame contacts | Native Windows98 input bridge and device tests |
| Keyboard/sensors | Exact contiguous keyboard array selectors; arbitrary variable HID usage/value decode | Class consumers, sensor usage/unit interpretation and firmware policy |
| Battery/thermal/lid/AC | Typed `_STA`/`_BIF`/`_BST`, `_RTV`/`_TMP`/`_LID`/`_PSR` evaluation and checked decoding | Real AML evaluator or equally verified firmware provider |
| EC sensor | Checked per-device offset/scale/range, no guessed default EC offsets | Verified OEM binding |

Unsupported GAS encodings, HW-reduced ACPI, shared EC interfaces lacking a real
Global Lock provider, missing AML evaluation and unimplemented HID constructs
return explicit errors. The source does not guess `_S3`/`_S4` sleep values, fan
controls, battery EC offsets, Intel/AMD I2C MMIO layouts or device ownership.
Backlight/fan control, system suspend/hibernation, interrupt registration, AML
namespace enumeration, multitouch frame aggregation and gestures are remaining
native work. This is a common driver foundation, not binary compatibility with
every contemporary vendor driver.

All operations are serialized and callbacks bounded/non-reentrant. Ownership
validation must come from the kernel's actual resource manager, not caller
supplied identity fields. Providers keep context and backing alive through
quarantine, and enforce the documented elapsed timeout inside any blocking
transfer/evaluation. EC polling also detects frozen/reversed clocks; a partial
EC transaction poisons admission until an explicitly supplied recovery provider
resynchronizes the hardware. A failed EC close retains ownership. No force
flag can clear it.

HID transfer outputs use storage inside the retained device object. The I2C
provider must return with no detached DMA targeting caller buffers, even when
it retains its own internal DMA after an error. Before a new RESET the driver
discards a bounded amount of old input, so an earlier zero-length RESET reply
cannot authenticate the new reset. Stop closes input admission, drains the
real transport, sends SET_POWER(SLEEP) only through a validated command
descriptor, and drains again. Any failed stage quarantines the context.
Malformed/short/oversized inputs and revoked ownership publish no caller data.

The typed ACPI provider is not an AML interpreter. Without that provider the
battery/thermal/lid/power APIs return `SHZ_UNSUPPORTED`. Battery percentage is
known only when remaining/full capacity are valid and use the same reported
unit; current ACPI charge-limit state is preserved. Absolute temperature is
returned as integer milli-degrees Celsius. `_RTV` is checked first; relative
temperatures return unsupported. An absent optional namespace method must
return `SHZ_NOT_FOUND`, distinct from an unsupported evaluator. Raw HID sensor
values retain their usage identifiers; this component does not invent physical
units from unknown descriptors.

`firmware.h` supplies `shz_laptop_firmware_probe(read, context, rsdp_pa, out)`
for a trusted native firmware owner. It resolves revision0 RSDT or revision2+
XSDT/RSDT, validates the complete directory and calls the actual FADT/ECDT
parsers on retained, checksummed snapshots. Revision1 is unsupported. FADT is
required; absent ECDT succeeds with `has_ecdt=0`. Duplicate addresses and
duplicate FADT/ECDT signatures, malformed checksums/lengths and overflowing
physical ranges fail without changing any byte of `out`. A nonzero invalid
XSDT never falls back to RSDT. Other valid table signatures may repeat.

Discovery is bounded to128 root entries,4096-byte RSDP and FADT/ECDT snapshots,
and1MiB per unrelated table. Unrelated tables and RSDP extensions use128-byte
checksum chunks, so ordinary SSDTs larger than4096 bytes are supported. The4MiB
aggregate read budget counts every byte requested from the reader, including
header rereads and failed callbacks; an over-budget request is refused before
the callback. Negative `SHZ_*` reader errors propagate; positive failures map
to `SHZ_IO`. Exact-length zero-return reads must validate real ownership and
mapping before and after copying, remain synchronous and bounded, and retain
one stable firmware snapshot throughout discovery. This API does not acquire
hardware resources, enumerate AML devices, route interrupts or enable power.

Verification uses the actual production C, an asynchronous EC/I2C hardware
model, the existing complete native AHCI/xHCI models, ownership revocation,
timeout/recovery and malformed input cases:

```sh
python3 drivers/shz_laptop/test.py --build-dir /dev/shm/fd5c-laptop-driver-validation-20261002
```

The receipt records exact source hashes, three host compiler/sanitizer profiles,
linked freestanding i486 objects, runtime imports and stack frames. A native
binding must budget its worker stack from those frames plus its callback chain;
it must not assume a small legacy IRQ stack can host descriptor parsing.
Host checks do not establish actual Win98 installation, real hardware DMA,
sensor accuracy, power state transitions or security isolation.

`pointer_adapter.c` is the shared descriptor-derived HID class consumer. It
converts calibrated relative or single-contact absolute frames to atomic
movement/button publications, keeps fractional motion and reestablishes the
baseline after contact changes/lift. Extra buttons and multiple contacts remain
unsupported. Application class is retained per Report ID, so unrelated keyboard
or sensor reports cannot clear a touchpad contact or button state. Mixed
application reports and mismatched absolute/relative axes fail before input
publication. The Windows98 native Supervisor binds this same adapter through
`shizukudos/supervisor/native_win98/pointer_bridge.c` to its i8042 auxiliary
endpoint. NTDRV/class owners can use the same sink interface; no separate HID
decoder or unverified NT binary ABI is introduced. Driver success is named
`SHZ_DRIVER_OK` (still zero), separate from Supervisor IPC's `SHZ_OK` so both
public interfaces may be included in an actual native binding.

The native binding is explicit after `shz_hidi2c_open` succeeds with verified
I2C/GPIO resources. No discovered OEM/I2C resource provider currently calls it
on live hardware; actual Win98 mouse-driver/USER input and hardware tests are
still required. See the native bridge's `POINTER_BRIDGE.md` for that gate.

Protocol references used for this independently authored implementation:

- [UEFI ACPI6.6 software programming model: FADT/GAS/ECDT](https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html)
- [UEFI ACPI embedded-controller protocol](https://uefi.org/specs/ACPI/6.5/12_Embedded_Controller_Interface_Specification.html)
- [UEFI ACPI battery states](https://uefi.org/specs/ACPI/6.6/10_Power_Source_and_Power_Meter_Devices.html)
- [UEFI ACPI temperature semantics](https://uefi.org/specs/ACPI/6.6/11_Thermal_Management.html)
- [Microsoft HID-over-I2C enumeration and power](https://learn.microsoft.com/en-us/windows-hardware/drivers/hid/plug-and-play-support-and-power-management)
- [Microsoft required HID descriptors](https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/required-hid-descriptors)
- [USB HID1.11 report descriptor specification](https://www.usb.org/document-library/device-class-definition-hid-111)
