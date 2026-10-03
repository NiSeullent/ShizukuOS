# Native laptop firmware discovery

This component retains the Windows98-on-ShizukuDOS product architecture. It
connects the existing portable ACPI fixed-power/EC descriptor parsers to the
Kernel64 firmware memory authority. It is a discovery step, not permission to
access an EC, I2C controller, power register or interrupt.

## Entry and ownership

`shz.laptop=probe` invokes `k64_laptop_firmware_init()` on the BSP after memory
initialization and before scheduling/interrupt enable. The initializer uses
`shz_cpu_firmware_prepare`, the existing bounded BIOS RSDP finder, and
`shz_cpu_firmware_finish_discovery` before parsing the directory. Its reader
translates unavailable retained memory into `SHZ_REVOKED`. No broad discovery
owner remains after success or failure. Retry clears the previous snapshot.

`k64_laptop_firmware_snapshot()` returns a kernel-only immutable descriptor
copy on success, otherwise NULL. Parsed register addresses are descriptions,
not resource grants. No application can supply a claimed mapping or owner.
The current authority supports the retained BIOS standalone path. The existing
Supervisor and direct-UEFI profiles refuse unsupported authority; no guessed
UEFI configuration-table pointer or arbitrary physical-memory read is added.

The native build compiles `laptop_protocols.c`, which includes the same
`drivers/shz_laptop/acpi.c` and `firmware.c` validated by driver host tests.
Canonical release custody must include those imported driver/common sources
and headers in its source union; the pre-existing kbuild directory inventory
alone does not include them.

## Directory contract

RSDP revision 0 uses RSDT. Revision 1 is unsupported. Revision >=2 prefers a
nonzero XSDT; an invalid or inaccessible advertised XSDT is an error, without
fallback to RSDT. Directory entries are bounded, nonzero and unique by physical
address. Repeated unrelated signatures such as SSDT are allowed. Duplicate
FADT/ECDT singleton tables are rejected. All directory members are checksum
validated, and FADT is required. ECDT is optional. Unknown table bodies are
streamed without executing AML. Output is unchanged on every parser error.

Limits are 128 root entries, 4096 bytes per RSDP or interpreted FADT/ECDT,
1 MiB per uninterpreted table, and 4 MiB of aggregate requested read bytes.
Headers, snapshot rereads and failed requests all consume the aggregate budget;
over-budget requests are refused before the callback. The allocation-free
parser retains copied bytes and checks headers for changes between reads. Its
trusted callback must provide a stable boot-time firmware view and reject
unavailable ranges. Header comparison is not a hardware snapshot mechanism for
firmware concurrently changed by SMM or another privileged writer.

The directory layout follows the official
[ACPI software programming model](https://uefi.org/specs/ACPI/6.6/05_ACPI_Software_Programming_Model.html).

## Checks and remaining integration

Run the portable production driver matrix and kernel adapter checks from the
actual worktree:

```sh
python3 drivers/shz_laptop/test.py --build-dir build/laptop-drivers --timeout 180
python3 shizukudos/tests/test_k64_laptop_firmware.py --out build/laptop-boot
python3 shizukudos/tests/test_k64_native_firmware.py --out build/laptop-owner
python3 shizukudos/tests/test_k64_smp_acpi.py --out build/laptop-rsdp
```

The adapter test executes real bootstrap and parser source with modeled
firmware-owner/scanner boundaries. Separate existing tests execute the retained
map and BIOS RSDP parser. GCC and Clang sanitizer checks, freestanding i486
checks, native Supervisor/standalone compilation and static stack records are
component evidence. They do not certify a guest boot or physical laptop.

Further native resource bindings must cover EC/I2C MMIO or ports, SCI routing,
AML evaluation, HID interrupt delivery, battery/thermal methods and suspend/
resume. Physical hardware, Windows98 service/UI integration, native direct-UEFI
firmware handoff and final installer ISO acceptance remain open. Discovery does
not claim modern-driver binary compatibility or complete ACPI implementation.
