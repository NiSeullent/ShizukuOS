# Native platform checkpoint — 2026-09-27

Product: **Windows 98 Shizuku's Second Edition**. This checkpoint continues
the independently implemented platform after commit `0bb94e8`; the earlier
[foundation record](INDEPENDENT_PLATFORM_CHECKPOINT.md) remains historical.
Windows 8.1/10/11 capability remains the active engineering goal.

## Implemented and tested

### NTWin32Wrapper9x

`NTW32.DLL` now exports thirteen functions: seven SRW operations, four InitOnce
operations, observed-wrap `GetTickCount64` and scoped `GetProcAddress`.
Initialization callbacks cross a real cdecl/Win32 calling-convention adapter.
Dynamic lookup only redirects supported names for the real KERNEL32 module;
all other module handles, unknown names and ordinals retain native resolution.
The provider's own native imports cannot be self-routed by the preparer.

The DLL has the full product name in an original version resource. Its five
imports are native `GetTickCount`, `Sleep`, `GetModuleHandleA`, `GetProcAddress`
and `SetLastError`; it has no CRT or KernelEx dependency.

Host checks include 80,000 concurrent SRW updates, 11,691 InitOnce assertions
with 72 eight-thread rounds, all 65,536 ordinal lookup values, sanitizer runs,
and thirteen PE preparer checks. The separate [actual PE32 CPU/ABI
harness](../platform/abi32/) executes the linked DLL at its preferred address
and after relocation by 16 MiB. Its native KERNEL32 calls are mocked, so these
results establish CPU instructions, stack/callback conventions and relocation
behavior, **not Windows 98 loader or API acceptance**.
Each address passed 136 checks and 60 actual PE calls, including stack balance;
the relocated image applied 45 HIGHLOW fixups. Twelve malformed-image/packer
tests passed.

Limitations: observed tick wraps only; no SRW fairness; no abandoned InitOnce
thread/SEH recovery; exact native error-code parity remains unverified. API sets,
general NT loader behavior, dependency recursion, and broader modern application
support are not implemented by these thirteen exports.

### NTWrapper9x native VxD

The [original native binding](../ntwrapper/vxd/) builds `NTWRAP9X.VXD` as an LE
virtual device with DDB ordinal 1, dynamic initialization/exit control and a
synchronous Win32 query. Original ELF-to-LE packaging emits internal fixups;
host checks relocate the image at independent object bases and exercise the
actual i386 control assembly. The event/handle core runs during initialization.
Ten host test groups passed, including 234 bridge assertions under
address/undefined-behavior sanitizers.

The query checks private user ranges, locks pages through native VMM services,
verifies permissions and matching physical frames, copies a bounded reply and
releases aliases. This is a uniprocessor synchronous query interface. It does
not yet export a kernel scheduler, driver IRPs, app event handles or PCI drivers.
`NTWQUERY.EXE` is the native guest load/query probe. A host mock cannot establish
the real VMM service semantics or successful Windows 98 loading.

### ShizukuDOS UEFI to 32-bit kernel

The [new loader](../shizukudos/uefi32/) reserves a low-memory transition region,
checks writable/executable identity mappings, captures GOP and the firmware
memory map, exits boot services, installs its own GDT/exception tables and
leaves long mode for an original i486 payload. That payload executes NTWrapper9x
event/lease operations and NTWDDMWrapper9x software fill/present/fences.

Actual OVMF/KVM execution passed with one CPU, 256 MiB and no network. Independent
QEMU register inspection confirmed CPL0, 32-bit code selector `0x10`, paging off,
PAE/PCIDE off and LME/LMA off; the physical handoff and the screenshot agree.
Final run PID 3573498 stopped after 1.743 seconds. Thirty-nine host contract
checks and 512 exception-gate checks also passed, including sanitizers.

This still has no DOS interrupt/runtime environment, BIOS emulation, filesystem
boot chain or Windows 98 GUI boot. Fixed-address allocation and framebuffer
below 4 GiB are current prerequisites. Hardware IRQs remain disabled. NTWDDM
is currently software graphics, with no WDDM binary compatibility or GPU driver.

## Artifact identity

| File | SHA-256 |
| --- | --- |
| `NTW32.DLL` | `bb48a8380bb46ae410b0f7a6734c1d35c145fbc73dcfa8510828d4615c1735bd` |
| `NTWPROBE.EXE` | `5e2eb3185a991b2267957f09e14c7bf3fdbc31d9b4b68e5dda818bb7c7a7bed0` |
| `NTWRAP9X.VXD` | `aff7acf54cd0323fe4dce9aab7d93da16df7b8cf345220ee9d2dafa95b0bc537` |
| `NTWQUERY.EXE` | `7f8abf3e15d2d7838d921e0aed1e9efb0efd9d7a2d243f968b7b5eca5f71ddb0` |
| UEFI32 `BOOTX64.EFI` | `0973b5fead3a1fe9e300b8313cf9b898ccd0631bed32af6ce9c353409cc300c6` |
| i486 `payload.bin` | `f0405f6f253cb9ceb53533856977c472aabdb0698605a9c2536191fc62e42621` |
| `transition.bin` | `d2d1058d664f7cf9b0ad52fb075c54887fb907e1f9c7adf859ab2653abd260ed` |

VxD/probe build hashes and host results are in `ntwrapper/vxd/build/`;
the actual PE32 execution receipt is `platform/abi32/build/results.json`.
UEFI32 has a source-hash manifest, machine-readable guest/register evidence,
physical handoff dump and screenshot. The allowlisted native-checkpoint ZIP
contains independent sources/artifacts and these development receipts. The
packager checks hashes; the independent extraction/rebuild verifies exact bytes.
Absolute paths within historical receipts describe the original test host.

## Windows 98 installation evidence boundary

The user supplied [Korean Windows 98 SE OEM media](https://archive.org/details/X03-77968)
in reply to the request for authorized installation media. The 307,714,048-byte
download matched pinned SHA-256
`4c1b148bfd8aa9ffa702d6756ffa32064c49bb78c00d074225db5a0f302c0873`.
It is retained only in a private ignored development directory, outside Git
and source/binary packages. An archive listing is not a license assertion.

The existing server Win98 libvirt placeholder remains untouched. Installation
uses a separate private 2 GiB disk, one CPU, 128 MiB, SeaBIOS/i440fx and no
network. QEMU reported KVM enabled. Original CD boot and Korean text setup
reached private-disk partitioning and the installer's restart; these are
installation-stage results, not an installed Windows GUI or wrapper pass.
Native Windows 98 DLL/VxD
acceptance remains unverified until actual guest execution and receipts exist;
old upstream KernelEx evidence does not validate these new independent binaries.

## Remaining full-goal work

Windows 98 loader and VMM guest validation come next, followed by real memory,
IRQ/DMA/device lifetimes, a functional PCI-E controller slice, Win98 graphics
binding and broader independent API families. UEFI-to-Win98 additionally needs
DOS/boot services and hardware access beyond the proven mode transition.
Enumeration, hosted contract tests and proof screens are tracked separately
from usable drivers, application functionality and operating-system completion.
