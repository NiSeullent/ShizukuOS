# Windows 98 Shizuku's Second Edition

This is the independent platform development entry point. The product name is
**Windows 98 Shizuku's Second Edition**; subsystem names are NTWrapper9x,
NTWin32Wrapper9x, NTWDDMWrapper9x and ShizukuDOS. Windows 8.1/10/11-level
capability is the long-term target, not the current compatibility claim.

| Component | Current implementation | Required next target |
| --- | --- | --- |
| [NTWrapper9x](../ntwrapper/) | Original object/handle/event core, native LE VxD and bounded VMM query bridge | Windows 98 guest load/query, scheduler, memory, interrupts, I/O |
| [NTWin32Wrapper9x](../ntwin32/) | App-local PE32 provider with 15 exports, original UTF-8 conversion and bounded import preparer; no KernelEx linkage | Clean Win98 static-import guest result, wider NLS/loader/NT service families |
| [NTWDDMWrapper9x](../ntwddm/) | Original software framebuffer/surface/presentation core | Win98 display binding, GPU memory/scheduling, vendor miniports and D3D |
| [PCI-E](../drivers/pcie/) | Config transport, topology, ECAM/capabilities/resources/DMA constraints | CONFIGMG/VMM binding, interrupts, real storage/USB/GPU drivers |
| [AHCI storage](../drivers/ahci_native/) | Original read-only core; post-UEFI 32-bit DMA reads against the disposable QEMU ICH9 fixture | Windows 98 driver binding, physical controllers, reset/recovery, interrupts and wider I/O |
| [ShizukuDOS UEFI](../shizukudos/uefi32/) | Original EFI program, verified transition from x64 firmware to own 32-bit protected-mode kernel | DOS/runtime/boot bridge capable of reaching Win98 GUI without CSM |

## Reproduce

The Linux host needs existing Python 3, GCC/Clang, make and i686/x86_64 MinGW.
No dependencies are installed by these commands.

```sh
python3 platform/build.py
python3 platform/test.py
python3 platform/abi32/build.py
python3 platform/abi32/test_packer.py
python3 ntwrapper/vxd/build.py
python3 ntwrapper/vxd/test.py
make -C drivers/pcie test
make -C drivers/pcie sanitize CC=clang
make -C ntwddm test freestanding
make -C ntwddm sanitize CC=clang
python3 shizukudos/uefi/build.py
python3 shizukudos/uefi/test.py
python3 shizukudos/uefi/test_qemu.py --qemu /usr/libexec/qemu-kvm --firmware-code /usr/share/edk2/ovmf/OVMF_CODE.fd --firmware-vars /usr/share/edk2/ovmf/OVMF_VARS.fd
python3 shizukudos/uefi32/build.py
python3 shizukudos/uefi32/test.py
python3 shizukudos/uefi32/test_qemu.py --qemu /usr/libexec/qemu-kvm --firmware-code /usr/share/edk2/ovmf/OVMF_CODE.fd --firmware-vars /usr/share/edk2/ovmf/OVMF_VARS.fd
python3 drivers/ahci_native/test.py
python3 shizukudos/uefi_ahci/build.py
python3 shizukudos/uefi_ahci/test.py
python3 shizukudos/uefi_ahci/test_qemu.py
```

Generated artifacts, firmware variable copies, receipts and images stay in
ignored `build/` directories. The UEFI test attaches only its disposable files
with networking disabled. No script installs into the host, changes global
client settings, flashes firmware or updates an installed Windows system.

After those checks, `python3 platform/package.py` produces
`build/windows98-shizuku-second-edition-storage-utf-checkpoint.zip`.
Earlier checkpoint ZIPs are preserved. The allowlist includes original sources,
the [storage/UTF checkpoint](../docs/STORAGE_UTF_CHECKPOINT.md), build artifacts,
and the source-bound host and guest evidence. It excludes firmware, Windows
media, ESP/test disk images, and guest installation files.

Publication requires the AHCI host sanitizer/freestanding results, clock tests,
matching current EFI/payload/transition bytes, and the exact build receipt used
by a stopped KVM guest. The guest must have completed both reads, verified 1024
bytes, closed successfully and released DMA. Six evidence-file hashes are
checked; physical proof/handoff records, CPU register data and the final DMA
sector are compared with the receipt. The disposable disk must still match
its unchanged before/after hash. Unicode host evidence is bound to the platform
test receipt. Any validated input changing before publication rejects the ZIP.

`python3 platform/verify_package.py` extracts a snapshot of that ZIP into a
separate build directory, validates its file manifest, and runs nine build/host
test commands, including the actual PE32 ABI harness, original AHCI model tests,
and lab clock tests. It requires byte-identical results for twelve artifacts:
the DLL, two probes, kernel archive, VxD, three EFI images, and the two 32-bit
payload/transition pairs. It does not boot a guest or install the artifacts.
Replacing the input ZIP during verification prevents publication of a rebuild
receipt. These checks establish reproducibility; they do not extend the guest
or physical-hardware compatibility claims recorded in the checkpoint.

## Engineering sequence and completion gates

1. **Independent foundations:** buildable ABI contracts, bounded parsing,
   lifetime/concurrency, firmware exit and real software presentation.
2. **Native Win98 binding:** clean licensed Win98 SE base, disposable overlay,
   VxD loader/control/DDB, native app import behavior, shutdown/reboot recovery.
3. **Kernel services:** physical memory ownership, VMM mapping, IRQ routing,
   DMA, work/timeout/cancellation queues, process/thread isolation and I/O.
4. **PCI-E device vertical slices:** one controller each for storage, xHCI,
   networking and display; reset/ownership, queues, interrupts, error recovery,
   suspend/resume and real-device verification. Enumeration alone is not a driver.
5. **Graphics:** Win98 GDI/display adapter, present/scanout, GPU buffer residency,
   context and scheduling, Direct3D runtime and user/kernel driver interfaces.
   Existing NT WDDM binaries cannot run merely because the module is named WDDM.
6. **App families:** keep the complete catalogue in `porting/`; establish native
   loader, Unicode, file/registry, NT synchronization, COM, network and graphics
   prerequisites, then move complete families into independent providers.
7. **UEFI-to-Win98:** memory ownership, ACPI/PCI enumeration, storage, DOS 7.1
   contracts and protected-mode handoff. An EFI proof screen is not DOS COM
   compatibility or Windows GUI boot.
8. **Acceptance:** exact binaries and hashes, Win98 cold boot and recovery,
   target-app functionality, actual driver/device evidence and full API-surface
   definitions. Windows 11 x64 applications need a real 64-bit execution solution;
   import routing alone cannot provide it.

Public interface sources are linked beside the relevant code. New core
libraries use original implementations. Historical third-party attributions
remain intact, but those files are excluded from this independent build.
The existing `build.ps1`/`src/` route is a historical KernelEx regression path.

## Environment observed on 2026-09-27

The reference baseline is Git commit `1d54ca7`. Host compilers and OVMF are
present. The registered Win98 VM is an empty placeholder, with no installed OS;
it has not been modified or booted. Old Windows-host VM results in `vm/README.md`
are reference history and do not validate these new components. Current exact
results belong in [the storage/UTF checkpoint](../docs/STORAGE_UTF_CHECKPOINT.md).
The [native checkpoint](../docs/NATIVE_PLATFORM_CHECKPOINT.md) and
[first independent checkpoint](../docs/INDEPENDENT_PLATFORM_CHECKPOINT.md)
are retained as historical evidence. The user has since supplied the same
Korean OEM ISO for this server; its SHA-256 was verified before preparing a
separate isolated installation experiment. Private media and guest disks remain
outside every source/artifact package.
