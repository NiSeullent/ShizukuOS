# Windows 98 Shizuku's Second Edition

This is the independent platform development entry point. The product name is
**Windows 98 Shizuku's Second Edition**; subsystem names are NTWrapper9x,
NTWin32Wrapper9x, NTWDDMWrapper9x and ShizukuDOS. Windows 8.1/10/11-level
capability is the long-term target, not the current compatibility claim.

| Component | Current implementation | Required next target |
| --- | --- | --- |
| [NTWrapper9x](../ntwrapper/) | Original freestanding object/handle/event core | Win98 VxD/VMM binding, scheduler, memory, interrupts, I/O |
| [NTWin32Wrapper9x](../ntwin32/) | App-local PE32 provider and bounded import preparer; no KernelEx linkage | Clean Win98 static-import guest result, loader/Unicode/NT service families |
| [NTWDDMWrapper9x](../ntwddm/) | Original software framebuffer/surface/presentation core | Win98 display binding, GPU memory/scheduling, vendor miniports and D3D |
| [PCI-E](../drivers/pcie/) | Config transport, topology, ECAM/capabilities/resources/DMA constraints | CONFIGMG/VMM binding, interrupts, real storage/USB/GPU drivers |
| [ShizukuDOS UEFI](../shizukudos/uefi/) | Original x64 EFI program and post-firmware handoff | DOS/runtime/boot bridge capable of reaching Win98 GUI without CSM |

## Reproduce

The Linux host needs existing Python 3, GCC/Clang, make and i686/x86_64 MinGW.
No dependencies are installed by these commands.

```sh
python3 platform/build.py
python3 platform/test.py
make -C drivers/pcie test
make -C drivers/pcie sanitize CC=clang
make -C ntwddm test freestanding
make -C ntwddm sanitize CC=clang
python3 shizukudos/uefi/build.py
python3 shizukudos/uefi/test.py
python3 shizukudos/uefi/test_qemu.py --qemu /usr/libexec/qemu-kvm --firmware-code /usr/share/edk2/ovmf/OVMF_CODE.fd --firmware-vars /usr/share/edk2/ovmf/OVMF_VARS.fd
```

Generated artifacts, firmware variable copies, receipts and images stay in
ignored `build/` directories. The UEFI test attaches only its disposable files
with networking disabled. No script installs into the host, changes global
client settings, flashes firmware or updates an installed Windows system.

After those checks, `python3 platform/package.py` produces an allowlisted source
and artifact ZIP. `python3 platform/verify_package.py` extracts it into a separate
build directory, validates the file manifest, repeats the application/core host
tests and requires identical rebuilt DLL, probe, archive and EFI bytes. It does
not boot another guest or install the artifacts.

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
results belong in [the independent checkpoint](../docs/INDEPENDENT_PLATFORM_CHECKPOINT.md).
