# Private installer archive custody

`private_installer_package.py` connects the independently anchored release
builder to an installer archive without changing the target ESP, target
`WIN64.IMG`, or ordinary public component flow. Invoke only with a real saved
producer manifest and a fresh canonical private output directory outside Git:

```
python3 shizukudos/install/private_installer_package.py \
  --native-release-manifest /private/accepted/MANIFEST.JSON \
  --out /private/new-installer-build
```

Production admission still refuses when independently approved native producer
or genuine installed-source custody is absent. Caller JSON, hashes, approval
flags, and an earlier build receipt cannot create the live build capability.
The command compiles the actual installer-only release into `KERNEL64S.BIN`;
ordinary target kernels receive no installer record.

The build keeps the original manifest, encoded SIM, independently admitted
normal target runtime, source code, and compiler inputs in the generator's
single read-lease union. The capability reads those same descriptors until
compilation, copy, full member readback, source/tool recheck, full input SHA
verification and mandatory lease release/close finish. The successful kernel
receipt is written only afterward. A failure can leave diagnostic files in the
new private directory; it leaves no successful receipt.

The new `private-installer/INSTALL.IMG` preserves the target runtime members and
adds precisely `\SHZ\SETUP\NATIVE\MANIFEST.JSON` and
`\SHZ\SETUP\NATIVE\ESP.SIM`. The actual archive parser resolves these nodes as
readonly original-initrd members. Snapshot custody, process ownership, native
release admission, target review/exclusions, generation, ERASE confirmation,
claim and guarded I/O remain the responsibility of the existing kernel/provider.
Packaging does not issue runtime authority. Reusing an installer archive as the
normal target runtime is refused to prevent a target/consumer source cycle.

The archive is streamed through a private 0700 directory and a fresh 0600 file;
no whole SIM/archive buffer is allocated in the host. Full bounded readback
matches every member against its original held descriptor. The completed
archive and actual newly built standalone kernel/stub are themselves leased and
pinned before successful receipt finalization.

Public builds retain the 64MiB archive, 256MiB RAM and 256MiB sealed-source
limits. A live independently admitted manifest/SIM/normal-runtime union can
construct `native_capacity_profile.CapacityProfile`. It measures the actual
member table and encoded byte extent, rounds source/archive budgets to MiB,
and rounds RAM to 2MiB after including archive placement, both page-backed
sealed snapshots and 32MiB OS headroom. Inputs exceeding the 512MiB wire ceiling
or the actual 1GiB identity boot mapping are refused. No caller-provided profile
object, compiler flag or metadata creates source/device authority.

The three measured private compiler definitions apply only to the installer
standalone kernel and its private EFI loader. Kernel receipts capture the
profile and public source/tool bytes, including the actual MinGW compiler and
its cc1/as/ld children in the explicit private lane. The public target kernel
and target runtime receive no installer release or increased allocation limit.
`setup_native_abi.h` remains version 1 and 440 bytes; CAP advertises the actual
compiled source limit. Runtime accepts bounded negotiation and uses it for both
release INFO and OPEN replies. Release state 0 permits existing public component
flow; state 1 means an available compiled record; state 2 means configured but
invalid and refuses native initialization without legacy fallback. Unknown
states also refuse.

During the same live finalizer custody, build the loader with
`supervisor.build.build_loader(payload, private_profile=release['profile'])`
after the actual AP trampoline build. Use a fresh canonical 0700 directory
outside Git; generated translation-unit inputs and the resulting EFI binary
remain held. The private loader embeds the exact computed profile marker.
`shizuku_se_media.efi_members(..., mode='install', menu_timeout=0,
private_native_profile=release['profile'])` verifies that marker and the full
SHA/extent of the already retained INSTALL.IMG. The existing
`boot_menu(..., setup=True, direct_install=True)` supplies the interactive BIOS
entry without a menu. Media construction must finish inside this same finalizer,
before admission closes; successful serialized receipts cannot recreate it.

This provides opt-in loader/member adapters, not a finished private ISO builder.
The final ISO orchestrator still must supply independently verified upstream
boot components, complete license/source archives, copy every member from its
held inputs and perform full ISO readback. The native UEFI loader must also
verify the actual firmware usable-memory map and retain observed physical
archive provenance. BIOS currently lacks the required independently observed
storage backing, so native source opening refuses there; no guessed BIOS drive
mapping or permission exemption is provided. Host capacity tests do not certify
firmware memory availability, real Windows producer approval, installation or
Windows 98 boot on ShizukuDOS.

Host tests use explicit tiny modeled producer/firmware/PMM fixtures. They verify
actual SHZARC01 packer byte equality, actual C parser/namespace/sealed snapshots,
original-FD retention, copied byte/hash equality, malformed layouts, size guards,
closed/broken custody, compiled-profile selection and close-before-receipt
ordering. They certify no real Windows producer, ISO, installation or boot.
