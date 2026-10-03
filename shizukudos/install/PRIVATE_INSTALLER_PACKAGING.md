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

The guard currently preserves the production loader/media 64MiB archive limit,
256MiB RAM limit and 256MiB per sealed source limit. It records exact archive
layout, rounded manifest/SIM PMM snapshots, heap metadata, 12MiB fixed kernel
heap and a conservative 32MiB OS-page allowance. This is a planning guard, not
proof of firmware memory availability. Snapshot payload pages already use PMM;
the heap stores only their page-pointer arrays and the bounded origin table.

A real Windows source is expected to exceed the 64MiB archive guard. Expanding
private installer capacity needs actual final native ESP/SIM and runtime member
measurement, a separate reviewed private firmware load profile, actual mapping
and usable-memory-map checks, and guest regression. Public defaults remain
unchanged. This increment does not build an ISO. A private ISO adapter must
consume the successful held-build receipt and exact pinned kernel/archive,
place the archive at `SHZ/SETUP/INSTALL.IMG`, use the existing zero-timeout
install BOOT.INI and direct interactive Syslinux entry, preserve observed physical
archive provenance, and keep all private outputs outside public distribution.

Host tests use explicit tiny modeled producer/firmware/PMM fixtures. They verify
actual SHZARC01 packer byte equality, actual C parser/namespace/sealed snapshots,
original-FD retention, copied byte/hash equality, malformed layouts, size guards,
closed/broken custody, compiled-profile selection and close-before-receipt
ordering. They certify no real Windows producer, ISO, installation or boot.
