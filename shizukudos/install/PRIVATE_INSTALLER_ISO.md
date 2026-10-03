# Private native installer ISO

`private_installer_iso.py` uses `kbuild.build_all`'s existing live finalizer. The
original admitted manifest, encoded ESP.SIM and normal target WIN64 remain under
the same read-lease union while the actual private installer kernel is compiled,
the INSTALL archive is streamed and fully compared, and the private AP/vBIOS/
Supervisor/EFI loader is compiled. Generated inputs and completed EFI remain
held. The target WIN64 and target ESP are never replaced by the consumer archive.

```
python3 shizukudos/install/private_installer_iso.py \
  --native-release-manifest /private/accepted/MANIFEST.JSON \
  --out /var/tmp/new-private-installer \
  --upstream-cache /public/immutable/build/upstream \
  --native-bios-producer-receipt /public/source-built-bios/result.json
```

Every output directory is fresh, canonical, owned 0700 and outside Git. No
package download, installation, VM launch or publication occurs. Original
Syslinux .deb/source packages must already exist in the cache and match exact
public upstream-manifest SHA pins. Debian ar/data tar members are decoded from
the original retained FD, without trusting an extracted cache or running package
scripts. Current clean Git source and pinned upstream/submodule Git objects,
licences, patches, generated private release C and measured compiler definitions
are included as corresponding source inputs. Compiler and media tools participate
in the actual private kernel source/tool receipt.

Public component limits remain unchanged. A typed live CapacityProfile is
required; serialized receipts or CLI flags cannot recover this capability.
Private EFI members require the exact compiled profile marker and the retained
INSTALL extent/SHA. The native path omits CSM entirely. UEFI BOOT.INI is direct
interactive mode with zero timeout; the BIOS Syslinux entry also has no menu,
but native source authority currently refuses BIOS storage backing. An EFI
image smaller than 16MiB is rounded to the observed minimum FAT16 geometry on
this host; real Windows source images are substantially larger.

Before media allocation, available host disk/RAM are observed. The bound counts
bytes-oriented members, FAT scratch/image, stage, ISO and extraction readback,
retaining the 17GiB disk reserve. The actual xorriso hybrid writer is followed by
complete ISO member-list and byte comparison, El Torito/MBR/GPT checks, catalogue
EFI-image comparison, every FAT member readback and fsck. The original admission
FDs remain live through these checks. Mandatory custody close succeeds before
kbuild emits a successful receipt; diagnostic partial files never imply success.

Production still refuses without independently approved native/genuine inputs.
The separately ROOT-owned `native_release_policy.NATIVE_SYSTEM_BIOS_SOURCE`
also defaults absent. It must independently anchor actual native SEABIOS bytes,
the source-builder receipt, source commit, source/tool map digests and original
source archive. The receipt follows
`shizukuos.actual-source-built-system-bios.v1`:

- `artifact`, `source_archive`: actual pinned file rows.
- `source_root` and `sources_sha256`: absolute producer root and relative/absolute
  input paths, including generated configuration and producer source.
- `tools_sha256`: actual tool paths and SHA digests.
- `license_files`: original pinned licence rows (dictionary or list).

The independent policy stores `artifact`, `receipt`, `source_archive` as
`(bytes, SHA256)` tuples plus `source_commit`, `source_map_sha256` and
`tool_map_sha256`. The command's receipt path is only discovery. Actual native
BIOS bytes, every source/tool input, source archive and licence are read and held
against those independent anchors. An old packaged system BIOS cannot claim
correspondence to merely similar pinned source. This module never edits or
issues producer policy.

Host controls build a real small xorriso/FAT image with an actual EFI compiler
and pinned Syslinux, using explicitly modeled non-Windows kernel/archive inputs.
They establish only pack/copy/readback behavior. No real Windows source admission,
installation, firmware memory availability or Windows 98 boot is certified.
