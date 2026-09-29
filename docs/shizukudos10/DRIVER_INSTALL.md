# ShizukuDOS 10: installing Windows driver packages

This page describes how a Windows driver package (an INF plus the `.sys`/`.cat`/`.dll` files it names) gets from a
medium into the ShizukuDOS 10 system, and what exists today. Driver packages are always supplied by the user:
this repository never ships, downloads or redistributes Microsoft or Intel drivers. The test inputs are drivers built
from ReactOS sources (see [DRIVER_CORPUS.md](DRIVER_CORPUS.md)) and synthetic INFs.

## Pieces

| piece | where | what it does |
|---|---|---|
| `inf.py` | `shizukudos/ntdrv/inf.py` | reference implementation of the INF rules (host, Python) |
| `store.py` | `shizukudos/ntdrv/store.py` | builds the media driver store `\DRIVERS\<package>\` + index (host) |
| `shzinf.c` | `shizukudos/win64/apps/shzpnp/` | the same INF rules in portable C, used by `shzpnp` |
| `shzpnp` | `\SHZ\SYS64\SHZPNP.EXE` | Win64 CLI in the running system: add-driver, enum, match, load |
| `T_SHZPNP.EXE` | `shizukudos/win64/tests/t_shzpnp.c` | runs `shzpnp` on Kernel64 and checks the files and registry it changed |

`shizukudos/ntdrv/tests/test_shzpnp.py` compiles `shzinf.c` for the host and compares it with `inf.py`, line for line,
on the synthetic INFs and on every INF of the ReactOS and virtio-win trees (136 files; 570 comparisons, all
identical at the time of writing).

## Media layout

```
\DRIVERS\INDEX.TXT          index read by shzpnp (UTF-8, tab-separated, CRLF)
\DRIVERS\INDEX.JSON         the same data for host tools
\DRIVERS\<package>\...      the package exactly as supplied: same names, same bytes, same sub-directories
```

`store.py add <package-dir> [--name N]` copies the directory byte for byte (verified by SHA-256 after the copy), then
re-indexes; `store.py verify` re-checks every recorded hash. Package names are 1-64 characters `A-Z a-z 0-9 _ . -`
and unique ignoring case (the medium's file systems are case-insensitive); no path component may exceed 95 bytes
(the Kernel64 file system limit). The default root is `build/shizukudos/ntdrv/media`; the ISO builder places
`<root>/DRIVERS` on the medium as `\DRIVERS`.

Index records (see the `store.py` docstring for the exact columns):

```
SHZDRV-INDEX 1 NTamd64.10.0...22631
PKG   name files bytes
INF   name inf-path class classguid provider driverver catalog
MODEL name inf-path rules install ddinstall sig feature service binary kmdf hwid compat;... description
FILE  name path size sha256
MISS  name inf-path file          a file the INF copies that is not in the package
```

`rules` is `W` when the model applies under Windows x64 rules and `L` when only the ReactOS-style fallback reaches it
(see below).

## INF rules implemented

Syntax: sections (repeated sections merge), `key = value, value`, `;` comments outside quotes, `\` line
continuation, `"..."` with `""` escapes, `%token%` substitution from `[Strings]` with the `[Strings.0409]` table
overriding it, `%%` as a literal percent, undefined tokens and `%12%`-style dirids left literal; UTF-16 (either BOM),
UTF-8 (with or without BOM) and, when the bytes are not UTF-8, Windows-1252.

Selection, per Microsoft's "INF Manufacturer Section":

* The target is NTamd64 10.0 build 22631, workstation (the version Kernel64 reports in the registry and the PEB).
* A `TargetOSVersion` decoration `NT[arch][.major[.minor[.producttype[.suitemask[.build]]]]]` applies when its arch
  matches, its version is not higher than the target's, product type and suite mask match, and a build number is
  not higher than the target's when major.minor are equal. The applicable decoration with the highest version wins.
* On amd64 the decoration must name the architecture ("Architecture must be specified ... for non-x86"), and an
  undecorated Models section is not used. ReactOS's own INFs rely on its lenient setupapi and use undecorated
  sections; `--legacy` (store.py `L` rules, `shzpnp --legacy`) reproduces that leniency and is never the default.
* DDInstall resolution: `X.NTamd64`, then `X.NT`, then `X`; the `.Services`, `.HW`, `.CoInstallers`, `.Wdf`
  extensions follow the decoration that was found, then fall back. `Needs=` pulls in other sections' CopyFiles,
  AddReg, services and HW AddReg. `FeatureScore`, `DriverVer` overrides and `KmdfService`/`KmdfLibraryVersion`
  are recorded.

Ranking, per "How Windows Ranks Drivers" and "Identifier Score (Windows Vista and later)": rank `0xSSGGTHHH`, lower is
better.

* `THHH` identifier score, positions zero-based: device hardware ID = INF hardware ID: `0x0000 + i`; device hardware
  ID = INF compatible ID: `0x1000 + i`; device compatible ID = INF hardware ID: `0x2000 + j`; compatible =
  compatible: `0x3000 + j + k*0x100` (`k` = position of the compatible ID in the INF Models entry).
* `GG` = `FeatureScore` (default `0xFF`). A lower feature score outranks a better identifier match; the tests use
  exactly that case.
* `SS` signature score. Windows ranks trusted-signed packages first, then unsigned packages whose DDInstall has an
  `.NT` extension, then unsigned undecorated ones; Microsoft does not publish the byte values. ShizukuDOS verifies no
  signatures (catalog files are copied, not checked), so every package is "unsigned": `0x80` (decorated DDInstall)
  or `0xC0` (undecorated). Only the order of these two values is Windows'.
* Equal ranks: newest `DriverVer` date wins, then the highest version.

PCI identifiers are generated in Microsoft's documented order ("Identifiers for PCI devices"), `SUBSYS_ssssvvvv`
from PCI configuration dword 0x2C: six hardware IDs (`&SUBSYS_&REV_`, `&SUBSYS_`, `&REV_`, plain, `&CC_ccsspp`,
`&CC_ccss`) and the compatible IDs (`&REV_`, plain, `VEN&CC_` x2, `VEN_`, `CC_` x2; the PCI Express `&DT_` forms in
`inf.py` only).

Directory ids: `%10%` = `C:\SHZ` (SystemRoot), `%11%` = `C:\SHZ\SYS64` (the system directory
`GetSystemDirectory` returns), `%12%` = `C:\SHZ\SYS64\DRIVERS`, `%17%` = `C:\SHZ\INF`, `%13%` / `%1%` = the
package's directory in the local driver store, `%18%` HELP, `%20%` FONTS, `%24%` `C:\`, `%25%` `C:\SHZ\SYSTEM`.
Other dirids are refused with a message rather than guessed.

## shzpnp

```
shzpnp add-driver <inf> [--install] [--device <id>]... [--legacy]
shzpnp enum [--log <file>]
shzpnp match [<device>...] [--store <dir>] [--all] [--legacy]
shzpnp load <service>
```

Devices are `VVVV:DDDD[:SSSSSSSS[:RR[:CCSSPP]]]` (hex, `-` for unknown), a `PCI\VEN_...` hardware ID, or a Kernel64
boot-log line `K64 pci: b:d.f vvvv:dddd class ccsspp irq n`.

**add-driver** first stages the package like `pnputil /add-driver`: the `[Version]` signature must be `$Windows NT$`
or `$Chicago$`; at least one Models section must apply; the INF and every file its applicable DDInstall sections copy
(found through `SourceDisksNames`/`SourceDisksFiles`, else next to the INF) are copied to
`C:\SHZ\INF\FileRepository\<inf>_amd64_<crc32>\`; a missing file fails the whole add. The INF is published as
`C:\SHZ\INF\oem<N>.inf` (the same package added again keeps its number) and recorded under
`HKLM\SYSTEM\DriverDatabase\DriverInfFiles\oem<N>.inf` and `...\DriverPackages\<id>` (InfName, OriginalInf,
StorePath, Provider, Class, ClassGuid, DriverVer, UndecoratedModels). Windows keeps this database in its own
DRIVERS hive; here it lives in SYSTEM because Kernel64 has one volatile registry.

With `--install` (implied by `--device`), every device — from `--device`, else from the Enum tree — is matched
against the INF's models, and the best-ranked model is installed the way SetupAPI installs a device:

1. CopyFiles of the DDInstall section to their DestinationDirs.
2. Each AddService creates `HKLM\SYSTEM\CurrentControlSet\Services\<name>`: `Type`, `Start`, `ErrorControl`,
   `ImagePath` (REG_EXPAND_SZ; `%12%\x.sys` becomes `\SystemRoot\SYS64\DRIVERS\x.sys`), `DisplayName`,
   `Description`, `Group`, `DependOnService`, then the service's AddReg with HKR = the service key.
3. A software key `HKLM\SYSTEM\CurrentControlSet\Control\Class\{ClassGUID}\<NNNN>`: `DriverDesc`, `ProviderName`,
   `DriverVersion`, `InfPath`, `InfSection`, `MatchingDeviceId`, then the DDInstall AddReg with HKR = this key.
4. The device key `HKLM\SYSTEM\CurrentControlSet\Enum\<first hardware ID>\SHZ<nnnn>`: `HardwareID`,
   `CompatibleIDs` (REG_MULTI_SZ), `DeviceDesc`, `Mfg`, `ClassGUID`, `Class`, `Driver` = `{guid}\NNNN`,
   `ConfigFlags` = 0, `Service` = the AddService entry flagged `SPSVCINST_ASSOCSERVICE`; `.HW` AddReg with HKR =
   its `Device Parameters` sub-key. The instance id `SHZnnnn` is shzpnp's own: no bus driver assigned one.

AddReg honours the documented flags: `FLG_ADDREG_NOCLOBBER`, `DELVAL`, `APPEND` (REG_MULTI_SZ, strings not already
present), `KEYONLY`, `OVERWRITEONLY`, and the type encoding in the high word (`REG_SZ`, `REG_EXPAND_SZ`,
`REG_MULTI_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, `REG_NONE`, other `BINVALUETYPE` types as raw bytes). HKLM,
HKCR, HKCU and HKU roots are absolute.

Not done (and said so, not faked): co-installers and class installers are not run (no user-mode installer DLLs are
executed), `.Security` sections are ignored (the registry has no security), catalogs are not verified, DelFiles /
RenFiles are not processed, `Include=` of inbox INFs (for example `machine.inf`, `pci.inf`) cannot be satisfied
because ShizukuDOS has no inbox INF set, and nothing is started: `Start=0/1/2` services are recorded, never loaded at
boot.

**enum** lists `HKLM\SYSTEM\CurrentControlSet\Enum`. Until the NT driver host's PnP manager enumerates buses, only
devices installed with `--device` are there; `enum --log <file>` lists the PCI functions a saved Kernel64 boot log
reports.

**match** ranks the models in `<store>\INDEX.TXT` (default `C:\DRIVERS`, the medium) against devices, Windows rules
first and the undecorated fallback only when nothing else matches (`--legacy` ranks everything together).

**load** calls `NtLoadDriver(\Registry\Machine\System\CurrentControlSet\Services\<service>)` when ntdll exports it
(the NT driver host adds that system call, 0xe0). Without it the command prints `driver host not present` and exits
3; `STATUS_INVALID_SYSTEM_SERVICE`/`STATUS_NOT_IMPLEMENTED` from the kernel are reported the same way. Exit codes:
0 success, 1 failure, 2 usage or missing input, 3 driver host not present.

## Verified

* Host: `python3 shizukudos/ntdrv/tests/test_inf.py --corpus` (19 tests; all 130 ReactOS/virtio-win INFs parse),
  `python3 shizukudos/ntdrv/tests/test_store.py` (5 tests + the ReactOS corpus packages),
  `python3 shizukudos/ntdrv/tests/test_shzpnp.py` (C engine = Python reference on 136 INFs).
* Guest: `T_SHZPNP.EXE` runs in the Kernel64 standalone test (`shizukudos/tests/run_k64_standalone.py`, QEMU TCG):
  add-driver with `--device` on a synthetic package, then checks the copied file bytes, the published INF, the
  service key values, the device, Device Parameters and software keys, REG_MULTI_SZ/REG_BINARY encodings, the
  DriverDatabase record, the undecorated-INF refusal and `--legacy`, `enum`, `match` against an index, and that
  `load` never succeeds on its non-driver payload (exit 3 today).

## Using it with a vendor package

On the host, with a package you have the right to use:

```
python3 shizukudos/ntdrv/tests/test_inf.py --package /path/to/package      # what the INFs select on NTamd64 10.0.22631
python3 shizukudos/ntdrv/store.py add /path/to/package --name MyNic        # into build/shizukudos/ntdrv/media/DRIVERS
python3 shizukudos/ntdrv/store.py match 8086:15B8:06DB1028:10:020000       # which model a device gets
python3 shizukudos/win64/tools/import_coverage.py /path/to/package --providers [--exports <driver-host export JSON>]
```

and in ShizukuDOS: `shzpnp add-driver C:\DRIVERS\MyNic\<file>.inf --device <id>` then `shzpnp load <service>`. What
`load` can do depends entirely on the NT driver host; see DRIVER_CORPUS.md for what a Windows 10 Intel package needs.
