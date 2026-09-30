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
| `shzpnp` | `\SHZ\SYS64\SHZPNP.EXE` | Win64 CLI in the running system: add-driver, enum, match, load, unload, status |
| `T_SHZPNP.EXE` | `shizukudos/win64/tests/t_shzpnp.c` | runs `shzpnp` on Kernel64 and checks the files and registry it changed |
| `T_DRV_LOAD.EXE` | `shizukudos/win64/tests/t_drv_load.c` | packages, installs, loads, reaches, unloads and reloads the ECHO.SYS test driver through `shzpnp` |
| `T_DRV_PNP.EXE` + `run_k64_pnp.py` | `shizukudos/win64/ntdrv/t_drv_pnp.c`, `shizukudos/tests/run_k64_pnp.py` | the ReactOS e1000 package on QEMU's e1000, end to end |

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
shzpnp unload <service>
shzpnp status [<service>]
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

With `--install` (implied by `--device`), every device — from `--device`, else every device `enum` lists — is matched
against the INF's models, and the best-ranked model is installed the way SetupAPI installs a device:

1. CopyFiles of the DDInstall section to their DestinationDirs.
2. Each AddService creates `HKLM\SYSTEM\CurrentControlSet\Services\<name>`: `Type`, `Start`, `ErrorControl`,
   `ImagePath` (REG_EXPAND_SZ; `%12%\x.sys` becomes `\SystemRoot\SYS64\DRIVERS\x.sys`), `DisplayName`,
   `Description`, `Group`, `DependOnService`, then the service's AddReg with HKR = the service key.
3. A software key `HKLM\SYSTEM\CurrentControlSet\Control\Class\{ClassGUID}\<NNNN>`: `DriverDesc`, `ProviderName`,
   `DriverVersion`, `InfPath`, `InfSection`, `MatchingDeviceId`, then the DDInstall AddReg with HKR = this key.
4. The device key `HKLM\SYSTEM\CurrentControlSet\Enum\<first hardware ID>\<instance>`: `HardwareID`,
   `CompatibleIDs` (REG_MULTI_SZ), `DeviceDesc`, `Mfg`, `ClassGUID`, `Class`, `Driver` = `{guid}\NNNN`,
   `ConfigFlags` = 0, `Service` = the AddService entry flagged `SPSVCINST_ASSOCSERVICE`; `.HW` AddReg with HKR =
   its `Device Parameters` sub-key. The instance id is `B<bus>D<dev>F<fn>` for a function of the Kernel64 PCI scan
   and `SHZ<nnnn>` for a `--device` given by hand; both are shzpnp's own (Windows uses the bus driver's instance id).

AddReg honours the documented flags: `FLG_ADDREG_NOCLOBBER`, `DELVAL`, `APPEND` (REG_MULTI_SZ, strings not already
present), `KEYONLY`, `OVERWRITEONLY`, and the type encoding in the high word (`REG_SZ`, `REG_EXPAND_SZ`,
`REG_MULTI_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, `REG_NONE`, other `BINVALUETYPE` types as raw bytes). HKLM,
HKCR, HKCU and HKU roots are absolute.

Not done (and said so, not faked): co-installers and class installers are not run (no user-mode installer DLLs are
executed), `.Security` sections are ignored (the registry has no security), catalogs are not verified, DelFiles /
RenFiles are not processed, `Include=` of inbox INFs (for example `machine.inf`, `pci.inf`) cannot be satisfied
because ShizukuDOS has no inbox INF set, and nothing is started: `Start=0/1/2` services are recorded, never loaded at
boot.

**enum** lists the devices the system knows: the `HKLM\SYSTEM\CurrentControlSet\Enum` tree, plus every PCI function
of Kernel64's own bus scan that is not registered there yet (`NtQuerySystemInformation` class 0x101, kernel64/sysx.c:
bus/device/function, vendor, device, class and the in-kernel driver bound to it, e.g. `gfx_fb`, `net_rtl8139`). That
record carries no subsystem ID or revision, so scanned functions get the `VEN&DEV` and class IDs only; the NT driver
host's PnP manager will replace this source when it enumerates buses. Under the Supervisor the scan is empty (the
configuration ports trap); `enum --log <file>` lists the PCI functions a saved Kernel64 boot log reports.

**match** ranks the models in `<store>\INDEX.TXT` (default `C:\DRIVERS`, the medium) against devices (given, else
all `enum` devices), Windows rules
first and the undecorated fallback only when nothing else matches (`--legacy` ranks everything together).

For `Class=Net` packages, add-driver also produces what the Windows Net class installer (NetCfg) leaves in the
registry and NDIS reads at `AddDevice`: in the software key `NetCfgInstanceId` (`{GUID}`, derived deterministically from
the devnode instance path and the service), `Characteristics` and `BusType` from the DDInstall section, `ComponentId`,
`Linkage\Export` = `\Device\{GUID}` and `Linkage\RootDevice` (REG_MULTI_SZ); in the service key `Linkage\{Bind,Export,Route}`;
and `Control\Network\{Net class}\{GUID}\Connection`. No protocol is bound (`UpperBind` is not written: there is no
TCP/IP stack on this side).

**load** reads the service key (`Type`, `Start`, `ImagePath` and the file it resolves to under the service control
manager's rules: `\SystemRoot\` and `%SystemRoot%` = `C:\SHZ`, absent = `SYS64\DRIVERS\<service>.sys`), refuses a
non-kernel or disabled service and a missing image file with a message (exit 2), then calls
`NtLoadDriver(\Registry\Machine\System\CurrentControlSet\Services\<service>)`. The NT driver host (NTDRV.md) maps the
image, loads the modules it imports from other than `ntoskrnl.exe`/`hal.dll` (`\SHZ\SYS64\DRIVERS\<dll>`, e.g.
`ndis.sys`) first, runs `DriverEntry`, claims every PCI function whose Enum devnode names the service
(`ntdrv:<service>` in the kernel's claim registry, `NtQuerySystemInformation` class 0x101, the status screen's PCI
table) and, when the driver registered `AddDevice`, starts it the way the PnP manager does (`AddDevice` with a PDO for the
function, then `IRP_MN_START_DEVICE` with the function's BARs and interrupt line as its resources). The status is
reported in words: loaded; already loaded (`STATUS_IMAGE_ALREADY_LOADED`); not an AMD64 PE32+ kernel image
(`STATUS_INVALID_IMAGE_FORMAT`); unresolved imports (`STATUS_PROCEDURE_NOT_FOUND`: the kernel log names each missing
export or module); image not found; or the driver's own `DriverEntry` status. Without the driver host the command prints
`driver host not present` and exits 3. Exit codes: 0 success, 1 failure, 2 usage or missing input, 3 driver host not
present. After a load the command prints the driver's status record.

**unload** calls `NtUnloadDriver`: `DriverUnload` runs and the claims are released; a driver without `DriverUnload`
stays loaded (`STATUS_INVALID_DEVICE_REQUEST`, as on Windows), and so does one another loaded image imports from
(`STATUS_CONNECTION_IN_USE`).

**status** `[<service>]` lists the images the driver host has loaded (`NtShzDriverQuery`): service, image window, the
device objects each created (`\Device\...`) and the PCI functions bound to it; exit 1 when the service is not loaded.

## Verified

* Host: `python3 shizukudos/ntdrv/tests/test_inf.py --corpus` (19 tests; all 130 ReactOS/virtio-win INFs parse),
  `python3 shizukudos/ntdrv/tests/test_store.py` (5 tests + the ReactOS corpus packages),
  `python3 shizukudos/ntdrv/tests/test_shzpnp.py` (C engine = Python reference on 136 INFs).
* Guest, default image (`shizukudos/tests/run_k64_standalone.py --accel tcg`, QEMU TCG, `GUEST_RUN`):
  * `T_SHZPNP.EXE`: add-driver with `--device` on a synthetic package, then checks the copied file bytes, the published
    INF (found through its `DriverDatabase` record, whatever `oem<N>` number it got), the service key values, the device,
    Device Parameters and software keys, REG_MULTI_SZ/REG_BINARY encodings, the undecorated-INF refusal and `--legacy`,
    `enum`, `match` against an index, installing on a function of the Kernel64 PCI scan without `--device`, and that
    `load` never succeeds on its non-driver payload (the host rejects it: `STATUS_INVALID_IMAGE_FORMAT`, exit 1). 35/35.
  * `T_DRV_LOAD.EXE` (`shizukudos/win64/tests/t_drv_load.c`): the unmodified `ECHO.SYS` test driver (shipped as test
    data `\SHZ\TESTS\ECHO.SYS`) packaged with a decorated INF for the last unclaimed non-display function of the PCI
    scan; `add-driver --install` → `load shzecho` (the function reads `ntdrv:shzecho` in the claim registry;
    `\\.\ShzEcho` opens and an IOCTL round-trips through the loaded driver) → `status` → a second `load` = already
    loaded → the error paths without a kernel fault (no service key; missing image; a non-PE image; a copy of ECHO.SYS
    whose import name `IoCreateDevice` was altered in the file: refused with `STATUS_PROCEDURE_NOT_FOUND`) → `unload`
    (claim released, device gone) → `load` again, left loaded so the status screen (`k64-status.png`) shows the claim.
    31/31.
* Guest, a real package (`shizukudos/tests/run_k64_pnp.py --accel tcg`, QEMU `-device e1000`, `GUEST_RUN`): the
  unmodified ReactOS e1000 NDIS 5 miniport package built by the corpus tooling (`shizukudos/ntdrv/corpus/build.py
  --packages` → `build/shizukudos/ntdrv/packages/e1000`: `e1000.sys` + `nete1000.inf`, unchanged) is put on the medium
  with `store.py add`, together with the corpus `ndis.sys` under `\SHZ\SYS64\DRIVERS` (the framework provider it
  imports; on Windows an inbox boot-start driver). `T_DRV_PNP.EXE` (`shizukudos/win64/ntdrv/t_drv_pnp.c`) runs
  `shzpnp match --store C:\DRIVERS`, `add-driver ... --install` (refused: the ReactOS INF is undecorated), `add-driver
  C:\DRIVERS\e1000\nete1000.inf --legacy --install` (Services\e1000, the Enum devnode `PCI\VEN_8086&DEV_100E\B00D02F0`
  with `Service=e1000` and `Driver={Net class}\0000`, the Net class installer's keys), `load e1000`, `status e1000`,
  `status ndis`, `unload ndis` (refused: in use). Kernel log:

  ```
  K64 ntdrv: NtLoadDriver(e1000) -> C:\SHZ\SYS64\DRIVERS\e1000.sys
  K64 ntdrv: e1000 imports ndis.sys: loading it first
  K64 ntdrv: ndis mapped at ffffe00000010000 (106496 bytes), calling DriverEntry
  K64 ntdrv: e1000 mapped at ffffe00000000000 (40960 bytes), calling DriverEntry
  K64 ntdrv: e1000 owns PCI 0:2.0 (8086:100e)
  K64 ntdrv: e1000 AddDevice(PCI 0:2.0) = 0
  K64 ntdrv: PCI 0:2.0: BUS_INTERFACE_STANDARD handed to the function driver
  K64 ntdrv: device interface \??\PCI#VEN_8086&DEV_100E#B00D02F0#{CAC88484-7515-4C03-82E6-71A87ABAC361} enabled
  K64 ntdrv: e1000 IRP_MN_START_DEVICE(PCI 0:2.0) = 0 (started)
  ```

  `IRP_MN_START_DEVICE` succeeding means NDIS ran the miniport's `MiniportInitialize` on the NIC: e1000 read its PCI
  configuration through the bus interface, took its port, memory and interrupt resources, mapped BAR0, allocated its
  descriptor rings as DMA common buffers, reset the chip, read the permanent MAC address from the EEPROM, connected the
  interrupt and enabled transmit/receive; NDIS then queried its OIDs (MAC options, current address, lookahead) and
  enabled the `GUID_DEVINTERFACE_NET` interface. The guest program confirms `ntdrv:e1000` on the function
  (`NtQuerySystemInformation` 0x101), the device object `\Device\{NetCfgInstanceId}` in the host's records, and opens it
  from user mode (`IRP_MJ_CREATE` through NDIS). 24/24. No protocol is bound on top (there is no NDIS protocol driver or
  TCP/IP stack on this side), so packets are not exchanged through it.
* Screenshot: `python3 shizukudos/tests/run_k64_gui.py --accel tcg --png --pnp` (the e1000 package loaded before
  T_GUI_STATUS runs) → `docs/shizukudos10/screenshots/k64-status-e1000.png`, the PCI table with `ntdrv:e1000`.

## Using it with a vendor package

On the host, with a package you have the right to use:

```
python3 shizukudos/ntdrv/tests/test_inf.py --package /path/to/package      # what the INFs select on NTamd64 10.0.22631
python3 shizukudos/ntdrv/store.py add /path/to/package --name MyNic        # into build/shizukudos/ntdrv/media/DRIVERS
python3 shizukudos/ntdrv/store.py match 8086:15B8:06DB1028:10:020000       # which model a device gets
python3 shizukudos/win64/tools/import_coverage.py /path/to/package --ntoskrnl build/shizukudos/win64/ntdrv
```

The last line says which imports the driver host does not provide yet (the corpus e1000 needed 40 more exports than
the host had; NTDRV.md lists what is there). Modules the package imports besides `ntoskrnl.exe`/`hal.dll` must be
present as `\SHZ\SYS64\DRIVERS\<name>.sys` (the Windows inbox framework drivers — `ndis.sys`, `storport.sys`,
`Wdf01000.sys`, ... — are not shipped here; the ReactOS-built ones are in the corpus).

In ShizukuDOS:

```
shzpnp match --store C:\DRIVERS                       # rank the store against the bus
shzpnp add-driver C:\DRIVERS\MyNic\<file>.inf --install    # or --device <id>; --legacy for undecorated INFs
shzpnp load <service>                                 # DriverEntry, PCI claim, AddDevice + IRP_MN_START_DEVICE
shzpnp status <service>                               # device objects and PCI functions
```

What runs after that depends on the driver's framework: WDM drivers and NDIS 5 miniports with the corpus `ndis.sys`
have been taken through `MiniportInitialize`; KMDF, NDIS 6, StorPort with extended SRBs and WDDM are not provided
(DRIVER_CORPUS.md says what each Windows 10 Intel family needs).
