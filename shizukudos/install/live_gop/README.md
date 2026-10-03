# Windows 98 GOP display installation

`gopinst.c` is a real Win16 ANSI SetupX class caller, compiled against the original
Windows 98 INC16 SDK. It enumerates present Display devices, binds the explicitly
observed HKLM Enum key, builds the compatibility list from the sole staged
SHZGOP.INF, and admits a unique matching install section. It calls
`DiCallClassInstaller(DIF_INSTALLDEVICE)`, then reads the device's actual Driver
class reference, DEFAULT drv/minivdd, and installed SYSTEM driver bytes back.
It does not assume NT SetupDi support and does not invoke DefaultInstall.

Installation is admitted only by the **real current-boot query**. The utility
looks up the already loaded source-built SHZGOP VxD through Win16 INT2F 1684,
device 4353, and queries additive service 4f10. It maps the actual current query
result with the original Win98 MapLS ABI, checks the live unique F-segment
locator, validates two freshly acquired descriptor/HDA snapshots and compares
the embedded implementation identity with the actual producer receipt. The VxD
independently re-reads its physical descriptor, initialized backend and current
PCI identity/BAR. There is no loading, mode-setting or INI-flag fallback. An
unloaded provider or a legacy BIOS/stdVGA baseline fails admission.

The current descriptor ABI contains **no Supervisor epoch**. This query proves
availability of the currently loaded native GOP backend and current descriptor;
it does not assert Supervisor epoch admission. Further full-product admission
must bind the real guardian/Supervisor epoch. Query snapshot bytes are recorded
in the guest log for independent host readback, and no compiled executable or
payload staging claims guest success.

The privately owned original full disk clone must be retained. The caller uses
fresh `C:\GOPBAK\ENUM.BAK` and `CLASS.BAK` registry-key snapshots before the class
installer mutates anything. It holds source files and SETUPX.DLL against writes,
requires fresh exclusive `C:\GOPINST.LOG`, restores SetupX's original source LDD,
and records reboot requirements. A partially completed class install is a
failure requiring recovery from the retained clone, not an automatic success.

After the real native GOP VxD is loaded in an independently authorized current
boot, the private guest operator must produce
`C:\GPREQ.INI` from that exact disk/current boot and actual source-bound artifacts:

```ini
[GOP]
EnumKey=Enum\<actual enumerated device key>
DRV_SHA256=<64 lowercase hexadecimal digits>
VXD_SHA256=<64 lowercase hexadecimal digits>
INF_SHA256=<64 lowercase hexadecimal digits>
SETUPX_SHA256=<hash of that guest's actual SYSTEM\SETUPX.DLL>
LIVE_PROVIDER_SHA256=<source implementation identity in the actual GOP build receipt>
```

Stage the three actual driver members at C:\, prepare the owned fresh GOPBAK
directory, and execute `GOPINST.EXE /install` inside Windows 98. Accept registry
installation evidence only with observed process exit code zero and the complete
read-back log; it still does not prove GPU activation. A new boot, actual native
GOP Enable/DCI/backend probe, live device state and screenshot are separate
required acceptance evidence. RunOnce registration must use a supported live
guest registry operation; neither a menu entry nor an authored synthetic
SYSTEM.DAT is equivalent.

`build.py` requires explicit private SDK/Watcom paths and a fresh private output
outside this repository. It verifies the pinned Watcom archive and cached
compiler/header/library bytes, captures exact public sources and the four
original SDK headers, and compiles only the captured closure. The resulting
receipt lists exact sources, tools, libraries, commands and artifact hashes.
Output contains Microsoft SDK headers: keep it private, outside Git and public
ISOs. No downloaded installer is executed; no client configuration is changed.

`../gop_preinstall_profile.py` preserves the original five HIMEMX/WIN.COM startup
payloads, binds actual GOP producer sources/tools/upstreams/artifacts, and emits
an eight-member private constructor profile. This is staging only. The current
native ingestion contract deliberately accepts five payloads, so this increment
requires explicit integration there before it can become a production input.

Primary API ABI source: privately extracted original Microsoft Windows 98 DDK
`INC_WIN98_INC16_SETUPX.H`, SHA256
`aef84421a79596dcf6c7aaa90af03466e73a1a36bf83ae953138a9252421e815`.
Original download is unavailable at the historical Microsoft URL. The acquired
archive matches the independent historical size/SHA1 catalogue; no publisher
signature verification is asserted. Microsoft headers are not included here.

`prepare.py` adds the actual `GOPINST.EXE` and an injection-safe `GPREQ.INI` to
the eight-member constructor profile (ten root files). It retains leases on the
actual public caller sources, captured SDK/compiler/library closure, actual GOP
producer inputs and the privately extracted guest SETUPX.DLL. It does not copy
that Microsoft DLL into an output or register RunOnce. Its request schema is
`shizukuos.private-live-gop-stage-request.v1`, with pinned `gop_profile`,
`utility_build_receipt`, `setupx_dll`, and an explicitly observed `enum_key`.
The underlying root-file constructor backs up/readbacks owned clones. The native
five-payload ingestion contract still requires a separate integration change.

There is a real existing Windows 98 dynamic-VxD load pattern in this repository:
`ntwrapper/vxd/diag_probe.c` preflights the exact owned binary before opening
`\\.\C:\NTWLAB\NTWRAP9X.VXD` with CreateFile and querying its actual backend.
The GOP producer already emits a dynamic LE VxD and routes both initial and
dynamic initialization through checked Device_Init. This establishes an OS load
mechanism, **not a proven GOP loader/guardian route**. SHZGOP activation needs a
separately trusted native-foundation loader on an owned clone after current
firmware/descriptor/guardian admission. An early `[386Enh]` SYSTEM.INI device
entry is another possible Windows loading route, but must preserve/backup and
read back that real file, and must not be applied to the legacy BIOS/stdVGA
baseline. An initialized SHZGOP MiniVDD cannot dynamically unload: hooks persist
until guest shutdown. No automatic early-load operation is implemented here.
The readonly probe correctly refuses an unloaded provider; ten staged root
payloads alone do not perform first-time default-display registration.
