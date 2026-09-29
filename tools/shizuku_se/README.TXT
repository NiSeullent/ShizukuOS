Shizuku SE overlay installer (SHZSE)
====================================

What this is
  A file copy of the project's own guest probe binaries into C:\NTWLAB
  inside an ALREADY INSTALLED Windows 98 (version 4.10). It uses the same
  layout as the project's guest trials: copy the binaries into a fresh
  C:\NTWLAB and run them from that folder (platform/win98lab/README.md,
  ntwrapper/vxd/README.md "Guest probe").

What this is NOT
  - It is not a Windows 98 installer. It does not install or repair
    Windows 98, and ShizukuDOS is not involved in it.
  - It does not edit SYSTEM.INI or the registry, does not copy anything to
    WINDOWS or WINDOWS\SYSTEM and does not install a boot driver. The
    project documents no such step, so none is invented here.
  - It does not run the probes for you.

Files (all built from this project's own sources)
  NTW32.DLL      NTWin32Wrapper9x library (used by NTWPROBE.EXE)
  NTWPROBE.EXE   DLL probe, writes NTWPROBE.LOG
  NTWRAP9X.VXD   NTWrapper9x virtual device driver
  NTWQUERY.EXE   VxD load/query probe, writes NTWQUERY.LOG
  NTWGPROB.EXE   software GDI probe (5 second window), writes NTWGPROB.LOG
  SHA-256 and size of each file: HASHES.TXT at the disc root.

How to use
  1. Start Windows 98 and open an MS-DOS Prompt.
  2. Run  D:\SHZSE\INSTALL.BAT D:   (use your CD-ROM drive letter), or
     change to the SHZSE folder and run INSTALL.BAT.
  3. The script stops without copying if C:\NTWLAB already exists.
  4. cd C:\NTWLAB, run each probe, keep the logs and the exit codes.
     Do not run a probe again before archiving its old log.

Known failure (recorded, not fixed)
  The project docs record, for a Korean Windows 98 SE 4.10.2222 guest
  without KernelEx: NTWPROBE.EXE and NTWGPROB.EXE exited 0, but opening
  NTWRAP9X.VXD failed with Win32 error 2 (docs/NATIVE_FIRST_TRIAL.md). The
  same error appeared when the VxD was opened by absolute path
  (docs/NATIVE_GDI_TRIAL.md), and a DOS-level VXDLDR load call returned
  error 6, BAD_DEVICE_FILE (docs/VXD_V86_LOADER_TRIAL.md). No native VxD
  load has passed. Expect NTWQUERY.EXE to fail on your machine too.
  The GDI probe covers software rendering only, not WDDM or a GPU.

Which binaries the records belong to
  The results above were recorded with binaries built on the project's
  original host, for example the frozen VxD, 9,390 bytes, SHA-256
  aff7acf54cd0323fe4dce9aab7d93da16df7b8cf345220ee9d2dafa95b0bc537.
  The binaries on this disc are rebuilt from the same sources at disc-build
  time with whatever toolchain the builder had, so their bytes can differ
  (compare with HASHES.TXT). The copies on this disc have no Windows 98
  guest result of their own.

Status of this installer
  INSTALL.BAT is new. It has not been run on a real Windows 98 system, so
  it is unverified. It is a plain copy script; copying the files is not
  evidence that the wrappers work.

Licence
  The binaries and this script are GPL-2.0-only project code.
