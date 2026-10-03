# OFFSAL: LibreOffice 26.8.0.3 SAL startup/process/module/file provider for Windows 98

OFFSAL.DLL exports `Ofs*` stdcall entry points for the sal/osl/w32 calls KERNEL32 on Windows 98 SE lacks:
SetProcessDEPPolicy, SetDllDirectoryW, SetSearchPathMode, GetProcessId (+ Register/ForgetProcessHandle),
GetModuleHandleExW, GetFileSizeEx, SetFilePointerEx, ReplaceFileW. The patch
`tools/modern_apps/office_win98_sal_startup.patch` (verified by `office_win98_sal_startup.py`) routes the
pinned upstream sources through them under `LIBO_WIN98=1`.

Truthful limits: DEP, DLL directory and safe search mode do not exist on Windows 98 (error 120); Unicode paths
are converted to the ANSI code page and refused (1113) if not exactly representable, long (>259) and `\\?\` paths
refused; ReplaceFileW works on one volume only and is not power-loss atomic; GetProcessId answers only the
current process and handles registered by the patched `osl_getProcess`; GetModuleHandleExW cannot pin.

Build and gates: `python3 -B ntwin32/office_sal/build.py --out DIR` (host logic test, i486 PE32 4.10 DLL,
probe and link-check, Win98 SE import gate). OFSALPRB.EXE writes C:\VXDLAB\OFSAL.LOG when run natively; not run yet.
SPDX-License-Identifier: GPL-2.0-only
