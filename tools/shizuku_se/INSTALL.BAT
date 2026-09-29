@echo off
rem SPDX-License-Identifier: GPL-2.0-only
rem Shizuku SE overlay installer (probe layout). Read README.TXT first.
rem
rem Run this from an MS-DOS Prompt INSIDE an already installed Windows 98
rem (version 4.10). It is not a Windows 98 setup program.
rem
rem Usage:   INSTALL.BAT [cdrom-drive:]
rem Example: D:\SHZSE\INSTALL.BAT D:
rem Without an argument the files are taken from the current directory.
rem
rem It only copies five files into a NEW folder C:\NTWLAB. It does not edit
rem SYSTEM.INI or the registry, does not touch WINDOWS\SYSTEM and does not
rem install a boot driver. That is the layout used by the project guest trials.
rem
rem This script is new and has not been run on a real Windows 98 system.
echo.
echo Shizuku SE overlay installer (probe layout)
echo.
if "%1"=="" goto here
set SHZSRC=%1\SHZSE
goto check
:here
set SHZSRC=.
:check
if not exist %SHZSRC%\NTW32.DLL goto nosrc
if not exist %SHZSRC%\NTWRAP9X.VXD goto nosrc
if not exist %SHZSRC%\NTWQUERY.EXE goto nosrc
if not exist %SHZSRC%\NTWPROBE.EXE goto nosrc
if not exist %SHZSRC%\NTWGPROB.EXE goto nosrc
if exist C:\NTWLAB\nul goto exists
md C:\NTWLAB
if not exist C:\NTWLAB\nul goto mkfail
copy %SHZSRC%\NTW32.DLL C:\NTWLAB\ > nul
copy %SHZSRC%\NTWRAP9X.VXD C:\NTWLAB\ > nul
copy %SHZSRC%\NTWQUERY.EXE C:\NTWLAB\ > nul
copy %SHZSRC%\NTWPROBE.EXE C:\NTWLAB\ > nul
copy %SHZSRC%\NTWGPROB.EXE C:\NTWLAB\ > nul
if not exist C:\NTWLAB\NTW32.DLL goto failed
if not exist C:\NTWLAB\NTWRAP9X.VXD goto failed
if not exist C:\NTWLAB\NTWQUERY.EXE goto failed
if not exist C:\NTWLAB\NTWPROBE.EXE goto failed
if not exist C:\NTWLAB\NTWGPROB.EXE goto failed
echo Copied 5 files to C:\NTWLAB:
echo   NTW32.DLL NTWRAP9X.VXD NTWQUERY.EXE NTWPROBE.EXE NTWGPROB.EXE
echo.
echo Next: run each probe from C:\NTWLAB and keep its .LOG file:
echo   cd C:\NTWLAB
echo   NTWPROBE.EXE
echo   NTWQUERY.EXE
echo   NTWGPROB.EXE
echo.
echo KNOWN FAILURE, recorded in the project docs and NOT fixed here:
echo   Opening NTWRAP9X.VXD failed in the recorded Windows 98 SE guest
echo   trials with Win32 error 2, also by absolute path, and a DOS-level
echo   VXDLDR load returned error 6. Expect NTWQUERY.EXE to fail the same
echo   way. This installer does not make the VxD load.
goto done
:nosrc
echo ERROR: the five files were not found in %SHZSRC%.
echo Run it as D:\SHZSE\INSTALL.BAT D:  (D: = your CD-ROM drive) or from
echo the SHZSE folder itself. Nothing was copied.
goto done
:exists
echo ERROR: C:\NTWLAB already exists. The probes expect a fresh folder and
echo refuse old logs. Nothing was copied. Archive or remove it yourself.
goto done
:mkfail
echo ERROR: could not create C:\NTWLAB. Nothing was copied.
goto done
:failed
echo ERROR: a copy into C:\NTWLAB failed. Check C:\NTWLAB by hand.
:done
set SHZSRC=
echo.
