@rem SPDX-License-Identifier: GPL-2.0-only
@echo off
c:\ntwlab\ntwdrun.exe
if errorlevel 4 goto unknown
if errorlevel 3 goto code3
if errorlevel 2 goto code2
if errorlevel 1 goto code1
echo 0 >c:\ntwlab\NTWDEXIT.TXT
goto done
:code1
echo 1 >c:\ntwlab\NTWDEXIT.TXT
goto done
:code2
echo 2 >c:\ntwlab\NTWDEXIT.TXT
goto done
:code3
echo 3 >c:\ntwlab\NTWDEXIT.TXT
goto done
:unknown
echo unexpected >c:\ntwlab\NTWDEXIT.TXT
:done
ver>c:\ntwlab\GUESTVER.TXT
echo Diagnostic probe run ended. Preserve all logs and NTWDEXIT.TXT.
