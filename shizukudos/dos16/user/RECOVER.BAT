@ECHO OFF
SET SHZPROFILE=RECOVERY
PROMPT RECOVERY$P$G
ECHO ShizukuDOS 10 recovery shell.
ECHO SHZSTART.BAT is the automatic startup file. Check it before retrying.
ECHO SHZSAFE.TAG skips startup on the next boot; remove it when ready.
ECHO F5 skips startup and F8 traces it during the normal boot-key window.
ECHO No disk format, installation, reboot or forced shell exit was performed.
C:\SHZREADY.COM R
