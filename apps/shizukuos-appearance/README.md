# ShizukuOS Appearance

Native Windows 98 USER/GDI app. Explorer stays the shell.

- Windows Classic needs no provider. The ShizukuOS choice is process-local/provider-only
  (M98THEME.DLL) and is enabled only when the real provider loads; otherwise the exact error shows.
  It is not a whole-desktop change.
- "Global palette settings..." starts the adjacent `SHZTHEME.EXE` (path derived from this
  module's folder, bounded buffers, no arbitrary path) only on explicit click. The selector opens
  its own window and reports its own result; nothing is auto-run at logon and this app writes no
  registry ABI for it. Missing file or CreateProcess failure is reported with its Win32 error.
- Not verified here: guest execution.
