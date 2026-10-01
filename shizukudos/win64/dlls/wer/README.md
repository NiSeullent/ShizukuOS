# WER executable exclusion family

The complete add/remove exclusion pair writes and deletes an actual registry
`REG_DWORD` value of 1 under
`Software\Microsoft\Windows Error Reporting\ExcludedApplications`. A false
`all_users` selects HKCU; a true value selects HKLM and requires the rights
accepted by the real registry provider. Paths select the final backslash
separated basename. Empty names, a trailing backslash, NULL and paths without
NUL within MAX_PATH fail with `E_INVALIDARG`. Extensions such as Office's
`.bin` are supported. No file is created or opened by these functions.

Add returns success only after a real registry create/open, set and close.
Remove opens an existing exclusion key and deletes the exact named value;
missing keys or values remain genuine failures. Every actual create/open,
set/delete and close error is preserved as `HRESULT_FROM_WIN32`. A later
close error cannot replace the first set/delete error. There is no global
module state or owned handle retained between calls.

Kernel64's registry is volatile across reboot. The existing registry backend
supplies its own identity, permissions and persistence limitations. Exclusion
state is real within that backend; it does not imply a crash reporting,
dump collection, upload, service or persistent hive backend. No unsupported
WER report API is exported.

The implementation is independent. Primary contracts are Microsoft
[WerAddExcludedApplication](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-weraddexcludedapplication)
and [WerRemoveExcludedApplication](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-werremoveexcludedapplication).
Reviewed source bodies: Wine `db11d0fe6a169c457e23d007e20404643d067aa8`
`dlls/wer/main.c` and One-Core API
`9eb3c31de9460c1ccce3f6a10c9c4a704f032514` `oca/new-dlls/wer/main.c`
(LGPL-2.1-or-later, Louis Lenders and Detlef Riekenberg, 2010). Both ignore
RegSetValueExW errors in add and translate unrelated delete errors; those
behaviors were not reused. No upstream implementation body is copied.
Pinned ReactOS `9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8` provides a
WER header but no WER implementation. KernelEx has no exclusion-family
implementation or runtime route. The historical project catalogue records
declarations and default DLL batches; no compatibility percentage is claimed.

Host tests compile the exact production block with explicit registry adapters
and injected error paths. Native tests query real registry values through
independent APIs, test both roots and a Unicode basename, verify absence after
remove, and clean their test values. Host, compiled native, actual guest and
Office behavior are separate evidence levels.
