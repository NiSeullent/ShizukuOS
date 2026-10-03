# Kernel64 file handle enforcement

The auxiliary Kernel64 service previously used the original file object's
access mask after `NtDuplicateObject` had reduced a particular handle's grant.
Read-only handles could write, truncate, rename, delete and change attributes.
Read-only create requests could overwrite, supersede or request deletion on
close. This violated the service's minimum-rights boundary even when the UID,
session and profile policy correctly admitted the caller.

File open now maps generic access to concrete file rights before publishing a
handle. Every operation captures the referenced object and that handle's grant
together. The asynchronous router uses this capture through IRP preparation;
closing and reusing the numeric handle cannot redirect filesystem I/O.
Rejection paths and IRP teardown release the file payload if a concurrent close
left the operation holding the last reference.

The enforced rights follow Microsoft's [ZwCreateFile contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile)
and [ZwSetInformationFile contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwsetinformationfile):

| Operation | Required concrete right |
| --- | --- |
| Read / list directory | FILE_READ_DATA / FILE_LIST_DIRECTORY |
| Write / flush | FILE_WRITE_DATA or FILE_APPEND_DATA |
| Truncate / extend / overwrite | FILE_WRITE_DATA |
| Change attributes | FILE_WRITE_ATTRIBUTES |
| Rename / deletion / supersede / delete on close | DELETE |

Append-only writes use EOF even when the caller supplies offset zero. WRITE_DAC
and WRITE_OWNER do not grant payload write, delete or rename rights. File access
queries report the captured handle's grant. FilePositionInformation retains its
existing behavior; no extra access requirement is inferred for it.

`test_file_rights_host.py` compiles the full production filesystem, account
authority and file dispatcher, with unchanged production object/handle/duplicate
and asynchronous router functions. It declares host IRQ, copies, heap, clock,
token storage, unavailable device service and IRP preparation/completion
boundaries. Tests cover concrete/generic rights, refusals before IRP effects,
account/sandbox admission, console and NUL behavior, forced handle reuse,
last-handle close on all error paths, and final allocation cleanup. This is
production-code host evidence, not actual Windows98 execution or a secure
Windows98 credential desktop. The volatile enrollment and legacy isolation
limits remain those documented in [README.md](README.md).

```sh
python3 -B shizukudos/tests/test_file_rights_host.py --label current --reuse-control
python3 -B tools/verify_std_console_access.py --repo "$PWD" --out "$PWD/build/std-console-check"
```
