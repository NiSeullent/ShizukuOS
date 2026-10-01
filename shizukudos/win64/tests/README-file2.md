# Shared modern file entry points

These original GPL-2.0-only providers implement common `CreateFile2` and
`CopyFile2` entry points through the existing real Win32/NT file, handle,
heap and metadata providers. No application name or version is special-cased.
The API contracts are Microsoft's [CreateFile2 documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfile2),
[CopyFile2 documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfile2)
and [progress message documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-copyfile2_message).

CreateFile2 supports default attributes, genuine handle inheritance,
overlapped/delete-on-close/backup handling and advisory sequential/random
hints. The current native create-file provider ignores nondefault initial
attributes; its disk writes do not enforce per-write device flushes. Requests
for nondefault attributes or write-through therefore fail before creating a
file. Security descriptors/QoS and template metadata also fail explicitly.
This is a bounded implemented contract, not complete CreateFile2 coverage.

CopyFile2 copies actual unnamed-stream bytes with real partial reads/writes,
basic time/attribute preservation, fail-if-exists and open-source-for-write.
Progress records contain the actual handles, sizes and transferred counts.
Cancel deletes the partial destination, stop preserves it and reports actual
partial stream completion, and quiet completes copying without more callbacks.
Unsupported flags, pause/restart, EFS, compressed/sparse/reparse metadata and
error-retry callbacks are not implemented. The current disk-backed metadata
setter returns unsupported, so disk copies requiring that setter fail honestly;
passing RAM-file fixtures does not prove general disk copying.

Before overwriting an existing destination, actual volume/file identifiers are
compared to preserve a source addressed through the same path or a normalized
alias. The existing kernel does not enforce general share-mode exclusion, so
concurrent rename/replacement races remain a backend limitation. This guard
does not claim a substitute for that missing filesystem contract.

The native fixture independently generates 131089 source bytes and verifies
every copied byte and EOF, real three-chunk progress, cancel/stop/quiet effects,
source-byte preservation after self/alias refusals, fail-if-exists preservation,
and precreate refusal of unsupported attributes/flush/template/flags. Ordinary
build, host object checks and real guest tests are recorded separately. None
of them by itself establishes application or installed Windows98 acceptance.
