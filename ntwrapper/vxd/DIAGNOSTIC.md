# NTWVDIAG — separate native VxD load diagnostic

Windows 98 Shizuku's Second Edition includes this original diagnostic to narrow
the first native `NTWQUERY.EXE` failure: opening `NTWRAP9X.VXD` returned Win32
error 2. That error alone does not establish a path or LE-loader defect. This
diagnostic preserves the driver, original query probe and their build manifest.
It has no native guest result yet. A host model or static PE check is not a
successful Windows 98 VxD load.

## Procedure and evidence

The executable creates **`C:\NTWLAB\NTWVDIAG.LOG` with `CREATE_NEW`**. An existing
log is preserved and execution stops. It checks `GetVersionExA` for platform 1,
major 4, minor 10 and records the full build number; this identifies Windows 98
but does not claim a particular edition from the version alone.

It opens **`C:\NTWLAB\NTWRAP9X.VXD` as an ordinary read-only file**, allowing only
read sharing, and requires the frozen 9,390-byte size. A bounded whole-file read
and an EOF check precede MZ, bounded `e_lfanew`, and LE-header bounds/signature
checks. Every byte is then compared against an embedded copy of this project's
original frozen VxD, SHA-256
`aff7acf54cd0323fe4dce9aab7d93da16df7b8cf345220ee9d2dafa95b0bc537`.
The SHA string is build provenance; the guest performs exact byte comparison,
not a cryptographic hash. No foreign binary or implementation is embedded.

After closing the ordinary file it opens the explicit 8.3 device path
**`\\.\C:\NTWLAB\NTWRAP9X.VXD`**, using `OPEN_EXISTING` and
`FILE_FLAG_DELETE_ON_CLOSE` just as the original probe did. This is a VxD device
handle; the ordinary file handle never receives the delete-on-close flag.
There is no relative-path fallback. A successful open is followed by the
existing 32-byte `NTWV_IOCTL_QUERY` and exact validation of all eight fields,
then `CloseHandle`. No LE, DDB, control dispatch, VMM services or driver behavior
is changed. This preflight cannot prove which bytes a concurrent file replacer
would make the subsequent VxD loader consume; run in the controlled test folder.

Logs record each numeric value as eight lowercase hexadecimal digits, preserve
the originating Win32 error before logging calls, and flush every complete
record. `PREFLIGHT=PASS` followed by stage 30/error 2 narrows the result to the
explicit device load/open boundary, without proving the underlying loader
reason. Each acquired handle receives one close attempt on every exit path.
A failed close is not retried because its ownership effect is ambiguous.
Both `RESULT=PASS` **and process exit 0** are required: the final log close can
still fail after the last record. The probe does not prove unload beyond the
reported Win32 close result.

| Exit / FAIL_STAGE | Meaning |
| --- | --- |
| 0 | Identity, file preflight, query, device close and log close succeeded |
| 1 / 6 | Other OS identity / version API error |
| 2–5 | Exclusive log creation / write or short write / flush / final close |
| 10–12 | Ordinary file open / size API / unexpected size or high size word |
| 13–16 | File read / short read / EOF read API / unexpected bytes after end |
| 17–20 | MZ / LE offset range / LE signature / expected-byte mismatch |
| 21 | Ordinary file close |
| 30–33 | Absolute device open / query API / query payload / device close |

`WIN32_ERROR=0` denotes a local validation failure. `OBSERVED` carries the size,
offset, first mismatching byte index or returned query length where relevant.
Cleanup errors have separate `CLEANUP_*_ERROR` records and do not replace an
earlier operation error. Log write/flush failures return 3/4 because subsequent
evidence is incomplete. A final log-close failure returns 5 only if there was
no preceding error. An existing log cannot receive an error record.

## Build and host tests

From the repository root:

```sh
python3 -B ntwrapper/vxd/build_diag.py
python3 -B ntwrapper/vxd/test_diag.py
```

These commands write only `ntwrapper/vxd/build/diag/`: generated expected-byte
header, PE32 executable, original host-model executables, logs and separate
JSON receipts. They read the existing driver, query probe and manifest without
running the old builder. Before/after SHA-256 checks refuse source drift or
changed preserved inputs. MinGW supplies declarations/import thunks only;
`-nostdlib`, i486 CPU flags and PE inspection require console/OS 4.10 and only
the ten classic KERNEL32 imports used by the diagnostic. GCC, Clang and
nonrecovering Clang ASan/UBSan execute an independent Win32 API fault model.
No Windows binary, guest, media, service or network is executed by either script.

This builder is currently **local-only**, because it pins the frozen driver's
exact 9,390 bytes and SHA-256. A different compiler can produce another valid
project VxD and deliberately fail this identity gate. Do not add this command
blindly to cross-toolchain CI or weaken the pin silently. The separate
diagnostic-supervisor host model uses explicit mock child processes and can run
in CI without this VxD fixture.

For a **separate diagnostic CD**, include `build/diag/NTWVDIAG.EXE`, the unchanged
`build/NTWRAP9X.VXD`, and the new build/test receipts. Preserve the old probe CD.
Inside an authorized Windows 98 test snapshot, copy the pair to `C:\NTWLAB`,
ensure no prior `NTWVDIAG.LOG` exists (archive it externally before another run),
then launch the new `C:\NTWLAB\NTWDRUN.EXE` diagnostic supervisor, which runs the
DLL probe, graphics probe and this diagnostic in that order. The original
`NTWRUN.EXE` has a fixed probe list and does not run this new probe. See
[`DIAGNOSTIC_RUNNER.md`](../../platform/win98lab/DIAGNOSTIC_RUNNER.md) for the
separate build, batch exit capture and required complete media inventory. Capture the
process exit code and fresh log without replacing the first native trial.
This document does not authorize or perform a new guest launch.

## Original provenance and primary contract sources

All diagnostic, build and model code is original GPL-2.0-only project code.
The embedded bytes are this project's own frozen original driver. Only factual
API contracts were consulted; no SDK sample, loader or external stack was copied.

- Microsoft KB141146, archived Microsoft article last reviewed May 24, 2004:
  [explicit device paths and the 8.3 restriction](https://ftp.zx.net.nz/pub/mirror/ftp.microsoft.com/MISC/KB/en-us/141/146.HTM).
- Manfred Schluttenhofer, Microsoft Corporate Support, October 9, 1995:
  [Loading Your VxD Using the Win32 API](https://techshelps.github.io/MSDN/TECHART/html/msdn_dynvxd.htm),
  specifying `OPEN_EXISTING`, the device close flag and `CloseHandle`.
- Microsoft [GetFileSize return-value contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize):
  a low word of `0xffffffff` is an API error only if `GetLastError` is nonzero;
  an otherwise valid oversized file is a size mismatch in this diagnostic.

The Microsoft-authored pages are archival mirrors. Their descriptions guide
the diagnostic path; they cannot establish whether our independent LE image is
accepted by the actual Windows 98 loader. That remains a guest test question.
