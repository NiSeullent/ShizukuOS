# Original DOS VXDLDR diagnostic experiment

`NTWLDR.COM` distinguishes a loader's native return from the Win32 `CreateFile`
error observed with the frozen experimental VxD. It is independent 16-bit x86
assembly, built with NASM, with no DDK implementation, library, CRT, or DOS runtime
linked into it. This is a diagnostic, not an installed driver or a Windows 98 ABI
compatibility result.

The program creates **`C:\NTWLAB\NTWLDR.LOG` exclusively**. An existing log is
preserved and causes exit 1. It obtains VXDLDR's V86 far entry with INT 2Fh,
AX=1684h, BX=0027h, and zero ES:DI. The pointer, raw returned FLAGS, AX and DX,
then the raw function-0 version response are logged. Version fields are
informational: neither the Windows version nor a specific loader protocol version
is inferred from DX. A zero entry segment is rejected conservatively.

Before calling the loader, ordinary DOS read-only access compares all 9,390 bytes
of `C:\NTWLAB\NTWRAP9X.VXD` with the embedded original experiment, checks EOF, and
closes the file. The pinned SHA-256 is
`83952d5c220272d4dbd724e309e29fcc431d2eefa0e59253d3283a116fc0801e`.
This is the previously isolated data-SHARABLE-bit candidate; it already failed the
Win32 open trial. The baseline is unchanged. The log's hash names the embedded
expectation; the actual preflight is a full byte comparison, not a guest SHA
implementation. An external concurrent file replacement after the comparison is
outside this isolated, single-operator trial's guarantee.

The COM calls function 1 with DS:DX pointing to that full path. Only CF=0 and AX=0
establish ownership. It then calls function 2 once with BX=FFFFh and DS:DX pointing
to the eight-character DDB name `NTWRAP9X`. This is the Microsoft Windows 95
by-name convention; the older Windows for Workgroups convention differs. No
fallback unload is attempted. A duplicate-load failure never authorizes unload.
Raw FLAGS/AX/DX are stored through CS before any flag-changing instruction, then
DS/ES and the direction flag are restored for DOS. The saved loader pointer is
retained even if a call returns another ES:DI. Log failure after a successful load
still attempts unload. All counted writes must complete; short writes and close
failures force a nonzero process exit. Read handles are closed before any load;
failed closes prevent loading and are left to DOS process teardown, without retry.

The counted, ASCII CRLF log ends with `RESULT_CODE=xxxx` and
`END=BEFORE_LOG_CLOSE`. **A complete log is not proof of successful final close**;
capture the DOS process exit separately. Exit 0 means the preflight and both API
responses succeeded and log writes/close succeeded. Other exits are 1 (log create),
3 (entry absent), 4 (file preflight/close), 5 (load), 6 (unload), E0h (log write),
or E1h (log close). Write/close faults can supersede an earlier result; retained raw
records contain the initiating native error when their writes succeeded. Returned
CF/AX disagreement is a failed API response, never success. Error constants such
as 3 (file open), 6 (bad device file), 7 (device refused), or 5 (duplicate device)
come from the archived Win98 interface header; the experiment records raw values.

Synchronous VxD calls have no internal time limit. The harness must impose a guest
watchdog. There are at most one version, one load and one unload call, with finite
read/format loops. An unload error leaves ownership unresolved; stop and discard
the fresh guest trial. Successful V86 load/unload does not exercise W32_DEVICEIOCONTROL,
prove a version query, or prove resident LE objects were physically reclaimed.

Build and host-only test commands, from the repository root:

```text
python3 -B ntwrapper/vxd/v86diag/build.py
PYTHONPATH=/private/verified/unicorn/site python3 -B ntwrapper/vxd/v86diag/test.py --tool-provenance /private/verified/unicorn/provenance.json
```

Only `ntwrapper/vxd/build/v86diag/` receives generated COM, listing, disassembly,
embedded input, receipts, and host logs. The test uses Unicorn 2.1.4 as a build/test
tool to execute the actual COM instructions with synthetic DOS/loader callbacks;
it is never linked or shipped in the OS. The pinned tool provenance accompanies
the receipt. No host test establishes the Win98 V86 ABI. No guest is started by
these scripts. For a separately authorized fresh Win98 DOS prompt trial, copy the
original COM and its byte-matched candidate into the owned `C:\NTWLAB` directory,
ensure `NTWLDR.LOG` is absent, then run `C:\NTWLAB\NTWLDR.COM`. Keep all prior
trial logs in their separate evidence directories; do not delete them to rerun.

The references record which facts are original Win98 declarations, older official
documentation, or first-person historical research. They do not certify the
Windows 98 loader implementation.
