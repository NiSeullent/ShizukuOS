# First independent Windows 98 native trial

On 2026-09-27, the original `NTW32.DLL` and prepared `NTWPROBE.EXE`
ran successfully on a newly installed Korean Windows 98 SE guest without
KernelEx. The complete three-probe suite **failed**: `NTWQUERY.EXE` could not
open the original VxD, and the runner therefore did not start the GDI probe.

| Observation | Result |
| --- | --- |
| Native OS identity | Platform 1, version 4.10, build 2222 |
| `NTWPROBE.EXE` process exit | 0; static-import test log reports PASS |
| `NTWQUERY.EXE` process exit | 1; first `CreateFileA` reports error 2 |
| `NTWGPROB.EXE` | Not started; no graphics log |
| `NTWRUN.EXE` batch-captured exit | 1 |
| Complete native acceptance | Failed; strict log validator rejects missing GDI log |

The DLL probe exercises the prepared static imports, dynamic API lookup,
single-thread SRW lock transitions, one-time initialization, tick-count
ordering, UTF-8/UTF-16 conversion and an ASCII ACP round trip. These are the
specific cases in [the original probe](../platform/tests/probe.c), not a claim
that arbitrary modern applications or all API semantics work. In particular,
this run does not establish multithreaded contention behavior or a tick wrap.

The VxD log ends at its first load attempt:

```text
START NTWrapper9x native VxD query ABI 0x00000001
BEGIN load cycle 0x00000001
FAIL CreateFile NTWRAP9X.VXD 0x00000002
```

This result does not establish whether the failure is path resolution, image
loading or driver initialization. No successful VMM service call, native kernel
binding, GDI execution or WDDM compatibility is claimed by this trial.

The guest used one KVM CPU, 128 MiB RAM, emulated i440fx/VGA, no network adapter
and a private Unix QMP socket. A clean installed snapshot was saved before
copying the original probe CD into a fresh `C:\NTWLAB` directory. The bounded
supervisor subsequently stopped its owned guest with QEMU exit 0. The installed
disk initially remained in private RAM because disk-reserve checks refused
persistence; a stopped process alone is not durable storage evidence.

After both guest and supervisor were absent, a read-only qcow2 conversion and
FAT file extraction recovered the logs and all six original binaries. The
source qcow2 hash stayed unchanged, temporary extraction storage was removed,
and every binary plus `RUNTEST.BAT` matched the independently re-extracted CD.
The accompanying [public receipt](NATIVE_FIRST_TRIAL.json) contains hashes and
original probe log text only. Windows media, the installed disk, screenshots
and the user-supplied registration value remain private.
