# Bounded native Windows 98 diagnostic capture

This controller runs one prepared, source-bound private cold VM for 20–900 seconds
(default 300). L0 KVM hosts L1 UEFI/Supervisor; the native domain must create its
own L2 VMCS. Its installed Windows 98 disk still boots original Microsoft DOS.
Collection success never attests to Windows VMM/GUI startup, ShizukuDOS replacing
MS-DOS, modern applications, or a completed ShizukuOS release.

The preserved 300-second and 900-second original-DOS controls reached Microsoft
ScanDisk at 99%. Neither established a Windows VMM or GUI transition. Their old
collector had weaker lifecycle/pin gates; the hardened source does not retroactively
upgrade those receipts or replace any preserved media, logs or screenshots.

## Explicit source identity

Supply a fresh private plan, its SHA-256 and the exact runtime helper identity:

```sh
python3 shizukudos/supervisor/native_win98/run_vm.py \
  --plan /private/owned-run/vm-plan.json --plan-sha256 PLAN_SHA256 \
  --repo /private/frozen-runtime-source \
  --runtime-sources-sha256 HELPER_MAP_SHA256 --timeout 900
```

`HELPER_MAP_SHA256` is SHA-256 of UTF-8 JSON with sorted keys and compact `(',',':')`
separators mapping the following repository-relative paths to their file SHA-256:

- `shizukudos/supervisor/native_win98/build.py`
- `shizukudos/supervisor/native_win98/prepare_vm.py`
- `shizukudos/tools/qemu.py`
- `shizukudos/tools/shzinfo.py`

Each helper is nonempty and at most 1 MiB. The explicit identity and frozen copies
are verified **before importing a helper**. The executed controller and its
`owned_capture.py` are also frozen and held under read leases. The builder-pinned
C evidence header must match the source-bound ESP producer, and the Python/C
layout is compiled and compared before launch.

Future preparation plans may include `preparation_runtime_helpers_sha256`, the
same four-file map captured before preparation and checked afterward. When present,
the controller requires an exact match before any helper import. Existing plans
remain usable with the explicit CLI identity; their receipts correctly record
`preparation_helper_source_pins_verified: false`. A current runtime snapshot does
not establish the source identity of a historical preparation.

## Ownership, bounds and result semantics

All six original builder inputs, all five preparation inputs, the plan, runtime
sources and evidence header remain read-leased through capture and owned cleanup.
The writable ESP and firmware variables use distinct owned inodes. QMP checks
Linux `SO_PEERCRED` against the exact `Popen` PID before capabilities, uses request
IDs, limits events and bytes, and applies absolute request/observation deadlines.
Only that owned child is signalled.

Before launch, disk admission requires **17 GiB retained free space plus 1 GiB**
for sampled ESP writes (256 MiB), three retained logs (64 MiB each), captures
(256 MiB total) and metadata/in-flight slack. This is a sampled write limit, not
an I/O throttle or a system-wide reservation. The running and final free-space
gates preserve the 17 GiB requirement. RAM admission requires 6 GiB MemAvailable
for the 4 GiB L1 VM and a 2 GiB host margin; the margin is checked while collecting.
Concurrent unrelated consumers can still trigger a failed collection.

Serial, debugcon and stderr use owned pipes, continuously drained into bounded
regular files. Overflow is discarded and recorded as a collection failure; it
cannot grow those log files without limit. Captures have per-file and aggregate
limits; PNG IHDR geometry is checked, and the evidence read must be exactly the
configured 8192 bytes. Header checks are not a complete PNG decoder. The final
owned VM pause and ESP counter sample must succeed before orderly quit.

The observation deadline is separate from the bounded final sample and cleanup.
QMP quit, normal wait, terminate wait and kill wait have explicit limits. Pipe
draining continues during shutdown. Any QMP quit error, forced shutdown, failed
reap, final input/source mismatch, lease break, resource violation or receipt
failure makes collection fail. An unkillable child remains an unresolved owned
process; the receipt records its PID, `owned_child_reaped: false`, and
`unresolved_owned_child: true`. Original read leases are released when this
controller exits; they cannot be promised to survive an unreaped process. That
child uses only owned clones. Do not treat the lifecycle as complete or reuse
that run while the owned process remains alive.

Canonical `native-result.json` is installed only after a complete write, fsync
and close to an exclusive same-directory temporary file and atomic replacement.
A partial valid JSON followed by disk/flush/close failure never becomes a
canonical success receipt. Failed temporary files are removed. If canonical
persistence itself fails, the command returns failure and reports it on stdout;
it cannot promise a result file on unavailable storage.

Exit 0 means **verified diagnostic collection only**. A faithfully captured guest
triple fault may have status `NATIVE_WINDOWS98_DOMAIN_FAILED` and exit 0 while
`collection_verified` is true. Always read the status and acceptance flags. QEMU
exit 0, VMCS activity and firmware progress are not Windows acceptance. All
Windows GUI, native Windows completion, MS-DOS replacement and modern-app flags
remain false in this controller.

No keyboard input is sent. Intervention needs an actual unambiguous prompt and
verified native input focus/routing. Public source handoff excludes private guest
media, absolute original input paths in documentation and private screenshots.

## Focused host verification

```sh
python3 -B -W error::ResourceWarning -m unittest discover \
  -s shizukudos/supervisor/native_win98/tests
```

The actual-main host fixtures use tiny owned inputs and modeled QEMU/VMCS; they
exercise failure decisions without running Windows or changing original media.
Separate actual Unix sockets verify peer PID, response ID, event/byte/deadline
limits. Real OS pipes and file descriptors verify bounded drains and cleanup;
partial-valid-JSON, fsync, close and replace failures verify atomic persistence.
These controls do not establish guest boot or native hardware support.
