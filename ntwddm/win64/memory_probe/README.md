# Actual AMD64 loader and basic-memory diagnostic

This original GPL-2.0-only probe executes in a sealed, private ShizukuDOS
Kernel64 guest. It consumes the immutable 143-member Modern+memory extension
archive and changes no existing bridge, provider, archive, peer source, client
configuration, native Windows 98 disk, or another VM's controls.

The first records compare A/W file attributes, live read-open, exact candidate
size and a 64-byte MZ-header read at `C:\SHZ\SYS64\KERNELBASE.DLL`. The probe
then tries lower-case ANSI basename, upper-case Unicode basename, and Unicode
absolute path. It saves exact handles and last errors before logging, records
module filenames, and resolves three adapter pointers plus the genuine
GetCurrentProcessId forwarder. Failed loading remains a failed diagnostic;
archive member count is not treated as proof of live filesystem access.

Only successful absolute loading and three nonzero dynamic API pointers permit
the memory trials. They execute real reserve/commit, zeroed and writable owned
memory, reservation conflicts, exact queried ownership, pagefile-backed writable
and read-only coherent views, a private copy-on-write view, real endpoint failures,
unsupported-parameter refusal, interior/private/double-unmap refusal, views that
outlive their mapping handle, and explicit cleanup. No memory endpoint is mocked.

`tools/win64_memory_probe_trial.py` creates a unique nonce-bound, freestanding
AMD64 PE32+ executable, checks its actual imports against the real archive, and
builds a private FAT image containing only this executable and autorun control.
The dedicated runner reuses hash-bound reviewed host helpers and independently
seals boot stub, kernel, archive, QEMU and firmware. It requires the existing
20 GiB free-space floor, 256 MiB private-write quota and 16 MiB combined own-output
limit. KVM evidence comes from its own live QEMU process descriptors. There is
no attached network device.

Evidence must come from the exact autorun child, executable, PID and fresh nonce.
Per-assertion and final counters must agree. The external kernel must report
normal exit 0 for PASS or normal exit 1 for a failed diagnostic, with no process
fault. Final `reaped=0` records the successful raw `proc_wait` return value;
the still-live-thread diagnostic branch is rejected. Loader results and basic
memory assertions are recorded separately. None of these prove Signal, Office,
Windows 98 integration or the complete modern memory API surface works.

Commands, using new owned directories:

```text
python3 -B tools/win64_memory_probe_trial.py prepare --overlay build/required-memory-runtime-6970-v1/extension-overlay.json --out build/new-memory-preparation
python3 -B tools/win64_memory_probe_trial.py run --prepared build/new-memory-preparation/prepared.json --out build/new-memory-run --qemu /usr/libexec/qemu-kvm --timeout 60 --firmware-dir /usr/share/qemu-kvm --firmware-dir /usr/share/seabios --firmware-dir /usr/share/seavgabios
python3 -B -m unittest discover -s tests -p test_win64_memory_probe_trial.py
```

The evidence-gate tests reject stale or spoofed nonces, executable/PID mismatches,
unprefixed markers, missing or contradictory content/handle/API records, wrong
counts, incomplete memory scopes, failure-shaped memory assertions, timeouts,
faults and absent/ambiguous external process completion. A loader failure cannot
be promoted to memory execution; it also does not erase independently completed
memory assertions when absolute loading worked.

The first frozen v2 preparation and real trial completed with 69 guest assertions,
zero failures, actual child exit 0 and successful raw proc_wait 0. Own live QEMU
descriptors proved `/dev/kvm`, a KVM VM and vCPU; original and sealed inputs were
preserved. The live candidate's 69609-byte size and MZ header matched, and all
three name/path loads returned the same module with error 0. The trial and exact
hashes are recorded in `handoff.json`, `build/mp64-run-v1/memory-diagnostic.json`
and its serial log. The diagnostic gate has 29 host tests.

The standalone QEMU's raw return 1 is the expected isa-debug-exit encoding of the
guest's debug-exit value 0. Actual child exit status is independently taken from
the kernel's final autorun result, rather than QEMU's host exit encoding. Earlier
Signal startup failures remain retained; this isolated direct-call PASS does not
resolve the app-specific loading behavior or demonstrate Signal functionality.

An independent read-only comparison rehashed the actual sealed boot stub, kernel,
runtime archive, QEMU and every firmware object against the retained
`signal-memory-themed-run-v1`: all were byte-identical. The six captured peer
helper hashes, their current files and common consumer recipes also matched.
Normalized launch flags differed only in RAM (this diagnostic 1024 MiB; Signal
4096 MiB). App, arguments, D: FAT payload/cwd and timeouts differed. Signal still
reports Kernelbase load failure at serial line 83 and optional memory lookups
against Signal.exe at lines 99–101. The discrepancy therefore remains dependent
on caller/loader state or other execution context; no changed shared runtime
explains it. The exact comparison is retained in
`build/memory-runtime-comparison-6970-v1/comparison.json`; no additional VM was
launched and no earlier attempt was edited.
