# Private AMD64 loader ordering diagnostic

SPDX-License-Identifier: GPL-2.0-only

This original freestanding probe derives its genuine memory ownership trials from the immutable `../memory_probe/probe.c`; `lineage.json` records that source hash. `preservation.json` binds the existing 69-PASS proof, the pinned KERNELBASE candidate and overlay, and both stopped Signal attempts. The dedicated wrapper refuses changed preserved inputs. Neither probe modifies the peer loader or existing provider/consumer sources.

The controlled sequence starts with the exact absent `api-ms-win-core-fibers-l1-1-2.dll` contract using LoadLibraryExW with LOAD_LIBRARY_SEARCH_SYSTEM32. Before any file attributes or candidate file reads, it then requests KERNELBASE with ExW and ExA using that flag, plain lower/upper basenames, and the SYS64 absolute path. Each handle and last error is captured immediately. Only after every initial load does it record module paths and inspect real file attributes, exact candidate size, and 64 MZ-header bytes. If the absolute load provides genuine functions, it executes actual private-memory, mapping, copy-on-write, invalid-parameter, ownership and cleanup trials.

[Microsoft LoadLibraryExW documentation](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw) specifies the reserved NULL file handle, the 0x800 SYSTEM32 search flag, and NULL plus GetLastError on failure. The probe uses the documented Windows AMD64 ABI and includes no Microsoft implementation code. It never supplies a replacement fiber contract or synthesizes a module handle.

A fresh nonce binds every attempt. The parser validates the exact child executable/PID, ordered six-value load sequence, absence of earlier file inspection, individual assertion totals, dynamic addresses, and external normal process result. `reaped=0` means successful raw proc_wait, not a Boolean failure. QEMU's isa-debug-exit code is recorded separately. Failed loader assertions retain independent memory results; timeout/fault/stale or contradictory logs cannot verify either branch.

The private trial uses the existing sealed 143-member Modern+memory overlay, 1024 MiB RAM, KVM, no guest NIC, a read-only FAT source image with a private snapshot, a 60-second host / 30-second child bound, a 20 GiB free-space floor, 256 MiB private writes and 16 MiB own output. Actual owned-process KVM file descriptors and original/sealed input preservation are mandatory.

The modern Signal app still fails to load KERNELBASE with the same overlay at both 4096 and 1024 MiB. This isolated diagnostic can test the proposed ordering/search-flag difference; it does not reproduce application concurrency or prove why Signal fails. Native Windows 98, full modern memory APIs, app usability, Office support and global OS compatibility remain unverified.

Use the dedicated `tools/win64_memory_loader_probe_trial.py` prepare/run commands in a new owned build directory. The original 69-PASS source and trial must remain unchanged; every future variant needs a new source binding and preparation.

## Retained actual result

The owned `build/lp64-run-v1/loader-diagnostic.json` passes 76 genuine guest assertions with fresh nonce `646abcd430094f858241e5e534c6f131`, child exit 0 and successful raw proc_wait 0. All five initial KERNELBASE load forms return the same actual module and zero error after the missing fiber contract fails with error 126. The repeated memory ownership trials also pass. No file inspection precedes those loads.

An independent final audit in `build/lp64-final-audit-root-v1/audit.json` verifies the stopped process, actual KVM use, unchanged inputs, sealed candidate bytes and normalized machine flags identical to the retained 1024-MiB Signal trial. All 37 parser, resource and preservation regressions pass. `handoff.json` binds the result and audit hashes.

This result rules out the tested load ordering/search flags as a sufficient reproduction of Signal's failure. Application context, concurrency and other runtime state remain unresolved; this does not justify a loader patch or establish Signal usability.
