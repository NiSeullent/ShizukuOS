# Private AMD64 basic-memory bridge

`KERNELBASE.DLL` is an app-local candidate for the three dynamic probes observed
in the stopped Signal 8.28.0 trial. It does not modify Kernel32, the kernel, an
existing archive, native Windows 98, or client settings. Finding a function by
name does not prove Signal or the function works in the guest.

The original C implementation is GPL-2.0-only under the repository LICENSE.
Microsoft documentation supplied the ABI and semantics; no implementation code
was copied. Each build freezes the reviewed consumer source, archive, compiler
commands, generated export definition and this implementation's source hashes.

| Entry point | Supported translation | Explicit failures |
| --- | --- | --- |
| VirtualAlloc2 | NULL or current pseudo handle; zero extended elements; nonzero page-multiple size; optional allocation-granularity-aligned base; commit, reserve and optional top-down; exact noaccess, readonly, readwrite, execute, execute-read, execute-readwrite protection. The real VirtualAllocEx owns memory and validates reservation conflicts. | Real process handles, extended parameters, placeholders, reset, physical/large pages, write-watch, write-copy protection, guard/cache/CFG flags and unknown options. |
| MapViewOfFile3 | NULL or current pseudo handle; zero extended elements; allocation type 0; 64 KiB-aligned offset; zero or page-multiple size. Base rounds down to allocation granularity. Six exact read/write/copy and executable variants translate to MapViewOfFileEx access; actual mapping rights, section size, coherence and write-back remain with the kernel. | Real process handles, extended parameters, reserve, placeholders, large pages, noaccess/execute-only, guard/cache/CFG flags, unknown options, offset or offset+size beyond signed 64-bit owner capacity. |
| UnmapViewOfFile2 | Current pseudo handle, flags 0, exact allocation base of a mapped committed or reserved view. VirtualQuery checks the base/type before real UnmapViewOfFile transfers ownership. | NULL or real process handles, interior addresses, private/image allocations, transient boost, placeholder preservation, unknown flags. |

Valid real process handles are deliberately unsupported: identity alone does
not establish PROCESS_VM_OPERATION rights, and the older mapping endpoint
operates solely on the current process. Invalid handle query errors propagate.
No extended parameter memory is read or written. Unsupported calls never reach
the allocation/mapping/unmapping endpoint. Successful translations return its
pointer or BOOL directly and preserve its last-error behavior. The bridge
acquires no extra handles, regions, thread, hooks or loader-lock allocations.

Other named exports are exact forwarders to direct, nonzero KERNEL32 functions
found in the supplied frozen archive. Existing Kernel32 forwarders are excluded
to keep this adapter's graph one hop. The generated ordinals are private; Windows
Kernelbase ordinal compatibility is not claimed.

The host tests use owned heap regions to verify zeroed allocation transport,
full-width addresses and offsets, exact protection/access translation, underlying
failures, untouched extended inputs, unsupported-operation refusal, double-unmap,
and memory ownership. These are adapter tests, not guest VM-semantic tests. Builds
also run AddressSanitizer and UndefinedBehaviorSanitizer, validate actual PE32+
imports/exports, and inspect the real consumer archive. No VM starts.

Run from the worktree with an explicit hash-pinned stopped archive:

```text
python3 -B ntwddm/win64/memory_bridge/build.py --archive <WIN64.IMG> --archive-sha256 <SHA256> --peer-root /root/Win98-Modern-apps-cb43
```

Sources reviewed: kernel32/k32_mem.c, k32_ipc_section.c, k32_ipc_proc.c and
k32_misc.c; kernel64/syscall.c, vad.c and ipc_section.c; ntdll/ntdll_main.c.
They are read and frozen, never edited or executed by this builder.

Primary ABI and ownership references:

- [VirtualAlloc2](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2)
- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [MapViewOfFile3](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3)
- [MapViewOfFileEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffileex)
- [UnmapViewOfFile2](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile2)
- [UnmapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile)
