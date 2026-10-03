# Local file mapping coherence: component change and evidence

Independent file section objects previously allocated separate physical pages
even when they held the same local VFS node and page index. Mapped writes could
remain invisible to another section, and closing a section could overwrite a
newer write with its stale page. This violates the local mapping-to-mapping
contract documented for [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile).
That contract excludes remote-file coherence and does not guarantee coherence
between mappings and direct ReadFile/WriteFile accesses.

The change shares resident file pages by retained `fsnode_t *` and page index.
Each section's resident leaf holds one cache reference. Its last handle and view
must disappear before the section releases that reference. The final reference
removes the entry and frees the page; no node pointer remains in the cache.
Anonymous sections keep private zero pages. Existing view protection checks and
private copy-on-write pages remain unchanged; private copies never enter the
shared cache or get written back to the file.

The cache has 256 hash buckets and an interrupt-preserving atomic lock. Metadata
grows with resident shared pages. Allocation, VFS I/O and freeing stay outside
the cache lock. A second lookup handles competing acquisitions. A bucket epoch
also catches an intervening publication and final release: if another section
published, changed, wrote back and removed a page while a candidate was being
read, the candidate is discarded and read again. This avoids registering an
obsolete snapshot after the second lookup misses. Collision-related epoch
changes can cause an extra read, without publishing stale bytes.

## Verification

Run a new bounded output directory from the repository root:

```sh
python3 -B shizukudos/tests/test_file_section_cache_1a36.py \
  --out build/file-section-cache-review --compile-unit
```

The runner extracts the actual production page, free, view fault, COW and view
release bodies. It models allocator, VFS I/O, object references, page tables and
interrupt boundaries. It compiles and runs the same fixture with GCC, Clang,
and Clang ASan/UBSan. It also compiles the complete actual `ipc_section.c` with
the project's freestanding GCC/Clang flags for Supervisor and `SHZ_STANDALONE`.
The quoted source/header union is hashed before and after, and actual compiler
dependency files must stay in that pinned union. Each invocation has a 16 MiB
owned output budget and a 60-second limit per subprocess. No kernel image,
application, VM or installed Windows 98 session is run.

The 79 assertions cover live bidirectional sharing, distinct files/page indices
and anonymous sections, close ordering and recreation at the same node address,
final deletion, allocation/read failure cleanup, separate process page tables,
read-only protection, live view references after handle closure, private COW
cleanup and non-writeback, short-page zero fill, extension into a new page,
writeback clamped after a shrink, eight synchronized competing first reads, and
a deterministic snapshot/publication/writeback/final-release interleaving.
Object and per-section lifecycle counters are serialized in the host fixture;
only independent cache acquisitions overlap. This does not establish complete
kernel SMP correctness.

Retained evidence under the owner's ignored `build/file-section-cache-1a36`:

* `baseline-final`: original source at
  `8825950d9d3c19a83a4b23836a6418235ad12d57`, source SHA256
  `966b58505806bba16039dc34c665797c4392676e23a7056d2ca3063848293c2d`,
  76 checks / 19 failures under all three host profiles; no live pages or heap.
* `epoch-red`: initial shared-cache implementation, 79 checks / 2 failures
  under all three profiles. The delayed candidate restores stale bytes after
  the intervening mapped writeback and last release. This failed implementation
  is retained as `pre-epoch-ipc_section.c`.
* `green-epoch`: corrected actual source, 79 checks / 0 failures under all
  three profiles, no live pages or heap; four complete translation units pass.

The older baseline and first green results remain original observations; they
are not relabeled as executions of the final fixture.

## Limits and remaining work

Creation, mapping, flush, credential-store guards, handle authorization, ABI,
VFS and existing view bodies stay byte-identical to the source base. This cache
does not grant access through an alias or replace those guards. The host tests
do not run the full section system call path or actual guest page tables.
The unchanged `section_write_back` clamps writes to both section and current
file length, and still ignores lower-level write errors. Full file truncation
policy, direct file I/O coherence and durable flush failure reporting remain
separate VFS/authorization work.

Node identity relies on the existing section-held `open_count` contract. Peer
review identified a pre-existing exception in RAM rename: `sysfile.c` can
replace/free an old node even while its `open_count` includes a mapped section.
That path is outside this reserved cache seam and remains an actionable owner
finding. This change does not claim to make that rename safe or to prove all
node lifetimes. Normal last-reference removal/recreation is covered.

Retained Chromium GUIV2 logs for official snapshot 1706750 report persistent
allocator corruption and a NULL write at `chrome.dll+a0cbbc4`, followed by
`c0000005`. The exact DLL SHA256 is
`5a36d13089083cc3e84831bcac6f22d373217c00350d63d8492bc499371aae4c`.
The mapping defect is source-proven; its causal connection to that failure is
unconfirmed. A matching Chromium retry is reserved to the existing private
input/VM owner. No crash suppression or application success is claimed here.
The required product remains actual Windows 98 on ShizukuDOS, with modern
application surfaces in its native USER/GDI windows.
