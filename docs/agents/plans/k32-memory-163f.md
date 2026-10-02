# Kernel32 allocator concurrency prerequisite

Root owns this isolated lane at d91e1bc. Windows98 stays the OS, native Windows
stays one virtual CPU. This is an allocator prerequisite; no Kernel32 AP
bootstrap, page-table concurrency or full SMP acceptance follows from it.

1. Capture actual mem.c, k32.h, ABI and existing pma_sync.h before execution.
   Exercise the actual PMM/heap with checked fixed low host mappings, local
   IRQ adapters and concurrent real host threads. Preserve an actual original
   concurrency/conservation RED and existing valid single-owner behavior.
2. Reuse existing pma_ticketlock_t for separate PMM and heap ownership. Mask
   local IRQ before ticket admission; release ticket before restoring IF.
   Keep page zeroing outside the PMM ticket after unique ownership is reserved.
   Protect counters under their owner, initialize before concurrent admission.
   Retain existing allocator API and heap geometry. Refuse zero/overflow sizes
   and invalid heap pointers before mutation using actual allocated block
   boundaries. VM map/unmap/root reclamation remains owner-restricted and is
   not included in this prerequisite.
3. Run meaningful actual-C concurrent uniqueness/content/free conservation,
   exhaustion/reuse and rejected-size/pointer controls with GCC and Clang
   ASan/UBSan. Bound processes to60s and owned outputs to64MiB, with no compiler
   dependency copies. Pin helper bytes before execution and discover actual
   local headers before compile, retain commands and executable/source hashes.
4. Freeze for independent review before commit/import. Later canonical compile
   and native regression bind merged source; host controls alone do not prove
   physical AP operation, generic MM lifetime safety or Windows runtime.

Owned paths: shizukudos/kernel32/mem.c, new
shizukudos/tests/test_k32_memory_concurrency.c and test_k32_memory_concurrency.py,
this plan and docs/agents/status/k32-memory.md. No shared scheduler, K64, TLB,
Supervisor, peer worktree, private media or global configuration mutation.
