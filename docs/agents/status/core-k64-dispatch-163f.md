# Kernel64 dispatcher/entry foundation, 163f

Own branch `codex/k64-dispatch-163f-20261002`, base
`0fffd07dd22bd23a6005731e8c3a1f5118106066`, isolated worktree
`/root/Win98-Modern-k64-dispatch-163f-20261002`. Root approved Tasks 1–3
in [the plan](../plans/core-k64-dispatch-163f.md). No canonical/source-index
mutation, commit or guest execution occurred in this epoch.

Production dispatch consumes the actual logical owner's current/idle/outgoing
record. Common dispatch/completion primitives preserve live-stack ownership and
release the queue ticket before context transfer. Only BSP advances wall time
and enters shared timeout/object/wait/process paths. AP registration remains
unsupported, scheduler online mask remains 1 and Windows remains one vCPU.

SYSCALL uses the reserved existing `shz_smp_cpus` anchor through a short paired
SWAPGS. Ordinary GS stays per-thread NT KPCR/TEB. Anchor binding runs after
topology preparation/reset in `sched_init`; all dispatch and the one assigned
`proc.c:user_thread_main` publication use the checked stack setter. AP private
TSS/syscall entry remains unsupported without an owning handoff.

BSP NMI and DF have distinct retained ISTs. Exact CPL0 interrupted-RIP
classification restores ordinary GS before C, remembers correction in the
saved frame's callee-saved register state and reverses it before IRET. Actual
entry bytes include LFENCE at all three reviewed boundaries. NMI/DF terminal
handling skips shared recovery callbacks. Timer scheduling still uses IST0.
This is C/assembled-byte evidence, not proof of hardware NMI entry. A separately
reviewed QMP true-NMI diagnostic and native UP gates remain required.

The policy remains 32 priorities/FIFO, 32-tick aging, quantum 1..16 and fixed
independent aged service 4. `pma_tests.c` and all original thresholds are unchanged.

## Preserved RED and limitations

- `build/k64-dispatch-red-2/tests/result.json`, SHA
  `3d02d698afa42166b9372c0bfbd130807b2816ac1aca7e1d95964f13fe4a44f6`:
  actual sched/provider C runtime fails owner-local current/accounting and absent
  stack publication. Actual legacy ASM still references singleton scratch.
- `build/k64-dispatch-ist-barrier-red-2/tests/result.json`, SHA
  `6c6e400a4674a6620af1da9437dfe11602027da20ecb56cf6d348a1995efb3f7`:
  actual NMI/DF C can reach driver recovery callbacks; all three assembled
  speculation-barrier assertions fail before their fixes.
- Initial harness compile/link failures are preserved separately as infrastructure;
  they are not promoted to semantic RED. Host GCC dynamic sanitizer libraries are
  absent; GCC uses ordinary host controls and Clang uses ASAN/UBSAN.
- Parallel final GCC queue run hit its unchanged outer 60-second timeout, SHA
  `b62c67c7de18df046bb656f23621273a4ac595284d447a5beb15779594ac041a`.
  Cause remains unattributed. The isolated diagnostic successor completed without
  a production change; its receipt SHA is
  `746c1ec84181162bb202d98f7428086817faf3a07de53641884d6234f63158e2`.
  No production bound or host timeout was enlarged.

## First frozen serialized host evidence

`build/k64-dispatch-final-host-6/validation.json`, SHA
`30037bf934f8709fe45a81082d56af03d1ed5bf631833776935870924b8101d3`,
is terminal PASS with tool and captured-helper bytes stable before/after.
GCC and Clang ASAN/UBSAN each pass 20 actual scheduler/provider controls, 12 actual
architecture/provider controls, 7 queue/context controls and 8 actual ASM
classifier controls, plus singleton-relocation and three barrier gates. A
controlled host-only watchdog failure at the actual modeled stack handoff emits
completed/last-step/current/outgoing/ticket fields and exits 124; its expected
negative control is accepted separately. No real AP or privileged SWAPGS is run.

Six genuinely concurrent host logical owners perform 12,000 actual queue/context
handoffs, conserving all thread identities/current/outgoing/ready ownership.
The final measured durations are 32.241592s GCC and 20.371851s Clang, each owner
completing 2,000 epochs. The timeout watchdog emits bounded diagnostics at 50s
before the unchanged outer 60s limit; these results do not explain the earlier
parallel timeout.

Original UP API and queue regressions each remain 27 + 13 PASS under both
compilers. These execute actual production C with privileged boundaries
substituted; they do not prove native preemption.

Final nested receipt hashes:

- New GCC: `26205a17a80b11f0ac376a9f8b206dc337071aef4fa30250d6af2ce2af013375`.
- New Clang: `2477b33c97fc5147d9ddc7644904d226de1dbe64855ebf55f995534c703cc8c6`.
- Original UP GCC: `405ca97a4cbe6ac393165d215c3486ca574515e1fbe1d10ed2b983090977c7ba`.
- Original UP Clang: `dc218982f0505bf183df84844dada4c2a441395b4e8ecd01aaee43fa96f9d993`.

## Frozen production pins

| File | SHA256 |
| --- | --- |
| `kernel64/arch.c` | `ba0f8e1a7dd18db47aa18bd0b8cf122b9381c9686cfede24b955b98f5116207e` |
| `kernel64/k64.h` | `0524c3c1f95792168946a8b0bdb6d30342187a06bfb29eb47afcdd2c463e2622` |
| `kernel64/proc.c` | `015f08d80b8dc9f64ab82bfc24c0e55b757ed508d824a36084fb7b3c7903904a` |
| `kernel64/sched.c` | `5dbf099497e60259ea5bc7fb3cc095d655b8785c7fa043cd496017b73b44f313` |
| `kernel64/sched_cpu.h` | `738b2ba5250a4f6c81714cf5d687388074ddcb8dedf63938ea2c040628c92585` |
| `kernel64/start.asm` | `8c86881f3a452221cf034708fd7ef30667e4517588da550d9bf964cad332ce88` |

## First frozen actual compile epoch

`build/k64-dispatch-compile-epoch-1` is terminal
`PASS_FOUR_KERNEL_COMPILE` (110.408s). The actual captured production helpers
select all four kernel profiles and both standalone stubs. The 236-file build
inventory and 1,352-file source/helper superset remain stable before/after,
along with Python, GCC, cc1/collect2/as/ld, NASM, nm/objcopy/objdump and git.
No `.pyc` is loaded. Project compiler-MM dependencies are checked before all 229
profile C compilations, plus three owned freestanding unit compilations.
The six-profile CPP closure independently passes 229 units and the copied-fixture
header/omitted-C negative controls. Aggregate local output is about 80MiB before
the final archive, below the authorized 160MiB cap.

The compile validation SHA is
`4067359f6eb6f35c1f917c9aec433a953e84114e3427d3c19848f16a4576eaf1`;
the pre-execution source archive SHA is
`847dd15b0a8cda01ac29d18168fc0e5744675a66e722d8fe4aeb9a89c8c7066a`.

The ordinary K64S image SHA is
`b57b2183d4c1be82d062aa595c8b9ce5c8b4a24fe30f1b293e061f850b4ae2bf`;
its ELF SHA is
`65ac037de114095bc8bad9558f408de0a2c9c05c56f3faa904360e985df5e385`.
The ordinary kernel receipt SHA is
`8cc4a05bf8c3616d3d8fd6e0f5e2dbac3261303360ed49e053ce72aed5a2e033`;
the CPP receipt SHA is
`c20b4643f7a469a1063ddbbcab28fb76d5d7d8f73cd7bd7eb864d1bed3c63d57`.

## P2 callback boundary successor

Independent review identified the weak external dispatch observer running under
the common queue ticket. The first freeze and its archive remain unchanged:
`build/k64-dispatch-final-handoff-1/complete-evidence.zip`, SHA
`49fd29b25438c910bccbb8ccfdea48de2e5d4687cc7e9606d4881420a99df9ae`.

`build/k64-dispatch-callback-red-7/validation.json`, SHA
`86452db4bae3804b41c299c47d98f6e96e89f91bee671d3f0e8f42614c2274ce`,
captures GCC and Clang ASAN/UBSAN actual-C RED. A separate translation unit
strongly overrides the real weak hook. Three nonblocking real-ticket trylocks
fail on the changed trace, changed observe and unchanged combined-flag paths;
all IRQ-off, selected/current/outgoing ownership and wait-argument checks pass.
No deadlock is induced.

The production repair captures the observation arguments and bookkeeping under
the ticket, releases it once, then invokes the external hook with IF still clear
before either unchanged return or context transfer. Selected `on_cpu` and outgoing
live-stack ownership retain the TCB lifetime. Policy, queue/entry/provider code
and `pma_tests.c` are unchanged by this repair.

Successor GCC and Clang each pass 33 actual scheduler/override controls, 12 actual
architecture controls, 7 queue controls and 8 actual ASM classifier controls,
the four object gates and the separate expected watchdog failure. Both original
UP 27 + 13 suites pass. The six owners each complete 2,000 epochs, in 10.344278s
GCC and 23.419882s Clang. These passes do not explain the historical timeout.

The successor aggregate writer initially failed after all host runs and both
unit compiles because its command list retained Python `Path` objects. That
infrastructure failure is preserved in
`build/k64-dispatch-callback-green-8/validation-writer-failure.json`, SHA
`4cd3b15e46872525f4cf362e6785f4ba1ca8ca0f971c28a30840859356f64beb`.
Completed host tests were not repeated. A separately captured collector
reconciles all original host receipts, before/after source/helper/tool/artifact
maps and source snapshots, then freshly compiles only `sched.c` in backend and
standalone profiles with actual compiler-MM dependencies pinned first.

`build/k64-dispatch-callback-reconciled-9/validation.json`, SHA
`63ba88ff2938bc38f464003b6d612fa29fa84a3eb4eda594d1bf2340e1cd6a63`,
is terminal `PASS_RECONCILED_HOST_AND_FRESH_SCHED_UNITS`. The old four-kernel
receipt and artifacts bind the first freeze's scheduler, not this successor;
no full four-profile rebuild, guest or commit occurred for this repair.

Native UP,
hardware NMI, private AP dispatcher admission, 2/4 CPU useful preemption/migration,
shared object/driver/user/MM and Supervisor/Windows integration remain open.
