# Architecture decisions

1. User explicitly authorized actual implementation, all permissions and parallel agents. No repeated approval gate is added for covered local build/test steps.
2. Use the latest fetched `origin/main`, initially `a648e9b`, in a new isolated branch. The original `/root/Win98-Modern` checkout is 611 commits behind and is preserved.
3. The current source has native Win98 opt-in sources and real channel2 creation. The older architecture audit describes its own historical tree and is not rewritten.
4. Extend Kernel64's actual scheduler and NTWRAP9X's existing transport. A new PMA scheduler/VxD transport would duplicate working code.
5. Keep integrated SMP unclaimed: current per-thread CPU context, allocators and object state use UP/IRQ-only assumptions. CPU0 affinity validation is an explicit current limitation.
6. Copy the existing WIN64.IMG as a regression input only. SHA256: `a098a49fdf686973d5246f74e7f61d8257afced11ab28a11a7f4bd47c0dc7a7e`. Kernel source is freshly compiled; this copied input does not establish a new Win64 userland build.
7. Share one isolated integration branch with disjoint file ownership and serialized integration commits. This avoids blind edits and duplicate heavyweight builds; no lead writes another lead's files.
8. Cross-chat cooperation is required by the user. This chat owns scheduling policy, firmware mode choice and existing bridge safety; c957 owns fair atomic synchronization, framebuffer validation and capability manifest; 65e2 owns DOS serialization; fd5c owns integration gates. Publish scoped tested commits for reuse.
9. Outstanding bridge pool buffers cannot be freed merely on local reset while the peer may consume them. Preserve the existing allocation lifetime and report the missing terminal cancellation/rundown contract explicitly.
