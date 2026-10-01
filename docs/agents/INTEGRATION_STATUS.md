# Integration status

Status: baseline and implementation preparation; no new feature is yet reported passing.

| Acceptance area | Source audit | New execution evidence |
| --- | --- | --- |
| Timer-preemptive native scheduling | Exists in Kernel32/64; K64 table holds 1024 | Baseline build running |
| PMA policy/ready queue/synchronization stress | Existing mutex/semaphore/events; policy work assigned | Pending |
| Integrated native SMP | Standalone AP probes, global UP context/locks | Not implemented/verified |
| EDID/high-resolution GOP selection | Current mode snapshot only; work assigned | Pending |
| On-demand per-process VGA/SVGA | Limited Supervisor text/port model | Not implemented/verified |
| DOS service serialization and replacement boot | Existing DOS16; real DOS-to-VMM replacement unresolved | Not verified |
| Windows VMM/PMA bridge | Existing NTWRAP9X and channel2; safety work assigned | Host model pending; native Windows PMA waits not verified |
| Actual Windows 98 on replaced DOS foundation | Remains mandatory final gate | Not verified |
| Modern API through actual Windows→wrapper→PMA worker→result | Existing components, live-peer acceptance needed | Not verified |
| Full requested wrapper families/driver stacks | Reuse existing implementations; no empty DLL campaign | Not verified |

Build/test logs are owned outputs under this worktree's `build/`. Status reports identify whether evidence is host, freestanding-link, firmware, native kernel or actual Windows execution.
