# Kernel32 finite deadline repair plan — 6970

Windows 98 retains VMM scheduling. This repair is for the existing uniprocessor Shizuku Kernel32 backend worker scheduler; it adds no Windows scheduler or SMP claim.

## Existing failure and ownership

The current production scheduler multiplies uint32 milliseconds by1000 before dividing by TICK_US, and stores the absolute result in a uint32 wake_tick despite a uint64 clock. Long requests can expire immediately; a finite deadline of2^32 truncates to the zero infinite-wait sentinel. Source audit alone is not a RED execution.

This lane owns only kernel32/sched.c finite sleep/semaphore expressions, kernel32/k32.h wake_tick width, a new abi/shz_sched_deadline.h helper and dedicated tests. Session163f owns Kernel64 scheduling. Fd5c independently confirmed a different Kernel32 thread/process publication race and explicitly declined scheduler/header edits. Canonical session163f acknowledged this lane and retains its separate user.c publication repair. Preserve both changes by scoped merge.

## Test first

1. Author a host fixture including the actual complete k32.h and production sched.c. Substitute privileged IRQ/CR3/TSS/stack-switch boundaries only; do not substitute deadline arithmetic, queues, thread layout or sched_tick/sem_post logic.
2. Freeze source closure: fixture, runner, sched.c, k32.h, khc.h, shz_abi.h and start.asm. The existing main KVER-only header update can be imported as an explicitly recorded baseline before RED.
3. At fresh20GiB+8MiB admission run real compiler and fixture with bounded output and a live resource guard. A compile/harness/resource failure is not RED. Preserve actual unchanged-production assertion failures.
4. Cases cover4,294,968ms and UINT32_MAXms; clocks before/after2^32 including a deadline that truncates to0; sleep0 minimumone tick, timeout0 minimumone tick and sem_wait indefinite0; actual wake immediately before/at expiry; timeout/post both orders with waiter links, timeout marker and token count checked. Keep context-switch assembly stack pointer offset0.

## Small production change after RED

Widen wake_tick to64 bits. Replace only finite deadline expressions with one checked common conversion/addition helper. Convert positive uint32 tick intervals using quotient/remainder without unchecked multiplication/addition; clamp unrepresentable finite deadlines to UINT64_MAX. Preserve minimumone tick and the explicit zero infinite-wait sentinel. Leave mutex policy, process publication and Kernel64 untouched.

The clock at UINT64_MAX has no representable later absolute time. Saturation is a documented finite-clamp policy, not a proof of full counter rollover, arbitrary-duration modular ordering or monotonic clock calibration. Do not test sched_tick past that endpoint and infer correctness.

## GREEN and integration

Add the helper to exact source closure. Run actual production fixture normal and ASan/UBSan, actual compiler argv/hash/version/exits, identical meaningful assertions, no sanitizer errors, before/after closure hashes, bounded self-inclusive receipt and resource samples. An independent reviewer checks production code and the host-only hardware substitutions.

Share tested scoped commit with canonical master and sole main publisher. Re-run merged Kernel32 build/standalone regressions including fd5c publication repair when resources permit; HOST arithmetic/queue results do not establish assembly switching, hardware preemption, VMM integration or actual Windows98 boot.

## Frozen preparation checkpoint

The C fixture SHA-256 is ee88bc841221604fa56353a3b460c399f33cbea28fe4753b4bc44c02a407ca53. The runner SHA-256 is8b7d3c6d3d5bacdebc54412dbe9bb8b744d5c3df4701556b787ca9bab98a97db. The real production scheduler remains4819e88176c90dff11666e7aa59a904fb47178f0748ae78e9414b5f9d45749dc; the header baseline is97b924cc350c50c72321ea8dcb1b9f7b51a9f9e90daee8f84be189b183eba51c (only the already-published current-main KVER label was imported).

Independent source review covered hardware-only substitutions, accumulated assertion failures, actual long/above32-bit expiry ticks, timeout/post ordering, two waiters, rewait, resumed return and exit/join. Runner lifecycle now retains the owned process-group leader with nonreaping waitid until pipe drain/abort teardown; final receipt binds self-inclusive bytes and observed resource samples. Static inspection is not execution of those controls.

An actual RED CLI admission attempt returned BLOCKED_NOT_RUN/exit3 at20,095,266,816B free versus21,483,225,088B required, without creating the requested proof root or starting a compiler. All four frozen source hashes remained unchanged. Python syntax parsing passed without bytecode output. There is no actual C compile, RED, GREEN, descendant teardown negative-control or native acceptance yet. The prepared tests are committed for continuation in another environment; no production deadline repair is included.

Use a fresh absolute direct child of this checkout's build/k32-deadline-6970 for every actual proof. The runner derives paths from the checkout and rejects reused/symlinked/outside roots. Keep resource admission and compiler/sanitizer requirements when continuing.

## Actual hosted RED and GREEN

The local blocked attempt above is preserved. A separate GitHub-hosted Ubuntu
checkout ran the real production C under the same20 GiB reserve and8 MiB
aggregate output cap; there was no local below-floor compiler exception.
Public source workflow d47b21521d20941c27f594ef59724e8a46c52d30 pins checkout,
verifies GITHUB_SHA, derives a fresh run/attempt path and uploads no artifacts.

| Phase | Exact source | Actual result | Receipt SHA256 |
| --- | --- | --- | --- |
| [RED run36915348082](https://github.com/NiSeullent/Win98-Modern/actions/runs/36915348082) | d47b21521d20941c27f594ef59724e8a46c52d30 | GCC compile0, fixture1;22 expected failures of76 checks | 3cf2fcd2ccaa6f42be2ba1cec65a85951fecc3a8dbe455b5f63701fffca2193e |
| [GREEN run36916096646](https://github.com/NiSeullent/Win98-Modern/actions/runs/36916096646) | 6dfc4b574a023c4e4277bbc357b876cfbd82f70d | HOST76 and ASan/UBSan76 checks, zero failures; all6commands0 | 31bcdf1a527efaee6ec17274b8d7b1391709b5b710b09bf31f6be39d4bcac135 |

Both multiplication overflow and finite-zero collision failed on actual
unchanged production. Root reconstructed each receipt from actual job logs,
matched its logged SHA and checked closure against current source. Independent
review also rehashed the bounded RED log and cleared the small production
change before GREEN. GCC13.3 and Clang18.1 compiler identities, argv, exits,
executable hashes and source before/after identities are in the actual receipts.

GREEN eight-file closure includes the unchanged fixture/runner plus the helper;
final aggregate1,625,251B, minimum observed free92,384,980,992B, resource failure
absent and receipt accounting verified. The original HOST fixture and runner
hashes remain unchanged. Sanitizer stderr is empty.

Only wake_tick width and finite sleep/semaphore expressions changed, with a
positive-tick static assertion and bounded unsigned quotient/remainder helper.
Kernel64 scheduler and peer user.c publication source were untouched. Source
review confirms assembly retains ESP32 at offset0 and unsigned64 division
helpers exist, but actual i486 lowering/linking is a separate pending proof.

Actual Windows98, VMM, context-switch assembly, thread_create, unlocked/torn
clock reads, full64-bit counter rollover and deliberate descendant-abort
negative control remain unverified by these receipts. Combined main imports
must retain peer publication/storage changes and run their own closure tests.
