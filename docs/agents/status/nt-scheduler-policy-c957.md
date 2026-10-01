# c957 partial NT priority projection

Source commit `f1e7750` contains only the common helper and its two tests.
The new common nt_sched_policy.h is a pure, unwired projection helper. It
accepts five non-realtime Win32 process classes and seven documented thread
levels:35 combinations. It retains the process class, requested relative
level, NT base increment and projected absolute base priority. Normal/normal
maps to8/0; Win32 IDLE/TIME_CRITICAL ±15 maps to raw NT class3 ±16 saturation.
High+2 and High+15 both project to15 but retain different requests. Realtime
and resource background mode are unsupported; invalid classes/gaps and NULL
outputs are invalid. Refusals preserve output bytes and validate bounded
scalars before arithmetic, including INT32 extremes.

This implements no NTSTATUS, thread information class, handle resolution,
access rights, process/thread object storage, dynamic boosting, quantum,
affinity, API behavior or runtime mutation. No existing runtime consumes it.
The Win64 frontend/IPC setters and user-thread initialization remain separate
coordinated work; fd5c owns IPC/object seams and163f owns scheduler/init seams.
The shared mailbox is `MESSAGE-c957-FD5C-163F-NT-SCHEDULER-CONTRACT-AUDIT.md`.

Production contract references are the
[Microsoft priority table](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities)
and independently inspected
[ReactOS kernel32 conversion](https://github.com/reactos/reactos/blob/master/dll/win32/kernel32/client/thread.c).
No external implementation body is imported.

Actual unsupported-stub RED compiled successfully, then failed2370 of3456
contract checks in each GCC and Clang ASan/UBSan run. Frozen RED receipt:
`build/pma-c957-nt-policy-red/result.json`, SHA256
`0415408e053d57d620df890ce109d769f520bc422128541f182fc53c9261e797`.
Actual production-helper GREEN passes3456 checks/0 failures in each compiler.
i486 and baseline x64 freestanding consumers compile without unresolved
symbols. Frozen GREEN receipt `build/pma-c957-nt-policy-green/result.json`,
SHA256 `83112d5282b40e0109d95cf8f60d77b9b1a0107658b174ace056fdd7153b424a`.
An independent reviewer approves semantics, literal table/refusal coverage,
frozen inputs, compiler/artifact identities and both RED/GREEN evidence.

Source SHA256:

| File | SHA256 |
| --- | --- |
| kcommon/nt_sched_policy.h | `f956c143494bffb5cbb9ac3e2e106f1cf7673c2a581c10cc59f17e3d3a26f236` |
| tests/test_nt_sched_policy.c | `d5065a5f3cebbe25dda06e2850a066a60cba8cc322872f41f4005742d397dfbb` |
| tests/test_nt_sched_policy.py | `a4811c3ce08e209cbf0f776a185b55d73f262553779da978016da047079c4c73` |

The new common header increases kbuild's complete source inventory212→213
even while unused. Prior212-source whole-kernel receipts retain their frozen
epoch and are historical for subsequent complete-tree builds. No new whole
kernel, Win64 runtime, VM, private media or NAS build is claimed here.
