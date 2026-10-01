# c957 partial timer and work capability contract closure

Code commit: `f3441a6df5953ef49dbd3a6b67367febcc445b44`.
Its parent/source snapshot is `3668b26c0dbbba56f39153824bc7f65c8c69a1c5`
in `/root/Win98-Modern-pma-c957-compat-20261002`. This status is a separate
follow-up; the original inventory and historical/native records are preserved.
Integration needs the existing capability inventory before this narrow commit.

## Scope and ownership

Only these existing inventory files changed:

- `ntwrapper/capabilities/manifest.json`
- `ntwrapper/capabilities/validate.py`
- `ntwrapper/capabilities/test_validate.py`
- `ntwrapper/capabilities/README.md`

This new status is the only documentation change outside that directory.
No driver, timer, worker, scheduler, PMA, VxD, display, font, runtime or
peer-worktree implementation was modified. Root retains the reserved framebuffer
address overlap repair and final merged-source acceptance.

## Inspected contracts and decisions

The fd5c review was verified against the actual source, not adopted as a new
runtime behavior requirement.

- `ntdrv_ke.c:405` `timer_set` returns its captured prior
  `Header.SignalState != 0`, not prior insertion. It sets `Header.Inserted`
  before `timer_arm` attempts admission to a 32-entry list (`:399`). A full list
  can therefore leave the inserted flag set without registering that timer.
  Negative due-time magnitude is divided by 10000 with a minimum one-tick
  delay; nonnegative absolute time is approximated as one tick. These are
  explicitly partial source semantics, not Windows timer parity.
- `ntdrv_ex.c:679` `ExQueueWorkItem` ignores `queue_type` and calls
  `ntdrv_queue_system_work` in `ntdrv_io.c:807`. Normal allocation routes through
  `IoQueueWorkItem`, the existing queue, worker and `syswork_run`. Allocation
  failure executes `fn(ctx)` synchronously at caller IRQL without explicit
  lowering, so every callback cannot be described as deferred PASSIVE work.

Both rows now carry policy-checked `source_semantics` and helper
`source_dependencies`. The Ex API explicitly includes `ntdrv_io.c`, rather than
depending on that file's presence elsewhere in the catalog. Relevant helper
bodies are checked after stripping comments/string contents and balancing
braces. Definition/exports, Microsoft x64 ABI, ownership, synchronization and
partial status checks remain in effect. These are lexical source gates, not a C
parser, compilation result, API behavioral test or guarantee against every
possible source change.

## Verification and effects

Exact approved command:

```text
python3 -B -m unittest discover -s ntwrapper/capabilities -p test_validate.py -v
```

Tests first reproduced false acceptance:

- Initial 8 controls: `Ran 64 tests in 8.135s`, `FAILED (failures=8)`;
  existing 56 tests passed. After the first implementation: 64 passed in 19.072s.
- Three further controls: `Ran 67 tests in 27.693s`, `FAILED (failures=3)`;
  changed normal worker dispatch, callback argument and an optimistic IRQL field
  were still accepted before their source/policy checks were added.
- Final source: `Ran 67 tests in 13.769s`, `OK`, exit 0. The 11 added controls
  cover signal return, absolute due-time approximation, bounded admission,
  allocation-failure callback, normal dispatch, callback argument, required
  provider dependency, inflated manifest semantics/IRQL and explicit receipt
  contracts. Mutations use owned temporary source copies only.

Exact approved receipt command:

```text
python3 -B ntwrapper/capabilities/validate.py --out build/pma-c957-compat/capabilities.json
```

Output, exit 0:

```text
PASS: source capability inventory: 120 families, 56 frontend APIs, 17 backend APIs; receipt build/pma-c957-compat/capabilities.json; behavior/native tests not run
```

The generated build receipt is not committed. Its SHA-256 is
`4f0aae91bb5d94c29d56e7e5e4f53afb7e2e74c9a7bd2d4cbde2eb9e38de171f`.
Advertised NTWG/W64 masks remain `0x3f`/`0x1f`. Behavior tests, native Win98-W64,
native Win98-PMA and replacement-DOS boot acceptance flags remain false;
historical evidence execution remains `not_run`. `git diff --check` passed.
No compiler, VM, native repository build, network, download, service or global
client configuration was used. Python bytecode writes were disabled.

## Exact source snapshot

| Source | SHA-256 |
| --- | --- |
| `shizukudos/kernel64/ntdrv_ke.c` | `62a64575444c419c7bf94c3e0529473217e14b154bbefe63214e103f2a35af3d` |
| `shizukudos/kernel64/ntdrv_ex.c` | `d7718d838bee8cac2ee4133afbccb93ccf6983c8b8cc44f3d1d0007c913bcead` |
| `shizukudos/kernel64/ntdrv_io.c` | `7aeac2266ba0977af85413b1c23a516495b71b8e90b279d25f113b95013b9e90` |
| `shizukudos/kernel64/ntdrv_prov.c` | `e727f0a70a4e9031fbdeb50935e090fe0017e4c7b9e0050bc6c452d1f5faed96` |
| `ntwrapper/capabilities/manifest.json` | `23a8857a76b3596a8d105da046fc1ef73721d94d20fc14252b382457b5b5f8c4` |
| `ntwrapper/capabilities/validate.py` | `a2d944ac10cbc696342cfc0f76a475e54c15b649796163105b3a8afb4e7501c8` |

## Dependencies, blockers and remaining work

No local inventory blocker remains. Root must rerun the approved source suite
and generate a fresh receipt after integration so hashes describe the actual
merged source, especially the independently changing driver/PMA/VxD code.
Driver behavior tests and native Windows 98 acceptance were not run here.
Actual channel 2/Windows peer execution, VMM-owned waits/completions and lifecycle
handling, USER/GDI application integration and Windows 98 boot over the ShizukuDOS
foundation remain separate acceptance gates. This commit neither fixes the
partial timer/work behavior nor claims those gates passed.
