# Private corresponding-source Git checkpoints — 6d41

Actual Windows98 running on ShizukuDOS remains the delivery target. These are
host source-custody controls, with no private input admission, VM execution,
installer execution, Windows boot or actual x64 application acceptance.

The historical f903 corresponding-source host receipt reports 5326 regular
inputs, 5333 held descriptors, complete cleanup and 1409.624 seconds. Its
Windows authority was explicitly host-modeled. This work does not rerun that
full closure or claim a production ISO speedup.

`Union.io_check` previously invoked every guard at each actual hash/read
checkpoint. A small file produces three callbacks for one full SHA pass. The
project Git guard launched both `rev-parse HEAD` and a complete `git status`
each time, so the full-tree status scan was repeated for each source file.

Five read-only samples on the unchanged frozen f903 checkout gave median HEAD
10.402ms and clean status 42.667ms. Its 4471 committed regular blobs total
53,521,969 bytes and require 13,419 callbacks per full hash pass, computed from
actual committed extents and the one-MiB read loop. Multiplying the sampled
medians estimates 712.133 seconds of Git calls for one project-source pass.
This is a call-graph estimate, not a profile or a timing decomposition of the
historical 1409.624-second run.

The candidate changes only the actual-data checkpoint protocol. Guards with an
explicit `io_check` method use that checkpoint; existing callable guards are
still invoked immediately. `Union.check`, `BuildCustody.check` and all final
full-SHA paths continue invoking complete callable guard audits.

The private ISO Git epoch guard has no caller-configurable interval. Its IO
checkpoint forces a complete Git audit at least every fixed second, measured
from scan start. Every phase audit is immediate. Each audit verifies canonical
tree and Git metadata directory identity, actual top-level/metadata location,
HEAD and symbolic reference, anchored child repository URL and originally
required clean-tree status. Upstream patched trees preserve their original
HEAD-only cleanliness policy. Git calls disable optional locks, and each scan's
remaining one-second budget is passed to its subprocesses. Clock regression,
subprocess failure/timeout or a slow scan permanently refuses this guard.
A valid build can refuse on a loaded host; the bound is never extended.

Every actual-data callback retains immediate active FD/path/inode/read-lease
checks and the shared any-input SIGIO latch, including a second latch check
after guard callbacks. No native source map/artifact authority is issued; both
public policy anchors remain absent. The exact ingestion source SHA is updated
in the existing policy pin.

Actual representative finalization used 128 regular host fixture inputs,
516,135 bytes, each under a Linux read lease with final full SHA and complete
before/after phase checks:

| Actual host fixture path | Seconds | Git subprocesses |
| --- | ---: | ---: |
| Original HEAD/status callback | 3.831114 | 772 |
| Candidate Git epoch guard | 0.186463 | 10 |

Both paths retained every read lease, and the final Git source was unchanged.
The ratio is 20.546 for this small fixture only; no production-scale ratio is
inferred.

Verification: 17 new actual small-Git/Linux-FD controls plus 11 existing source
closure, eight tiny-ISO and eight release-admission controls passed (44 total,
8.241s). The new controls include immediate legacy callbacks, forced phase and
final scans during the interval, due bounded scans, real child HEAD/same-SHA
reference/remote mutation, original directory/inode replacement, a real writer
against an unrelated union member, SIGIO during a guard, and failed/slow/clock
regressing scans. Actual tiny ISO tests retain their explicit host-model scope.

Two process-memory mutations were expected RED: substituting the exact original
base `Union.io_check` failed the bounded-callback control; substituting bounded
IO checks for full phase audits failed the final-drift control. Both selected
tests were GREEN after restoring the candidate. Production source files were
unchanged by these mutations.

The independent reviewer owns final review/commit. Main, existing worktrees,
private media, VM/QMP/process custody and public publication were untouched.
