# Controller RPC EOF and exact parent exit

A controller can close its Unix RPC endpoint during interpreter teardown before
its parent observes the process exit. The actual native11 capture completed
with QEMU exit0 and a persisted collection receipt, but this gap produced an
EOFError and a failed guardian outcome. Windows98 was still unverified.

The guardian remembers transport EOF and waits for its original ParentWait.
Every subsequent iteration retains cancellation, held bootstrap/source checks,
cgroup/resource checks and the original preparation/observation/finalization
deadlines. Closed transport sleeps100ms between checks. EOF does not authorize
success or custody release. Exact controller exit0, actual owned-child reap and
prior admitted QMP peer remain mandatory; cleanup still retains custody on
uncertain status. No decoder error, nonzero status or ECHILD becomes success.
After the parent reports exit, a final guard checkpoint checks cancellation and
the already-established phase deadline before accepting completion. It retains
the bootstrap/source and cgroup/resource checks and creates no new time budget.

The original eight controls reproduced seven failures from the unchanged loop.
Independent review then identified two completion-boundary cases: a successful
exit observed after cancellation or after the original deadline. Both additional
controls failed before the final checkpoint; all ten passed after the repair.
They execute the exact guarded loop and completion checkpoint AST
from independently held production source bytes. Unix endpoint closure, the
still-live child, pidfd/parent wait, nonzero exit and elapsed deadlines are real
Linux observations. Source/resource/cgroup/owned-QEMU admission boundaries are
explicit host fixtures. This test is not a QEMU, Windows, device or ISO result.

Each finite host unit used MemoryHigh1GiB/MemoryMax1280MiB/TasksMax64/CPUQuota100%
and120s, with unchanged host6GiB+160MiB+64MiB and owned RAM6GiB+160MiB floors.
Sources and primary tools were readleased/fullSHA checked before evaluation and
after tests, closed before the actual return; PID1/current PID/cgroup joins
close each epoch. Complete external runtime dependency closure is not claimed.
Native11 and predecessor source/test evidence remain separate historical files.
