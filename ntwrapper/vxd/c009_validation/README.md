# Production VxD consumer validation — chat c009

This slice reuses the boot owner's production driver and the apps owner's frozen
GUI diagnostic. It creates no competing driver, observer, transport or VM. The
new output is `/root/Win98-Modern-boot/build/ntwrap-production-c009-20261001/`.

The fresh production build and all 12 host test methods passed. The rebuilt
`NTWRAP9X.VXD` is byte-identical to the apps fixture and the previously executed
native candidate: SHA256
`44d7a537c1a547d3b735d98ebdf5756c132486605dc1a25e3f6f364b9547b9bf`.
The builder's console `NTWQUERY.EXE` was compiled and tested, but is not staged
for the GOP guest. Its source remains unchanged. The host receipts retain their
own native execution fields as false.

Direct inspection of the preserved production trial's three raw logs confirms
two actual Windows 98 open/query/checked-close/reopen cycles, native event and
error contracts, query process exit 0 and inner observer process exit 0. The
historical review records `PASS_BOUNDED_NATIVE_PROOF_WITH_HOST_FAILURE_PRESERVED`:
the host launcher failed, and the outermost observer's own OS exit was not
observed. Preserve both facts. This evidence goes beyond the earlier successful
control-only VxD fixtures, but proves no positive Win64 channel or GUI bridge.

The new consumer copies the exact four files from apps chat cb43's frozen V3
fixture into `build/ntwrap-production-c009-20261001/guest/`. Their bytes and GUI
PE profiles are pinned. The copied manifest stages only 8.3 names under
`C:\VXDLAB`, and requires all three output logs to be absent before execution.
The original fixture nonce is retained deliberately; freshness must come from a
new cold clone, absent output baseline and actual stopped-disk readback. No
result from an earlier or interrupted clone may be substituted.

The diagnostic requests the real production QUERY, verifies that W64_OPEN fails
with error 50 when the real CPU does not advertise Shizuku Supervisor, verifies
QUERY again, then closes and repeats. Its two GUI observers record actual child
OS exits. The expected error is a truthful missing-Supervisor boundary; it is not
positive Win64 execution. Checked CloseHandle/reopen does not prove global driver
unmapping, and the outermost selected exit remains intent rather than its own
observed OS exit.

The complete runner argument array and scope are in
[native-proposal.json](/root/Win98-Modern-boot/build/ntwrap-production-c009-20261001/native-proposal.json).
The proposal preserves the existing 20 GiB floor, uses a fresh private run name,
128 MiB/two CPUs, no network, and the previously reviewed cold GOP source.
Each GUI action requires the actual corresponding screenshot. The parent must
assign a quiet execution slot before launch; the advisory lock alone does not
establish that other native owners are idle. Do not run the apps owner's guard
unchanged: it pins a different run, manifest and 17 GiB floor.

Evidence and provenance are in
[consumer-report.json](/root/Win98-Modern-boot/build/ntwrap-production-c009-20261001/consumer-report.json),
[rebuild-receipt.json](/root/Win98-Modern-boot/build/ntwrap-production-c009-20261001/rebuild-receipt.json),
[host-tests.json](/root/Win98-Modern-boot/build/ntwrap-production-c009-20261001/driver/host-tests.json),
and the exact
[guest-files.json](/root/Win98-Modern-boot/build/ntwrap-production-c009-20261001/guest/guest-files.json).
No VM was executed by this consumer preparation. Existing peer sources, outputs,
disks, observations and earlier failures were preserved.

The proposal is now deferred: the parent independently observed apps chat cb43
executing this same frozen negative fixture in its own V5 trial. Do not launch a
duplicate. Review that owner's fresh stopped-disk logs when available. Its
proposal uses a 17 GiB floor; this unexecuted consumer proposal retains 20 GiB.
Those resource policies and native-execution ownership must remain distinct.
