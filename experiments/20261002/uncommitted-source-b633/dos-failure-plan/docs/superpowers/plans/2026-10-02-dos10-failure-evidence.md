# DOS10 failure evidence implementation plan

> Agentic workers: implement with a failing regression first, then independent review.

**Goal:** Preserve the failing DOS10 UEFI guest state before the test harness tears down its owned VM.

**Architecture:** Extend the existing bounded user-boot harness error path. Snapshot VGA text, CPU registers and the guest's first MiB through its existing QMP connection; write a failure result while preserving the original exception and cleanup.

**Tech Stack:** Python standard library, existing QMP helpers, isolated QEMU with no NIC.

**Spec:** User asks to fix ShizukuDOS 10 UEFI Invalid Opcode while preserving MS-DOS compatibility, collaborating with all sessions and asking no questions. This task supplies failure evidence to the root-cause owner.

## Constraints and review focus

Never change the source disk or firmware; never affect other guests. Snapshot failures must not hide the original failure. Preserve serial text, raw VGA and register state. An unavailable QMP must be recorded explicitly. Capture only bounded guest memory and owned files. Existing successful boots remain unchanged.

## Task

Files: shizukudos/dos16/test_user_boot.py; focused regression under shizukudos/dos16/.

- [ ] Reproduce that a startup exception currently loses guest state.
- [ ] Add a failure snapshot before the existing guest cleanup and keep the original error.
- [ ] Verify complete snapshot and partial/unavailable QMP behavior with focused tests.
- [ ] Run the actual UEFI boot harness against the existing cached DOS10 image in a new output directory, and a deliberately invalid owned-copy startup fixture to verify failure capture.
- [ ] Independently review the diff; share the patch and evidence with other session owners.
