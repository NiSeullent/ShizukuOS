# 2026-10-01 experimental source checkpoint

These are exact source copies from private build workspaces, preserved so a clone can continue development. They are not enabled automatically by the normal build.

- `native-win98/`: genuine Windows 98 Supervisor/SeaBIOS/ATA/string-PIO candidate and nine existing Supervisor snapshots. Apply the retained patch after reviewing current main; the genuine Win98 candidate has no successful native boot or GUI bridge proof yet.
- `dead-screen-native-controls/`: reviewed standalone Kernel64 intentional-fault test source and its seven-hook integration patch. V4 boot reached a real captured panic, but the observer incorrectly rejected authentic BP=0. V5 fixes this gate and has host controls; no V5 native acceptance is claimed.
- `native-boot-lane/`: historical task-private test guard.

The frozen runners intentionally retain their original lab paths and receipt identities. They are source references, not relocatable commands. Start with the normal builders described in `docs/CONTINUE_ON_ANOTHER_MACHINE.md`; port the experimental runner inputs to a new machine explicitly. Microsoft media, VM disks, firmware VARS, credentials and old generated binaries are not included.
