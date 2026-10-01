# Native theme automatic-start bootstrap

SPDX-License-Identifier: GPL-2.0-only

This argument-free original i486 bootstrap reads exactly 32 lowercase hex bytes
from a staged challenge, confirms its exact module path and Windows 98 SE
identity, and creates the unchanged quoted NTTHRUN command with no inherited
handles. Its file and observer lifetime tests pass 2,922 assertions normally
and under sanitizers. No arbitrary command, registry or network input is used.

`tools/theme_startup_trial.py` inserts only the bootstrap path into an existing
empty WIN.INI `[windows] run=` on a new private COW clone. It conservatively
refuses nonempty/duplicate/ambiguous entries, preserves every other byte and
boot sector, verifies independent readback, and retains the shared native lane,
source guards, 20-GiB reserve, 256-MiB writes and 16-MiB output limits. Its 15
real-FAT/reflink/refusal regressions pass. Preparation does not launch a VM.

The actual stopped v12 trial started automatically in genuine Windows 98 SE.
The unchanged strict verifier passes both styles and theme-child normal exit
zero. The bootstrap independently witnesses observer wait/query/normal exit
zero and closed observer handles. Its own final log close and external exit
are explicitly unobserved; its log never declares those as final success.

All five input files, four logs, patched WIN.INI and original boot sectors were
independently checked. Forty-four final source/compiler checks pass. `handoff.json`
binds the retained receipts and evidence index. Full Classic is visible; Modern
has the changed palette/label with missing captions/background sections. Manual
selection, complete Modern visibility, global/persisted themes and app support
remain unverified. A separate composition diagnostic preserves this source and
all v12 evidence.
