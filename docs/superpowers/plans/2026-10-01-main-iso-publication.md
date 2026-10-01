# Main integration and ISO publication implementation plan

> **For agentic workers:** Continue the authorized parallel execution. Root owns Git integration and publication; each agent owns the assigned files only.

**Goal:** Preserve every project source branch on GitHub, integrate main, build a source-backed public ISO and publish it on the nginx official site with external verification.

**Architecture:** Use an isolated integration worktree from origin/main; commit source snapshots in their original branches, merge histories and resolve shared APIs without overwriting running experiments. Build public media from the resulting source. Keep Microsoft media/private VM disks separate. Nginx serves Korean/English download and preview pages.

**Tech Stack:** Git/GitHub, Python/GCC/MinGW/NASM, QEMU/OVMF, xorriso/mtools, nginx/static HTML.

**Spec:** User directions in this session: all commits/main merge, continue on another machine, final ISO on m98.nyase.kr, external official homepage instead of VNC.

## Global constraints

- Preserve original worktrees, unrelated VMs and immutable native receipts.
- Public ISO never includes Microsoft media, credentials, VM disks or firmware VARS.
- Source integration and ISO bootability do not imply eight modern apps/full graphics/Windows98 installation completion.
- No force push; current origin main must remain an ancestor.
- External 403/challenge/VNC cannot be recorded as successful official homepage delivery.

## Review focus

- Shared runtime declarations/implementations from different branches: compile and scoped tests.
- Reused generated binaries: reject mismatched source closures; rebuild merged source.
- Hidden lab-only source: source-only experimental archive plus fresh-machine instructions.
- ISO source/license/media closure: inspect builder receipt and ISO contents.
- Public route/cache/proxy behavior: normal-DNS real browser and external HTTP checks.

## Tasks

- [x] Inspect all worktrees/branches and exclude generated/private input files.
- [x] Commit project source snapshots and source-only experimental archive; prepare fresh-machine handoff.
- [x] Remove mandatory historical receipts from default DeadScreen source build; retain explicit history verification.
- [ ] Merge all relevant branch histories and preserve conflicting historical evidence separately.
- [ ] Rebuild merged runtime/boot components and run appropriate source/build checks.
- [ ] Build Microsoft-free public ISO, inspect contents, run private BIOS/UEFI boot checks.
- [ ] Add ISO/checksum/download metadata to Korean and English pages and publish immutable nginx release.
- [ ] Verify main remotely and external homepage/download behavior; retain actual blockers honestly.
