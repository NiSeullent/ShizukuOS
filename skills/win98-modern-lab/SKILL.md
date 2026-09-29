---
name: win98-modern-lab
description: Engineer Windows 98 Shizuku's Second Edition through Wine/ReactOS API porting, accelerated guest tests, ShizukuDOS and ShizukuFS, multicore and PAE memory work, CSM NVMe/SATA/xHCI, and local prebuilt plus patch release paths. Use for work in the Win98-Modern repository, not general Windows troubleshooting.
---

# Windows 98 Shizuku's Second Edition Lab

Find the repository root from the current worktree and inspect its current state before acting. `README.md`, `docs/TARGET_APPS.md`, `docs/COMPATIBILITY.md`, `vm/README.md`, and the actual source and test results outrank this skill's historical details, except that the user's latest explicit target supersedes older numeric targets: **100% of the defined Windows API surface and all five selected apps actually running**. Keep the full goal intact: a new Win98 SE modernization project, direct Win98 installation and guest tests, newly built ShizukuDOS in place of FreeDOS, usable multicore execution, app-specific CPU modes, VT-x/AMD-V acceleration, PAE with all usable RAM on modern CSM systems, CSM-era boot and Skylake-class SATA/xHCI support, GitHub source, and an owner-only installation/download site. Work on a concrete part without treating it as completion of the whole.

Use the relevant reference when that work begins:

- [API porting](references/api-porting.md): complete catalogue, dependency-based family batches, Wine/ReactOS analysis, ABI and guest evidence.
- [Guest validation](references/guest-validation.md): the direct Win98 SE VM, test media, app probes, and evidence.
- [System work](references/system-work.md): ShizukuDOS, ShizukuFS, multicore, app CPU profiles, PAE/all usable RAM, and CSM-era NVMe/AHCI/xHCI.
- [Release and site](references/release-publication.md): licenses, allowlisted packages, GitHub, and official page.

## Shared invariants

- Preserve a powered-off base VM and use independent disposable clones for risky memory, driver, or boot experiments. Confirm hardware virtualization from the **current** VM log; a VM setting alone is insufficient.
- Do not put Windows installation media, product keys, Microsoft redistributables, target-app archives, VM disks, or screenshots with keys into version control or public packages.
- Label evidence precisely: host build, PE static check, guest direct call, guest KernelEx import, app startup, and app functionality are different claims. The 100% target is the **defined whole Windows API surface** with behavioral guest validation; a curated app import match is not that score. Completion also requires all five selected applications to run and pass meaningful guest functionality checks.
- Keep source lineage and per-file licensing beside every imported algorithm. Implement real contract behavior where possible; do not count a success-shaped stub as compatible.
- Split independent research/implementation/validation among agents when useful, give them disjoint file and VM ownership, and integrate their results against the current worktree.
- Use the complete API catalogue and family work queue before implementing new wrappers. Finish shared prerequisites and coherent families; use app errors as regression evidence. Retain unresolved/stub/alias entries without counting them as compatible.
- The user selected an owner-only official Sites page. Keep that visibility unless explicitly changed; GitHub source publication is a separate authorization.
