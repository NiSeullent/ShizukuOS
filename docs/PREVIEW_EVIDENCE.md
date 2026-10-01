# Preview evidence handoff

This document records existing local evidence inspected on **2026-09-30 at
22:59 KST (13:59 UTC)**. It is a shared reference for the site and release
owners. The results below describe the preserved runs and their recorded
inputs; they do not certify later edits in this shared worktree. No repository
script, build, VM, service or network request was run to prepare this handoff.
Only this document was added; screenshots and other artifacts remain in their
existing locations.

## Evidence boundaries

| Path | What the cited evidence establishes | What it does not establish |
| --- | --- | --- |
| ShizukuDOS standalone Kernel64 desktop | Two cold UEFI boots of the desktop-profile ISO, the project's own shell, keyboard input, file persistence and a real Win64 test child | Microsoft Windows 98 running this shell, a complete Windows-compatible distribution, or physical-hardware support |
| Standalone GOP application QA | 85 project test applications passed in the recorded QEMU run | Chromium, Electron, VS Code, Notepad++ or other selected real applications passing their functional requirements |
| Microsoft Windows 98 guest through CSMWrap | The separate visual review confirms the Korean Windows 98 desktop, taskbar and Welcome window | Successful save/readback or complete application interaction; the cited Save As attempt failed |

The 85/85 figure is a **test-application count**, not a general application
compatibility percentage. The standalone desktop and the Microsoft Windows 98
guest are different operating-system paths and must have separate captions.

## Standalone desktop ISO

Primary run: [desktop ISO result.json](/root/Win98-Modern-boot/build/desktop-harness-iso/20260930T132352-fr68teka/result.json).
The record's `utc` is `2026-09-30T13:23:52Z` (22:23:52 KST), its `accel` is
`kvm`, and both boot records identify `boot_medium: shipped-iso-cd`.

| Exact JSON field or counted array | Inspected value |
| --- | --- |
| `status` | `PASS` |
| `scope` | `two QEMU UEFI boots; persistent own desktop/input/disk I/O/Win64 child` |
| `checks` | 43 entries, all `status: PASS` |
| `boots[0].status`, `boots[0].checks` | `PASS`; 28 entries, all `PASS` |
| `boots[1].status`, `boots[1].checks` | `PASS`; 27 entries, all `PASS` |
| `iso.source` | `/root/Win98-Modern-boot/build/windows98-shizuku-second-edition-desktop.iso` |
| `iso.bytes` | `196083712` |
| `iso.sha256` | `fd54efaf64577ff0a15e4aa271ffea6770fcd00dbcb207354f97aea2e0494da0` |
| `expected_file.path`, `expected_file.bytes` | `D:\DESKTOP.TXT`; `25` |
| `expected_file.sha256` | `22d8f82bf677991bcd1e0c07ebe4c8de20f1e04b1f4e8181d348849a4237bd99` |

These are 98 recorded check entries across three arrays, rather than 98
independent hardware or application compatibility claims. The common checks
include source-bound build receipts, actual shipped EFI/configuration selection,
independent host file extraction, FAT consistency and preserved inputs. The
boot checks include the actual 1280x800 GOP desktop, directory enumeration,
keyboard-driven save/reopen, exact file contents, a real Win64 child exiting
with code 7, idle persistence, explicit shell exit and volume flushing.

The [ISO builder receipt](/root/Win98-Modern-boot/build/windows98-shizuku-second-edition-desktop.json)
independently records `boot_profile: desktop`, the same `iso`, `bytes` and
`sha256`. During this inspection, ordinary read-only `stat` and `sha256sum`
confirmed that both the source ISO and its preserved
`iso-inputs/boot.iso` copy are **196,083,712 bytes** and have the SHA-256 above.
The builder receipt's actual SHA-256 also matches the run's
`iso.receipt.sha256`:
`93f8059f02dccc30765c2fb16d753691e82b876067108bfe3ae4d1038dc5e281`.

Both independently extracted `boot-1-DESKTOP.TXT` and `boot-2-DESKTOP.TXT`
were rechecked with those same read-only tools: each is 25 bytes and matches
the recorded file hash. The run receipt binds a dirty source worktree through
`git.worktree_fingerprint`, rather than claiming an unmodified release commit.
That fingerprint is
`4bd2479baaa8988e9d0c26d8c91fc621d95b6f801f916cda6314bff78cda2210`.

Existing guest screenshots suitable for preview references:

- [Own standalone desktop](/root/Win98-Modern-boot/build/desktop-harness-iso/20260930T132352-fr68teka/boot-1/desktop-ready.png)
- [Editor after saving](/root/Win98-Modern-boot/build/desktop-harness-iso/20260930T132352-fr68teka/boot-1/editor-saved.png)
- [Editor reopening the persisted file after a cold boot](/root/Win98-Modern-boot/build/desktop-harness-iso/20260930T132352-fr68teka/boot-2/editor-cold-boot.png)

Their actual hashes were checked against `boots[].screenshots[].sha256`.
`desktop-ready.png` matches
`7c75f6de6e620370c903e913fdb35497576ba26a8df0c356271684ca26bd9549`;
both cited editor images match
`9188b25878cd17e5114e497dec70f9ec7ea4c3122affc4bcbd15c1eff0ef7d25`.
This is local artifact validation; it does not establish a published download
URL or public release asset.

## Standalone GOP test applications

Primary record: [GOP provenance result.json](/root/Win98-Modern-boot/build/gop-provenance/20260930T131556/result.json).
Its `utc` is `2026-09-30T13:22:08.957757+00:00` (22:22:08 KST).

| Exact JSON field | Inspected value |
| --- | --- |
| `status` | `PASS` |
| `apps_run`, `apps_pass` | `85`, `85` |
| `apps_failed` | `[]` |
| `guest_check_count` | `26` |
| `delay_regression.parent_checks`, `fresh_child_checks`, `failed` | `32`, `3`, `0` |

The linked [guest-result.json](/root/Win98-Modern-boot/build/gop-provenance/20260930T131556/guest-result.json)
also has `status: PASS` and 26 entries in `checks`, all `PASS`. The provenance
`notes` identify the unchanged `qemu64` TCG/std runner, 43 loaded DLLs, real
framebuffer/status pixels and PS/2 keyboard/mouse/wheel checks. That run has no
`D:` volume; the separate desktop ISO evidence establishes storage persistence.

The record's `remaining_issue` explicitly excludes the direct ntdll
`LdrResolveDelayLoadedAPI` and bulk `ResolveDelayLoadsFromDll` paths from this
suite's coverage. It records their original unprotected pointer writes and
different failure-hook/exception contracts, plus a redundant local/forwarded
`ResolveDelayLoadedAPI` entry in `kernel32.def`. Keep those limitations when
describing the delay-import result.

Existing images: [GOP framebuffer](/root/Win98-Modern-boot/build/shizukudos/kernel64s/gop-run/20260930T131557-nxtveqsb/std/shot-fb.png)
and [GOP status screen](/root/Win98-Modern-boot/build/shizukudos/kernel64s/gop-run/20260930T131557-nxtveqsb/std/shot-status.png).
Their actual SHA-256 values match `screenshots`: respectively
`44062c46784537477e45337b6964fc29698878a8cff08df0b211ae232f1269c0`
and `96f95501670725c9e7fdfeb82162852dbaac5547841832f983a47106c15997fe`.

## Separate Microsoft Windows 98 guest

The preserved [execution receipt](/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-uefi-q35-kvm-helper-id-m1-full/result.json)
retains `status: NEEDS-VISUAL-REVIEW` and `gui_verdict: not-established`.
Its separate [visual-review.json](/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-uefi-q35-kvm-helper-id-m1-full/visual-review.json)
records `gui: visually-confirmed`, `interaction: not-established`, and
`screenshot: screen-003.png` at `2026-09-30T13:06:30Z` (22:06:30 KST).
The review's `receipt_sha256` was rechecked against the execution receipt and
matches `d9af9c2b02342f373955212f917c37ec79c1045d9ebeed3841dd81021f25e127`.

The review describes the genuine Korean Windows 98 desktop, taskbar and
Welcome window in [the existing screenshot](/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-uefi-q35-kvm-helper-id-m1-full/screen-003.png).
The receipt records Q35/KVM, two CPUs, 128 MiB RAM, the patched CSMWrap path,
`himem_machine: 1` and `network: none`. `originals_unchanged` and
`prepared_source_unchanged` are true. This is evidence for that particular
private QEMU configuration, not general hardware acceptance. The GUI claim is
attributed to the separate visual review; this handoff did not re-review the
Windows 98 screenshot.

The later [Save As execution receipt](/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-uefi-q35-kvm-helper-id-gui-save-as/result.json)
has `status: FAIL` and `gui_interaction.verdict: not-established`. Its
[visual review](/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-uefi-q35-kvm-helper-id-gui-save-as/visual-review.json)
records `interaction: FAIL`: timed input entered the Start menu/Windows Update,
and the observed File menu belonged to Internet Explorer. There was no valid
Notepad save proof. The standalone shell's successful save/reopen cannot be
used to fill this Windows 98 interaction gap.

## Site and release handoff

At inspection, [DESKTOP_BOOT.md](/root/Win98-Modern-boot/docs/DESKTOP_BOOT.md)
still says shipped ISO desktop acceptance is pending and describes the older
84/85 GOP result. The preserved results above are newer than those statements.
The site/release owner can reconcile them using the exact records, without
mixing the standalone and Microsoft Windows 98 paths.

The [site source](/root/Win98-Modern-boot/site/index.html) still points its
download to the historical `v0.1.1-preview` KernelEx ZIP. The desktop ISO hash
in this handoff belongs to a separate local artifact; it must not be attached
to that historical ZIP. Publication and download-link validation remain the
site/release owner's work.

For traceability, the inspected desktop ISO run receipt has SHA-256
`727f525de9f4409909822a2236fcbce10121910f811f918045ba79a60aa6446c`;
the inspected GOP provenance receipt has SHA-256
`1682da93ea0fee325fe2260bdccff31e6e07dcede8d46e9fe9835eaa888339f6`.
These local generated evidence paths may not exist in a clean clone. This
document preserves references and identifying hashes; it does not copy their
contents into the repository or establish their public availability.
