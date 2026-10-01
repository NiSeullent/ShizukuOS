# All remote branches — continuation snapshot

Recorded 2026-09-30 from the already-fetched local `origin/*` refs. No fetch,
merge or branch deletion was performed for this document. Baseline:
`origin/main` = `abc160b429f5498a2a5328b05af29e099964d54a`.
Ahead/behind counts are commits unique to the branch/main respectively,
measured by `git rev-list --left-right --count origin/main...<ref>`.
The symbolic `origin/HEAD` points to main and is omitted below.

| Ref under `origin/` | Exact tip SHA | Ahead / behind main | Latest commit subject | Scope |
|---|---|---:|---|---|
| `main` | `abc160b429f5498a2a5328b05af29e099964d54a` | 0 / 0 | Merge pull request #29 from NiSeullent/wip/w2-trident | Integrated baseline; current boot work starts here. |
| `codex/shizuku-independent-platform` | `008525be709e20fb83cb7e88275ee6e0050de7a4` | 0 / 410 | Record isolated VxD flag experiment and disposable QA acceptance | Independent platform/VxD foundation and bounded native diagnostics. |
| `gh-pages` | `8452c81d074a64212e3df0ccfc8b851c2eb03d37` | 3 / 456 | Support CNG hash pseudo-handles and verify preview release | Published preview branch; preserve its deployment role. |
| `wip/shizukudos-10` | `a70ab6b1b10990c7c36fb4aa7041b92771c3dc1f` | 0 / 409 | WIP: ShizukuDOS 10.0 multikernel | Original multikernel continuation baseline. |
| `wip/shizukudos-10-toydzv` | `1c34d973c3232b1dda119cd4ea6f4d598fcea426` | 8 / 30 | Merge pull request #26 from NiSeullent/wip/w3-webkit-webcore | Parallel shared baseline containing WebKit/WebCore integration work. |
| `wip/integration` | `d48508aca3d98c005e9a3bf862eb794c9b5adb99` | 5 / 26 | Merge pull request #30 from NiSeullent/wip/e1-electron | Integration history and E1 continuation evidence. |
| `wip/k3-chromium-wip` | `2971a1863b1bb5579b9f5ff1332bc8a5d2ea8210` | 6 / 83 | Merge pull request #24 from NiSeullent/wip/n4-ntdrv-coverage | Chromium loader/runtime bring-up with an N4 merge. |
| `wip/k4-chromium-run` | `bf73d7d26ae19fcec4d7b4230d2a7c173419d0eb` | 5 / 4 | K4 report: run 16 prints the page's DOM (V8 ran the script); the process then dies in browser shutdown | Chromium execution, runtime fixes and remaining shutdown fault. |
| `wip/k5-chromium-dlls` | `bbaf38e549a8577dc8f034262d97b48cb18b2a9c` | 0 / 14 | Merge remote-tracking branch 'origin/wip/shizukudos-10-toydzv' into wip/k5-chromium-dlls | Win64 system DLL/API and resource support for Chromium. |
| `wip/e1-electron` | `31a1cc8bb8877fb2abfd936fc79603a480ad0d72` | 4 / 44 | E1: merged K4/K5 status, walls behind the loader, proposals and evidence | Electron/Node probes, proposed patches and explicit failure evidence. |
| `wip/n3-driver-load` | `f78a07e907c81075c1429ea3f5ad750f33febffa` | 0 / 52 | Merge origin/wip/shizukudos-10-toydzv (main d624824: PRs #6, #8, #9, #10, #11) into wip/n3-driver-load | Driver package install/load, PCI resources, PnP and NDIS bring-up. |
| `wip/n4-ntdrv-coverage` | `ab30205400af5aae2082e9ea06a5a10c18d38245` | 8 / 96 | ntdrv: report, STATUS.md and NTDRV.md with the measured numbers; coverage --export-drivers | NT provider coverage, corpus DriverEntry and KMDF binding. |
| `wip/w1-webkit-jsc` | `ea6806dbd58ceb189a1388401b6d3d7598cd0d40` | 5 / 30 | W1: adopt the shared WebKit toolchain (mingw-w64 13 UCRT + libc++ 18) | JavaScriptCore and shared cross-build toolchain. |
| `wip/w2-trident` | `96c27383a4945354c1df66e2ed04a075cab51f1b` | 0 / 27 | trident: component build driver (engine, xul) for the WIN64.IMG hook | Trident engine API and component build integration. |
| `wip/w3-webkit-webcore` | `7b80ceed2954da67d88aebd25e2c773c96444ce6` | 7 / 30 | Merge branch 'wip/shizukudos-10-toydzv' into wip/w3-webkit-webcore | WebCore/backend and common WebKit dependencies. |

A zero ahead count means that tip is already an ancestor of this main; it
does not mean all behavior described by the branch has passed acceptance.
Commit counts likewise do not establish a clean merge or working applications.

## Evidence and remaining reconciliation

The repository entry is [README](../README.md). ShizukuDOS evidence is in
[STATUS](shizukudos10/STATUS.md), with branch-specific details in
[E1](shizukudos10/reports/E1.md), [K4](shizukudos10/reports/K4.md),
[K5](shizukudos10/reports/K5.md), [N3](shizukudos10/reports/N3.md),
[N4](shizukudos10/reports/N4.md), [W1](shizukudos10/reports/W1.md) and
[W2](shizukudos10/reports/W2.md). [WEBKIT](shizukudos10/WEBKIT.md) records
the shared W1/W3 work; [TRIDENT](shizukudos10/TRIDENT.md) records W2's
architecture. These reports retain their own revisions and evidence scopes.

- **N3/N4:** [Integration pass 4](shizukudos10/reports/INTEGRATION.md)
  records conflicts in `ntdrv_io.c`, `ntdrv_ke.c`, `ntdrv_mm.c`,
  `ntdrv_pnp.c`, `ntdrv_prov.c` and `ntdrv_zw.c`, including different IRQL,
  object-reference and MDL behavior. [N3's overlap discussion](shizukudos10/reports/N3.md#overlap-with-n4s-second-export-batch-for-the-leads-merge)
  describes the 40 shared exports and behavior to preserve. This is historical
  merge evidence at the revisions named in those reports; no new merge trial
  was run here. N3 is now fully in main; N4 still has eight unique commits.
- **Browser branches:** K4's latest result records DOM execution followed by
  a browser shutdown fault. E1 separates committed runtime behavior from its
  proposed patches. W1/W2/W3 are build/runtime continuation work; their reports
  must be read before claiming browser or application completion.
- **Active UEFI work:** local `codex/uefi-desktop` is based on the main SHA
  above. [DESKTOP_BOOT](DESKTOP_BOOT.md) distinguishes the implemented Shizuku
  shell from Microsoft Windows 98 GUI boot and records the required actual
  guest checks. It does not change the remote refs in this snapshot.

## Previous-session trace

The latest E1, K4, N3, N4, W1 and W2 commit messages contain the exact trailer
`Claude-Session: https://claude.ai/code/session_01AHHXMseAQefjAfcUCErzWc`.
Their exact commits are pinned in the table. The trailer is repository
metadata connecting this work to that session; its private conversation was
not accessed or reconstructed. The original `wip/shizukudos-10` tip instead
records `Co-authored-by: Cursor <cursoragent@cursor.com>`.

Refresh this snapshot from newly approved/fetched refs before making further
integration decisions; retain per-branch build and guest receipts separately.

## Refreshed continuation — 2026-09-30

All 15 branch refs were fetched again with the previously approved command.
Current `origin/main` is `c686bc9ad2fb2bda440a277ef7aeab374fe41381`. The initial table above remains the
historical snapshot; these are the new source tips, not new native app passes.

| Ref under `origin/` | Exact tip SHA | Ahead / behind current main | Latest subject |
|---|---|---:|---|
| `main` | `c686bc9ad2fb2bda440a277ef7aeab374fe41381` | 0 / 0 | Merge pull request #33 from NiSeullent/wip/shizukudos-10-toydzv |
| `codex/shizuku-independent-platform` | `008525be709e20fb83cb7e88275ee6e0050de7a4` | 0 / 430 | Record isolated VxD flag experiment and disposable QA acceptance |
| `gh-pages` | `8452c81d074a64212e3df0ccfc8b851c2eb03d37` | 3 / 476 | Support CNG hash pseudo-handles and verify preview release |
| `wip/e1-electron` | `2ae22aa421d495fd3b0402209142428b64ed6579` | 11 / 15 | E1: report, evidence and proposals for main abc160b + K4 bf73d7d (marker and exit 0 reached with proposals; GPU process is the blocker) |
| `wip/integration` | `bbd1c464cdf0b993d5ade9431de35de25bcb426e` | 8 / 24 | INTEGRATION.md: corrections from the independent check (gate order, restart wording, pass 1 k4 row, ring-3 #GP wording) and the second k64_disk cause |
| `wip/k3-chromium-wip` | `2971a1863b1bb5579b9f5ff1332bc8a5d2ea8210` | 6 / 103 | Merge pull request #24 from NiSeullent/wip/n4-ntdrv-coverage |
| `wip/k4-chromium-run` | `498cb8f1bea3f046a36a142d626c10fa79cb2be9` | 4 / 0 | K4 report and STATUS: blocked items and gates brought up to date |
| `wip/k5-chromium-dlls` | `2c1aff835803bbaaffd91b58f7d65472d364d07b` | 6 / 21 | docs: K5 report section 13 (run 7 with --v=1: NULL call in a worker thread, gs:[0x30]==0 in the wineport SEH handler, recursion to stack overflow) |
| `wip/n3-driver-load` | `f78a07e907c81075c1429ea3f5ad750f33febffa` | 0 / 72 | Merge origin/wip/shizukudos-10-toydzv (main d624824: PRs #6, #8, #9, #10, #11) into wip/n3-driver-load |
| `wip/n4-ntdrv-coverage` | `25588c3b8ae6a88b3132a71b80aa90ffae0261dc` | 11 / 37 | Merge remote-tracking branch 'origin/wip/shizukudos-10-toydzv' into wip/n4-ntdrv-coverage |
| `wip/shizukudos-10` | `a70ab6b1b10990c7c36fb4aa7041b92771c3dc1f` | 0 / 429 | WIP: ShizukuDOS 10.0 multikernel |
| `wip/shizukudos-10-toydzv` | `513808df78ab6b90b6a5691bebfa77ca39922ab7` | 0 / 37 | Merge pull request #32 from NiSeullent/wip/w1-webkit-jsc |
| `wip/w1-webkit-jsc` | `0d44c907a0241a51766ee93164aecbfd1a4c23a4` | 5 / 37 | W1: M1 PASS - jsc.exe (C loop) runs m1.js in the Kernel64 guest |
| `wip/w2-trident` | `e9426d4c8381631515f276c214306e5fbf205b95` | 7 / 34 | docs: W2 report — tridentrt and shzlite core verified in the standalone and GUI gates |
| `wip/w3-webkit-webcore` | `87f94e0f53e7f5a3f113e4653a5f9e58e7cf0312` | 11 / 37 | W3: PORT=Shizuku configures; WEBKIT.md section 6 (port choice) |

The local `codex/uefi-desktop` work remains based on `abc160b429f5498a2a5328b05af29e099964d54a`.
No merge, rebase or checkout was performed on its active multi-agent modifications.
Current main changes 44 files relative to that base, including overlapping kernel,
IPC, PE parser, build and dependency files; reconcile their source and frozen native
proof bindings before integration. Native provider and original application artifacts
remain held at their explicitly tested hashes.

Fresh K4 reporting records an older Chromium multi-process M2 DOM marker with
actual exit0; its literal single-process repeat faults during shutdown. K5 records
a worker NULL call followed by a Wine-port SEH recursion/stack overflow. E1 records
GPU/IOCP/pipe/graphics gaps and distinguishes proposed changes from integrated code.
These are results for the exact ShizukuDOS/Kernel64 corpora in those reports. They
do not establish Chromium157, Electron43/Legcord1.3, or a native Windows98 GUI pass.
