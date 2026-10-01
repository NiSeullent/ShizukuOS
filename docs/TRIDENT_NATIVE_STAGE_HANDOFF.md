# Genuine Trident native stage — 2026-10-01

The optional extension now has three independently checked frozen components:
actual QuickJS runtime v10, genuine MSHTML Automation v4 and owned-child
observer v2. This checkpoint launches nothing and does not install or register
a system script provider. The installed target is Win98 SE 4.10.2222, ACP949,
with actual IE 5.00.2614.3500/MSHTML; each later IE variant needs its own trial.

`tools/stage_trident_automation_native.py` requires caller-pinned successful
receipts and the exact current and frozen source profiles. It reuses the strict
verifier's canonical bounded reader, source, prepared-input, log and artifact
checks. Conflicting shared ABI pins fail. All validation precedes creating a
fresh, canonically spelled direct child of the owned boot build directory.
It verifies the observer schema, nonce, paths and 240-second/5-second bounds,
the runtime's nine exports and actual structured i486 instruction gate,
OEM PE gates, 2 MiB reserve and respective 512/64 KiB stack commits, and the
unchanged harness maximum of 1 MiB per input.

The existing stage is:

`/root/Win98-Modern-boot/build/trident-automation-native-5abe-20261001-v1/guest-files.json`

SHA256 `13eddef2f02f8bfc3a1ba331aaf8fa027e334cff8e7a2a225ddeeab517e46a9a`.
It launches `C:\GOPLAB\M98AURUN.EXE` and supplies exactly `M98AUTPR.EXE`,
`M98QJS.DLL` and `M98AURUN.EXE`; outputs are `AUT13.LOG`, `AURUN.LOG` and
`AUOUT.LOG`. Networking is disabled. The stage preserves original receipts,
32 merged project-source pins, 45 prepared runtime files, the generated selected
fixture header and successful build logs. Independent checks matched all 146
copied files and all three native artifacts, without changing the stage.

| Frozen receipt | SHA256 |
| --- | --- |
| Automation v4 | `20b983e4c5c3fdbaa6beb8973d521e2cc334314aa31e1555bc8f033c3594372e` |
| Runtime v10 | `7e036db6906484a046c1253e4668930c4d85645f492ce2bf9a626fd6a1cbf716` |
| Observer v2 | `7b1e29758d8df087054e3ddf502b7282b2e01ed214eee946f8bddc70a8d54206` |
| Native verifier v2, synthetic controls only | `cae7de247e4e4e1e165a31e91c713890ba279b3a1a236090ab750955b3c50fa8` |

Meaningful stager controls rejected an existing output, wrong receipt pin,
historical runtime v9/current-source drift, Boolean schema, invalid nonce,
wrong observer deadline, noncanonical output spelling and a leading-punctuation
nonce before any new stage directory was created. These controls and the
actual stage readback are preserved separately under owned ignored build output.
The strict native verifier passed 43 controls normally and with Python `-O`;
these are verifier tests, not native component execution.

Native acceptance still requires a fresh, cold private Win98 clone through the
unchanged canonical harness, 20 GiB reserve, GOP, 128 MiB RAM, two CPUs, no NIC,
the shared queue lock and preserved original inputs. Allow the observer's full
child deadline and output flush/reap; QEMU exit and requested observer exit do
not establish actual child completion. Visibly confirm the Run dialog before
typing its launch command. Click the genuine MSHTML input and enter actual QEMU
keyboard text; independently review the Korean Promise mutation and resulting
typed-value match. Synthetic events or component logs cannot prove painted
content or external input.

Read `TRIDENT_AUTOMATION_NATIVE_EVIDENCE.md` for the caller-pinned collector and
manual review requirements. Script-only native execution uses a different
three-input manifest and its own matching observer/probe nonce, not this stage.
Native DOM execution, trusted input, paint, ordinary browser script selection,
navigation/origin integration, HTML5 layout, full JavaScript/CSS/WASM,
WebGL/WebGPU and modern application workflows remain pending.

GPL-2.0-only original handoff. Upstream interpreter/math notices and original
source are retained in the runtime checkpoint; publication is not performed.
