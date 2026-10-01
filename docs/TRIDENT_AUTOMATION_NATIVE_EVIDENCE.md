# Genuine MSHTML Automation component evidence

This verifier binds one **stopped, private Windows 98 SE Korean guest run** to
caller-approved source/build/harness receipts. It launches nothing, changes no
guest or registration, and does not interpret pixels. The Automation v4 and
observer v2 implementation was reviewed at local commit `09e6285`; their native
execution is still pending. Passing the synthetic verifier tests is not a
native, browser, input or visual result.

## Trust and exact scope

`tools/verify_trident_automation_native.py` receives explicit SHA256 pins for the
run result, manifest, harness source and all three original build receipts.
Those caller-approved receipts establish the reviewed implementation and
harness semantics. Hashes alone cannot establish that source is production
code, that a PNG depicts MSHTML, or that a sent keyboard action had an effect.
The verifier checks bytes, source generation, complete component/child results
and the following strict profile:

- Windows 98 SE 4.10.2222, platform 1 and ACP 949, real system MSHTML document
  creation and a directly hosted document; no global JScript replacement.
- Current frozen, EXE-adjacent `M98QJS.DLL`, the exact nine-function ABI including
  `m98_script_invoke_this`, and the statically embedded Automation adapter.
- Modern syntax execution, genuine interpreter Promise jobs, independently
  queried typed MSHTML text, a nonempty actual input value equal to the entire
  JavaScript-produced status, queued event delivery outside COM, and teardown.
- The observer's actual owned `M98AUTPR.EXE` child PID, wait completion, queried
  exit code zero, stdout flush and handle close. Its requested supervisor exit
  zero is reported separately: the actual observer process exit remains
  **unobserved**. A zero QEMU exit is not an observer process exit.

`WM_KEYUP` and COM event counts remain component observations. Without the
optional trusted input/paint review, `real_gui_input_verified` and
`genuine_mshtml_paint_verified` stay false even when every component check passes.
Standard browser navigation, full modern CSS/HTML5/JavaScript, WebAssembly,
WebGPU/WebGL and Legcord/Signal/Office functionality always remain false. No
compatibility percentage is produced.

## Frozen staging contract

The root-owned stager creates a fresh stage only after checking the original
frozen build inputs. It must retain these names and copies:

| Stage content | Binding |
| --- | --- |
| `M98AUTPR.EXE`, `M98QJS.DLL`, `M98AURUN.EXE` | Exact approved artifact size/hash, PE gate and committed stack bounds |
| `automation-build.json`, `runtime-build.json`, `observer-build.json` | Original bytes and independently supplied caller pins |
| `source/<repository-relative path>` | Every exact project source pin; shared ABI/source generations must agree |
| `runtime-prepared/quickjs/...`, `runtime-prepared/math/...` | Every interpreter `prepared_sha256` pin; original absolute build paths are never read by this verifier |
| `runtime-selected.h` | Pinned generated selected interpreter fixture header |
| `build-logs/{automation,runtime,observer}/<original basename>` | Every successful integer-zero step and exact log SHA; safe `.txt` and `.log` names, no duplicate basenames |

Automation and observer schema/kind are exact; runtime profile is
`bounded-local-trident-quickjs-v1` and its current receipt has no numeric schema.
Its native runtime `i486_instructions` dictionary must have exactly
`instructions_decoded` and `post_i486_families: "absent"`, with a positive checked count
bounded by the native 1 MiB per-input PE profile. Build logs have a separate
explicit 8 MiB per-file bound: the real provisional runtime v7 disassembly was
7,485,493 bytes, above a default 4 MiB reader. The final runtime log size must be
measured before accepting its frozen stage; oversize logs fail rather than
silently relaxing the bound.
All original receipts retain their original paths and hashes. The verifier
derives only safe stage-relative source/log copies, rejects symlinks, checks
regular bounded files and detects changes during each read. Original dependency
archives and compiler paths are metadata in the approved build receipt; this
verifier neither reads nor downloads them. The prepared interpreter source and
project source copies are the code generation bound here.

The manifest has schema 1, kind `isolated-guest-file-inputs`, a bounded nonempty
nonce equal to the observer's compiled nonce, command
`C:\GOPLAB\M98AURUN.EXE`, and `network_required: false`. Its **exact** three
inputs, three source receipts and three outputs must agree with the harness's
immutable source set and the fresh private prepared-input hashes. Outputs are
`C:\GOPLAB\AUT13.LOG`, `C:\GOPLAB\AURUN.LOG` and `C:\GOPLAB\AUOUT.LOG`.

The run must use the approved cold private KVM/GOP clone, 128 MiB, two CPUs,
20 GiB reserve and no guest networking, then be normally stopped with original
and prepared sources preserved. Freshness must be `new-in-owned-run` after an
`all absent before private injection` baseline. `AUT13.LOG` and `AURUN.LOG` must
contain their complete exact success fields with CRLF termination; every
HRESULT must succeed, every component check must pass and `FAILURES` must be
zero. Repeated queued-event records must match the callback count.

`AUOUT.LOG` is legitimately **empty**: this GUI fixture writes its component
result to `AUT13.LOG`. Its fresh captured zero-byte hash is still mandatory.
Unexpected stdout diagnostics are rejected. Empty/partial component logs,
stale logs, unknown keys, missing teardown, observer timeouts and nonzero or
unqueried child exits fail.

## Invocation

The verifier prints JSON on stdout and exits 1 for missing, stale, partial or
unapproved evidence. Capture that output in a new audit checkpoint; do not
overwrite the original native receipt.

```text
python3 tools/verify_trident_automation_native.py \
  --run-result /absolute/owned-run/result.json \
  --run-result-sha256 <approved-run-sha256> \
  --manifest /absolute/frozen-stage/guest-files.json \
  --manifest-sha256 <approved-manifest-sha256> \
  --harness-sha256 <approved-harness-source-sha256> \
  --automation-build-sha256 <approved-automation-receipt-sha256> \
  --runtime-build-sha256 <approved-runtime-receipt-sha256> \
  --observer-build-sha256 <approved-observer-receipt-sha256>
```

## Optional manually trusted GUI input and paint review

Add both `--trusted-input-visual-review <absolute-json-path>` and
`--trusted-input-visual-review-sha256 <caller-approved-sha256>` only after a
person independently reviews the actual action/effect and the captured frames.
This external trust is explicit; the verifier does not infer visual content
from names, PNG hashes, log messages or sent-action status.

The review schema is `win98modern.trident-automation-input-visual-review.v1`.
It binds `harness_result_sha256`, `manifest_sha256` and the exact three-name
`input_sha256` map. Set `genuine_mshtml_paint_verified` and
`qemu_gui_input_verified` true only for the reviewed native evidence. Set
`standard_browser_integration_verified`, `full_web_standards_verified` and
`modern_apps_verified` false; modern CSS/WebGPU/WebGL assertions cannot be true.

`gui_actions_sha256` hashes the actual harness action array serialized with
Python JSON `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=True`,
`allow_nan=False`, then UTF-8 encoded. `input_action_sequence` selects exactly
one positive integer action sequence from a complete contiguous `1,2,...` array. The supported action
contains bounded printable ASCII `typed`, finite `seconds`, and the actual
harness status `sent; application effect requires screenshot/readback
verification`. `reviewed_typed_input` must equal those sent bytes, while
`manual_review` explains the independently observed actual focus/input/result.
Unsupported action formats fail this optional lane; component-only verification
can still be used while input/paint evidence remains pending.

`frames` contains exactly `focused_input` and `korean_after_input`, each with
`path`, `sha256`, `seconds`, and a nonempty `visual_review`. Both must match
distinct hashed, captured PNG artifacts directly inside the owned run directory.
Their actual harness capture times must bracket the selected action. The manual
reviews must establish genuine MSHTML input focus and the resulting visible
Korean status containing the exact nonempty input. The programmatic fixture
observations support that review but cannot replace it. The report labels this
as caller-approved manual action/effect/paint trust and always keeps
`visual_content_automatically_asserted` false.

## Validation limits

`tests/test_verify_trident_automation_native.py` uses deliberately synthetic
non-PE and non-image files. It exercises protocol rejection, not native execution.
Controls cover every HRESULT and required component check; partial/stale logs;
child wait/exit/flush/close failures; source, ABI, input and step-log mutations;
path escapes, symlinks, duplicate JSON; and untrusted, stale, ambiguous or
unsupported input/paint receipts. Running those tests under Python optimization
also ensures verifier guards do not disappear with `assert` removal.

GPL-2.0-only project verifier and test code. This layer copies no MSHTML source;
QuickJS/musl source licenses and port details remain with the separately reviewed
runtime receipt and runtime handoff.
