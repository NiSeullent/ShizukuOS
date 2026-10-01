# Genuine MSHTML CSS native trial preparation

The reviewed current core is `build/css-core-v4/result.json`. The real-token
property consumer/actual MSHTML fixture is `build/css-mshtml-fixture-v8/result.json`;
the separately bounded child observer is `build/css-mshtml-observer-v4/result.json`.
All native, full CSS/browser/WPT/GPU/app flags in these build receipts remain false.
The newer fixture and observer use the complete raw executable-byte i486 scanner;
the historical core's line-crossing scanner is supplemented by the fixture scan.

`tools/stage_css_mshtml_native.py` validates explicit caller-approved receipts,
current/frozen source closure, original build artifacts, generated core fixtures,
successful hashed logs, shared source generations, native paths/bounds and corrected
complete instruction scans before creating a fresh direct child of the canonical
boot build. It starts nothing. Current preparation is
`/root/Win98-Modern-boot/build/css-mshtml-native-5abe-20261001-v2/guest-files.json`,
SHA256 `cef8c34813161bb544dbdcf3f8ba2ab83310d738d4d75642c17231b4e520320e`.
It contains exactly three native inputs and three fresh output paths.

A new actual guest trial requires the existing protected cold/noNIC GOP harness,
unchanged originals, the full20GiB reserve plus measured copy/dirty/staging floor,
adequate available memory and both the shared flock and an actually vacant QA slot.
Other sessions' guests outside the flock also prevent our launch. No peer process
or image may be stopped or changed to obtain that slot.

`tools/verify_css_mshtml_native.py` is read-only. Acceptance binds the approved
three builds and full frozen stage to actual harness source/hardware/preservation,
immutable/private input readbacks, fresh stopped collector outputs, strict actual
observer DWORD exit/flush/close and every required component observation. It checks
32px-to168px actual style/geometry, genuine parent identity, independent typed color
and Korean BSTR readbacks, completed holds and cleanup. The observer's requested
exit does not establish its own actual outer process exit.

`tests/test_css_mshtml_native_log.py` and `tests/test_verify_css_mshtml_native.py`
exercise deliberately synthetic protocol bytes and stopped-run metadata with
real frozen build bytes. They test missing/failed/duplicate/partial rows, short
holds/clock wrap, stale collector output, changed provenance, wrong hardware and
warm resume. No such test is native execution or native acceptance evidence.

Paint needs a separately caller-approved manual review of two distinct actual
harness captures, before/after in timestamp order, with exact run/manifest/input/
capture hashes. The optional review schema is
`win98modern.css-mshtml-paint-review.v1`; frame roles are `initial_gray` and
`modified_colors_korean`. Without it, successful native protocol acceptance still
sets `native_paint_verified=false`. No automatic image inference is performed.

This fixture consumes an explicit already-cascaded map from real DOM attributes.
General stylesheets/selectors/cascade, modern CSS layout, browser WPT, HTML/DOM
integration, current JS/Wasm and WebGPU/WebGL remain mandatory unfinished work.
