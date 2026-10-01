# Zetscape historical JavaScriptCore Wasm probes

The boot snapshot contained six original probe source/patch/pin files absent from the live branch checkpoint. They are preserved here byte for byte, together with six bounded historical compiler failure/receipt/dependency records. This is a source-only continuation archive, outside the production build. The original probe pins state `engine_built=false`, `guest_executed=false`, `browser_pass=false` and `full_wasm_conformance_pass=false`; these records do not establish browser or Wasm support. Absolute paths identify the original lab and are not prerequisites for cloning the project.

Original snapshot: `a73a7725776bb7de80617569e9879b892f77c701`. Parent reviewed project seams remain under `tools/iewebkit_port/zetscape_capabilities_83bd/`. Rebuild from pinned original source in an isolated directory before any new execution claim; do not reuse these historical receipts as fresh acceptance.
