# FD5C VxD host receipt input closure

- Worktree: `/root/Win98-Modern-pma-integration-fd5c-20261002`.
- Owned files: `ntwrapper/vxd/test.py`, new `ntwrapper/vxd/tests/test_receipt_inputs.py`, this status file.
- Dependencies: root imported peer VxD admission, copied-header geometry corrections and the complete IPC snapshot followup; full combined build/test acceptance is root-owned.
- Code commit: `04fb9df`, after independent compatibility review. This agent did not change the Git index or create a commit.

## Problem and change

The host receipt previously hashed VxD-directory inputs, shared wrapper inputs and build artifacts, while checking external manifest dependencies only before testing. A persistent change to `shizukudos/abi/shz_abi.h` or `shz_ipc.h` during the child test process could therefore leave `passed` and `inputs_unchanged_during_test` true.

The runner now includes every `manifest['sources']` path in its deduplicated initial input set. Build-source validation uses those exact captured hashes, and the existing final comparison checks every captured manifest dependency as well as prior inputs. This also covers future external dependencies declared by the build manifest without adding a separate hardcoded header list. Receipt layout and native acceptance flags remain unchanged.

Independent root and compatibility review also found a parse/capture race: the runner could parse manifest M1, then capture the hash of a persistent replacement M2 while using M1's dependency closure. It now reads the manifest bytes once, parses those exact bytes, and requires their SHA256 to equal the initial captured manifest hash before child admission.

## Focused RED/GREEN evidence

Command executed before the production change and again afterwards:

```sh
python3 -B ntwrapper/vxd/tests/test_receipt_inputs.py
```

The fixture copies the actual runner into a temporary private project under `build/fd5c-vxd-receipt/`. Manifest parsing, source hashes, admission checks, final input comparisons and receipt decisions execute the real runner. Its child test-process boundary is modeled. The parse/capture regression additionally wraps the private manifest read: it returns the old bytes and immediately persists a new manifest declaring a new dependency, before initial hash capture. Fixture headers and artifact bytes are private placeholders. No compiler, VxD, Windows guest or real project ABI file executes or changes in these tests.

- RED: command exited 1, with seven expected assertion failures across six tests. Persistent changes to each ABI header and a newly declared external dependency still returned success; those three paths were absent from receipt hashes; deletion of the private IPC header also returned success. The unchanged-input, stale-build rejection and failing-child controls passed. Evidence: `build/fd5c-vxd-receipt/red.log`.
- Initial GREEN: all six tests passed, exit 0, using eight invocations of the actual receipt runner. It rejected persistent external changes/deletion, recorded original hashes for every manifest source, preserved unchanged success, rejected stale build inputs, and preserved failed child results. Evidence: `build/fd5c-vxd-receipt/green.log`.
- Review regression RED: the new manifest-read boundary test failed because the mismatched snapshot still returned success; the other six tests passed. Evidence: `build/fd5c-vxd-receipt/manifest-red.log`.
- Final GREEN: all seven tests passed, exit 0, using nine invocations of the actual runner. The manifest snapshot mismatch is rejected before the modeled child runs and no new success receipt is written. Evidence: `build/fd5c-vxd-receipt/manifest-green.log`, SHA256 `70049426c04d3ccb56fa3f956a32c0a85fd51eb18b4cba5582933f30ee11a797`.
- Scoped `git diff --check` passed.

Final source SHA256:

- `test.py`: `f6318f3b36d8530295288432ae7596d0c421e73478392e36aeeea77b01817642`.
- `tests/test_receipt_inputs.py`: `645acc06d4cb717b56dbf8ccf392c21ad4e6b4b6c494f2e0f5fe477e7cefc4d5`.

## Limits and remaining work

Initial/final samples detect persistent observed input drift; edits reverted between samples are not proven absent. The build manifest must continue listing its complete actual source dependencies. This change does not introduce compiler-derived dependency discovery or change transport/runtime semantics.

After the live ABI source froze, root built the actual VxD and ran the complete
host runner:20 tests passed, including these seven receipt controls and actual
C bridge/W64 wire/admission tests with sanitizer/thread checks. The receipt
`build/fd5c-vxd-final/host-tests.json` records50 input hashes, both external ABI
headers and exact manifest identity, with passed/input-stability true. This agent
did not execute those root checks. Historical receipts and real ABI files were
preserved.

Actual Windows 98/VMM/loaded VxD/Supervisor/PMA round-trip acceptance remains a separate runtime gate. Windows 98 remains the product OS and VMM keeps Windows thread authority.
