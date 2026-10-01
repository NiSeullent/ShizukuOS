# Actual combined-kernel HIGH follow-up

This is a **new follow-up** to the frozen [LOW/HIGH runtime checkpoint](../dos-memory-comparison-cb43-20261001/README.md). Its thirteen files and the earlier eleven compile/static memory-source files remain unchanged. Root alone ran a third, separately owned guest with the source-built **combined** CB43 WIN31 C+NASM kernel plus the primary honest DOSMGR patch. The kernel is 72,751 bytes, SHA-256 `c1c86626585c8332a8788a01ded40c8795fd449d1832c9428436038530bbe906`; it is distinct from the earlier CB43-only `62194...` kernel.

The root source review physically matched all 288 patched/configured source inputs and five linked/build artifacts, and verified correspondence between the distinct public sanitized build receipt `891e76c07ee93923eb1f582709694b8155581b7b0feb22963a449d66ce1ed056` and private raw receipt `6b5f90db8a13b8120facbf3e5406335f90f931bc3d232fbd1b2c6fcea1f3e8e0`. That source review did not rebuild a kernel or execute a guest; its false pre-run VM flags remain intact. The [separate limited runtime receipt](native-combined-memory-receipt.json) supplies the later actual execution provenance.

The new guest-written 810-byte memory report is byte-identical to the earlier [HIGH report](../dos-memory-comparison-cb43-20261001/high-memory.txt), SHA-256 `48af4cd9ae837ae930340d783eae4d683cd34860f41e01f4704eaa31ef69e9e6`. Its independently captured 21-byte ERRORLEVEL marker is byte-identical to the [prior marker](../dos-memory-comparison-cb43-20261001/dos-errorlevel-marker.txt), SHA-256 `456e7641cd18025324e4d151fcd540b810932f44c369cc04261bef90bb406aeb`. These are shared files, not an old execution result transferred to a different kernel. Fresh absence, root-owned execution, new physical report readback and unchanged input readbacks bind this distinct run.

Actual PHASE=7, eleven checks, zero failures and separately captured DOS ERRORLEVEL 0 agree with the [new combined-kernel interpretation](combined-high-interpretation.json). All 28 offline interpretation gates pass. The actual largest block is 39,139 paragraphs / 626,224 bytes / floor 611 KiB; the raw HMA flag is 1000h with a valid known-source AX=3306 version response. The independent parser still does not attest guest provenance; its native/freshness flags remain false and the runtime receipt supplies that separate evidence. Additional fresh guest-written reports contain 17 DOS internals passes and 16 XMS passes; their physical report identities and scoped footer checks are recorded without exporting more logs.

The preparation retained a **30-second** capture target. Before launch, root changed only its new controller to the reviewed preflight harness and a **120-second** target/twelve capture intervals. Actual command/result record 120 / 120.08 seconds. The [controller clarification](controller-change-summary.json) preserves both values. The command's `preparation_input_sha256` identifies the prepared private image, not the preparation JSON; those namespaces are distinct. The current controller-source hash is explicitly an **after-run** identity, not a fabricated prelaunch self-pin. Exact cleanup path and QMP quit acknowledgment were not recorded; only stopped/reaped process state is asserted, with clean guest shutdown false.

Root's earlier combined-v1 preparation failed before guest launch because a public sanitized receipt identity was applied to the distinct private receipt namespace. That failed attempt remains preserved and supplies no guest evidence. This follow-up binds only the corrected actual combined-v2 run and does not rewrite preparation, source-review, compile/static or earlier runtime records.

The actual 120-second root capture remained at the Windows Registry Checker's restored-good-registry/restart prompt. No Enter/input was sent. These DOS memory/XMS/internals results do **not** establish later Windows-process free memory, successful Windows startup/VMM/desktop, replacement of MS-DOS or native modern application compatibility. No 580 KiB acceptance gate is applied. No private paths, Microsoft originals, images, screenshots, registry hives, keys or compiled binaries are published.

To reproduce only the offline interpretation from the prior source-only checkpoint:

```sh
python3 -B ../dos-memory-comparison-cb43-20261001/parse_cbmem_report.py \
  ../dos-memory-comparison-cb43-20261001/high-memory.txt \
  ../dos-memory-comparison-cb43-20261001/dos-errorlevel-marker.txt \
  --kernel-sha256 c1c86626585c8332a8788a01ded40c8795fd449d1832c9428436038530bbe906 \
  --probe-sha256 0a93f6402ada0478ae6d95f1e02169e8f7fdd5b30c1353c0ec9d54bf00048c18
```

That command reads text and prints a scoped JSON interpretation; it does not execute DOS or inspect an actual image. Root alone owns further private Windows validation. [checkpoint-manifest.json](checkpoint-manifest.json) freezes this follow-up's source/text identities.
