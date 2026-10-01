# Actual DOS LOW/HIGH memory comparison

Two separate root-owned 128 MiB, one-CPU TCG guests produced fresh `CBMEM.TXT` reports and independently captured DOS ERRORLEVEL markers. Both actual reports satisfy the eleven original diagnostic checks and the independent parser's 28 scoped report/interpretation gates. The frozen diagnostic source/build checkpoint is [the prior memory source checkpoint](../dos-conventional-memory-cb43-20261001/README.md); its eleven files remain unchanged.

| Actual root profile | Largest available paragraphs | Largest bytes | Floor KiB | Raw AX=3306 DX HMA bit |
|---|---:|---:|---:|---|
| DOS=LOW | 35,765 (`8BB5`) | 572,240 | 558 | `0000` |
| DOS=HIGH | 39,139 (`98E3`) | 626,224 | 611 | `1000` |

The measured difference is 3,374 paragraphs / 53,984 bytes. INT 12 reports **639 KiB total contiguous base memory**, not free memory, in both runs. Actual successful allocator strategy queries returned 0 and UMB linkage AL=0. The parser checks the reported block-size arithmetic, own MCB/PSP and protected 322-paragraph allocation, actual AH=4A carry clear, AH=48 carry set/error 8 and the independently reported ERRORLEVEL 0. It preserves undefined successful-call register values and every raw FFFF without replacing them with zero.

The known source-built kernel is the earlier CB43 WIN31-only `62194db22e7d157865f9767c78ca3ecf7d7977d720a99a1afe8c8c02b1aebb3f`, with the primary DOSMGR patch excluded. Actual AX=3306 returned BX=0A07; the HIGH run's raw DX=1000 selects DH bit 4. In the pinned FreeDOS implementation this flag is set after real HMA reservation/A20/kernel relocation. It is not inferred from the CONFIG request. Source declarations passed to an offline parser do not independently establish an actual disk's contents; [the limited root runtime receipt](native-memory-comparison-receipt.json) binds the actual source-built inputs, report freshness, process runs and readbacks separately.

These are the actual diagnostic-point measurements, with the 5,152-byte retained probe allocation, its environment and parent shell still present, before report creation and later XMS/DOS/Windows commands. **They do not establish that 580 KiB will be available to a later Windows process.** The parser applies no minimum-free-memory threshold. A synthetically valid below-580 or zero-free-memory report can pass the scoped format/measurement contracts; that is not a simulated Windows acceptance test.

The root-owned guests were stopped after 30.13 and 30.20 seconds. Host process exit 0 and the separately captured probe ERRORLEVEL 0 do not imply a clean guest shutdown. The root session observed the actual Registry Checker continuing to restore files; Windows startup/VMM/desktop, replacement of MS-DOS and modern application acceptance remain **unverified**. No Windows/Microsoft originals, disk images, screenshots, registry hives, user details or keys are included here.

## Exact report and marker contracts

The report is exactly 810 ASCII bytes with CRLF lines, the two exact header lines, 34 unique four-digit uppercase hexadecimal fields in source order and the two exact footer lines. Full success requires PHASE=0007, CHECKS=000B and FAILURES=0000 plus a separately captured DOS ERRORLEVEL 0. The parser requires the known diagnostic/source kernel identities, validates own PSP/MCB ownership and sizes, a standard conventional strategy 0/1/2 and unlinked UMB AL=0 with successful queries, AH=48 CF=1/AX=8, base-memory span constraints and exact BX/64 floor KiB arithmetic. It checks BL>=5, BH<100, AL!=FF and raw DX-bit consistency before interpreting HMA for a known kernel. PSP+2 allocation-end values are observations and are not used as resize-success conditions.

The actual marker's unchanged bytes are `CBMEM_ERRORLEVEL=0 ` followed by CRLF: FreeCOM ECHO before redirection retained one trailing ASCII space. The parser accepts either no space or that **single** trailing ASCII space; it never broadly strips whitespace. Negative fixtures reject multiple spaces, tabs, missing CRLF, duplicate markers, invalid unsigned decimal codes, nonzero ERRORLEVEL, duplicate/missing/reordered/unknown fields, invalid hexadecimal/ASCII, truncated or altered headers/footers, source/ownership/carry/layout contradictions and invalid HMA/version interpretation. [Sixteen synthetic host test groups](synthetic-tests.log) passed. They do not execute DOS, BIOS or Windows.

The two [guest reports](low-memory.txt) / [HIGH report](high-memory.txt) and the [byte-identical marker from both runs](dos-errorlevel-marker.txt) are exact guest bytes. [LOW interpretation](low-interpretation.json) and [HIGH interpretation](high-interpretation.json) are independently generated offline outputs; their `native_execution_verified` and freshness flags remain false because an offline parser cannot establish the parent run's provenance. The runtime receipt supplies that separate limited evidence. [Independent read-only source review](independent-parser-review.json) examined all parser/tests and the actual result arithmetic without executing them.

## Source-only reproduction

Python 3's standard library is sufficient; there are no cached tools or private directory dependencies. The parser reads bounded report/marker inputs and prints JSON. It writes no file, starts no guest and performs no network operation:

```sh
python3 -B parse_cbmem_report.py low-memory.txt dos-errorlevel-marker.txt \
  --kernel-sha256 62194db22e7d157865f9767c78ca3ecf7d7977d720a99a1afe8c8c02b1aebb3f \
  --probe-sha256 0a93f6402ada0478ae6d95f1e02169e8f7fdd5b30c1353c0ec9d54bf00048c18
python3 -B -m unittest -v test_parse_cbmem_report
```

For HIGH, substitute `high-memory.txt`. CLI exit 0 means the scoped reported contracts pass; 1 means semantic/identity/ERRORLEVEL gates fail; 2 means a malformed, missing or oversized report/marker. An actual run owner must bind the marker immediately to this diagnostic invocation, establish both outputs were absent before launch and verify input/readback hashes. The CLI is not a no-follow file reader or an external VM freshness verifier; the actual inputs here were separately checked to be ordinary owned files.

The original parser/tests are GPL-2.0-only. [Parser/source receipt](parser-source-receipt.json) and [checkpoint manifest](checkpoint-manifest.json) preserve all published source/text hashes. Previous DOS/XMS/memory source checkpoints remain unchanged. The source/parser agent ran only bounded host tests and offline parsing; root alone executed the private guests. Source-only publication retains no compiled diagnostic, manager or compiler binaries.
