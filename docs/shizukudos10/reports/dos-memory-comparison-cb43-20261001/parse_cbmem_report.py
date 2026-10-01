#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline CBMEM report interpreter; validates reported values, never a VM run."""
import argparse
import hashlib
import json
from pathlib import Path
import re

HEADER = ("CB43 DOS MEMORY V1",
          "All values are raw 16-bit hexadecimal; FFFF can mean not measured.")
FOOTER = ("END=0001", "I/O and process outcome require actual DOS ERRORLEVEL.")
FIELD_NAMES = tuple((
    "PHASE INT12_TOTAL_KB COM_CS CURRENT_PSP AX3306_AX AX3306_BX AX3306_DX "
    "AX3306_FLAGS AX3306_DH_BIT4_RAW AX5800_STRATEGY AX5800_FLAGS AX5802_RAW_AX "
    "AX5802_FLAGS MCB_TYPE_BEFORE MCB_OWNER_BEFORE MCB_PARAS_BEFORE PSP_END_BEFORE "
    "SELF_KEEP_PARAS AH4A_AX AH4A_BX AH4A_FLAGS MCB_TYPE_AFTER MCB_OWNER_AFTER "
    "MCB_PARAS_AFTER PSP_END_AFTER AH48_AX AH48_LARGEST_PARAS AH48_FLAGS "
    "LARGEST_KB_FLOOR UNEXPECTED_OWN_SEG CLEANUP_AH49_AX CLEANUP_AH49_FLAGS "
    "CHECKS FAILURES"
).split())
KNOWN_PROBE = "0a93f6402ada0478ae6d95f1e02169e8f7fdd5b30c1353c0ec9d54bf00048c18"
KNOWN_KERNELS = {
    "62194db22e7d157865f9767c78ca3ecf7d7977d720a99a1afe8c8c02b1aebb3f": "CB43_WIN31_ONLY",
    "c1c86626585c8332a8788a01ded40c8795fd449d1832c9428436038530bbe906": "CB43_COMBINED_DOSMGR",
}


class ReportFormatError(ValueError):
    pass


def parse_report(data):
    if not isinstance(data, bytes) or len(data) != 810 or not data.endswith(b"\r\n"):
        raise ReportFormatError("Expected exact 810-byte CRLF report including final CRLF")
    try:
        lines = data.decode("ascii").split("\r\n")[:-1]
    except UnicodeDecodeError as exc:
        raise ReportFormatError("Report must be ASCII") from exc
    if any("\r" in x or "\n" in x for x in lines):
        raise ReportFormatError("Bare newline or carriage return")
    if tuple(lines[:2]) != HEADER or tuple(lines[-2:]) != FOOTER:
        raise ReportFormatError("Exact header/footer required")
    if len(lines) != 2 + len(FIELD_NAMES) + 2:
        raise ReportFormatError("Incorrect field/line count")
    fields = {}
    for expected, line in zip(FIELD_NAMES, lines[2:-2]):
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([0-9A-F]{4})", line)
        if not match:
            raise ReportFormatError("Expected uppercase four-digit hexadecimal field")
        name, value = match.groups()
        if name in fields:
            raise ReportFormatError("Duplicate field: " + name)
        if name != expected:
            raise ReportFormatError("Unknown/missing/reordered field: " + name)
        fields[name] = int(value, 16)
    return fields


def parse_marker(data):
    # FreeCOM ECHO before a redirect preserved one trailing ASCII space in the
    # physically read root markers. Accept that exact variant, no broad trim.
    match = re.fullmatch(rb"CBMEM_ERRORLEVEL=(0|[1-9][0-9]{0,2}) ?\r\n", data)
    if not match or int(match.group(1)) > 255:
        raise ReportFormatError("Expected one exact separate CBMEM_ERRORLEVEL=0..255 marker, optional single space, CRLF")
    return int(match.group(1))


def parse_and_interpret(report, marker, kernel_sha256, probe_sha256):
    f = parse_report(report)
    code = parse_marker(marker)
    kernel = kernel_sha256.lower()
    probe = probe_sha256.lower()
    checks = []

    def check(name, condition):
        checks.append({"name": name, "passed": bool(condition)})

    check("separate_DOS_ERRORLEVEL_zero", code == 0)
    check("known_source_built_probe_identity", probe == KNOWN_PROBE)
    check("known_source_built_kernel_identity", kernel in KNOWN_KERNELS)
    check("full_success_phase", f["PHASE"] == 7)
    check("eleven_actual_probe_contract_checks_reported", f["CHECKS"] == 11)
    check("zero_reported_contract_failures", f["FAILURES"] == 0)
    check("current_PSP_matches_nonzero_COM_CS", f["CURRENT_PSP"] == f["COM_CS"] and f["COM_CS"] > 0)
    check("before_own_MCB_type_M_or_Z", f["MCB_TYPE_BEFORE"] in (ord('M'), ord('Z')))
    check("after_own_MCB_type_M_or_Z", f["MCB_TYPE_AFTER"] in (ord('M'), ord('Z')))
    check("before_own_MCB_owner", f["MCB_OWNER_BEFORE"] == f["CURRENT_PSP"])
    check("after_own_MCB_owner", f["MCB_OWNER_AFTER"] == f["CURRENT_PSP"])
    check("retained_size_exact_322_paragraphs", f["SELF_KEEP_PARAS"] == 322 and f["MCB_PARAS_AFTER"] == 322)
    check("original_own_block_not_grown", f["MCB_PARAS_BEFORE"] >= 322)
    check("AH4A_actual_carry_clear", not (f["AH4A_FLAGS"] & 1))
    check("AH48_actual_carry_set", bool(f["AH48_FLAGS"] & 1))
    check("AH48_actual_insufficient_memory_error_8", f["AH48_AX"] == 8)
    check("no_unexpected_owned_allocation_cleanup_path", all(f[n] == 0xffff for n in
          ("UNEXPECTED_OWN_SEG", "CLEANUP_AH49_AX", "CLEANUP_AH49_FLAGS")))
    check("allocator_strategy_query_carry_clear", not (f["AX5800_FLAGS"] & 1))
    check("allocator_standard_conventional_strategy", f["AX5800_STRATEGY"] in (0,1,2))
    check("UMB_link_query_carry_clear", not (f["AX5802_FLAGS"] & 1))
    check("actual_UMB_link_AL_zero", (f["AX5802_RAW_AX"] & 0xff) == 0)

    total_paras = f["INT12_TOTAL_KB"] * 64
    largest = f["AH48_LARGEST_PARAS"]
    check("BIOS_total_base_memory_KB_nonzero_at_most_640", 0 < f["INT12_TOTAL_KB"] <= 640)
    check("original_own_MCB_span_inside_base_memory", f["CURRENT_PSP"] + f["MCB_PARAS_BEFORE"] <= total_paras)
    check("retained_own_MCB_span_inside_base_memory", f["CURRENT_PSP"] + f["MCB_PARAS_AFTER"] <= total_paras)
    check("largest_available_plus_retained_own_block_fits_base_memory", largest + 322 + 1 <= total_paras)
    check("reported_largest_KB_equals_actual_paragraphs_floor", f["LARGEST_KB_FLOOR"] == largest // 64)

    bx = f["AX3306_BX"]
    version_valid = (bx & 0xff) >= 5 and (bx >> 8) < 100 and (f["AX3306_AX"] & 0xff) != 0xff
    bit = f["AX3306_DX"] & 0x1000
    hma_consistent = f["AX3306_DH_BIT4_RAW"] == bit
    check("true_DOS5plus_version_fields_valid", version_valid)
    check("HMA_raw_bit_matches_returned_DX", hma_consistent)
    interpretable = kernel in KNOWN_KERNELS and probe == KNOWN_PROBE and version_valid and hma_consistent
    passed = all(c["passed"] for c in checks)
    return {
        "schema": "cb43-independent-conventional-memory-report-interpretation-v1",
        "status": "PASS_SCOPED_REPORTED_CONTRACT" if passed else "FAIL_SCOPED_REPORTED_CONTRACT",
        "acceptance_passed": passed,
        "report_bytes": len(report), "report_sha256": hashlib.sha256(report).hexdigest(),
        "marker_bytes": len(marker), "marker_sha256": hashlib.sha256(marker).hexdigest(),
        "separately_reported_DOS_ERRORLEVEL": code,
        "declared_input_identity": {"kernel_sha256": kernel, "probe_sha256": probe,
                                    "known_kernel_profile": KNOWN_KERNELS.get(kernel)},
        "raw_fields": f,
        "checks": checks,
        "failed_checks": [c["name"] for c in checks if not c["passed"]],
        "reported_memory": {"BIOS_total_KB": f["INT12_TOTAL_KB"], "largest_paragraphs": largest,
                            "largest_bytes": largest * 16, "largest_kib_floor": largest // 64,
                            "retained_probe_bytes_including_PSP": f["SELF_KEEP_PARAS"] * 16,
                            "minimum_580_KiB_gate_applied": False},
        "reported_HMA": {"interpretable": interpretable, "raw_DX_bit_0x1000": bit,
                         "DOS_in_HMA": bool(bit) if interpretable else None},
        "native_execution_verified": False,
        "external_guest_run_identity_or_marker_freshness_verified": False,
        "Windows98_verified": False, "MSDOS_replacement_under_Windows98": False,
        "modern_apps_verified": False,
        "limits": ["Offline report contract validation only; supplied source identities are declarations, not image inspection",
                   "Separate marker must be independently bound to this actual probe invocation by the run owner",
                   "All raw registers preserved; FFFF is never silently changed to zero",
                   "PSP allocation-end values are observations, not resize-success conditions",
                   "Memory measurement includes retained probe and its environment/parent shell",
                   "No free-memory threshold, Windows startup or MS-DOS replacement acceptance follows from this report"],
    }


def read_bounded(path, maximum):
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ReportFormatError("Input exceeds report/marker size bound")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("errorlevel_marker", type=Path)
    parser.add_argument("--kernel-sha256", required=True)
    parser.add_argument("--probe-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.report.resolve() == args.errorlevel_marker.resolve():
            raise ReportFormatError("Report and marker must be separate inputs")
        result = parse_and_interpret(read_bounded(args.report,2048), read_bounded(args.errorlevel_marker,64),
                                     args.kernel_sha256, args.probe_sha256)
    except (OSError,ReportFormatError) as exc:
        print(json.dumps({"status":"INVALID_REPORT_OR_MARKER", "error":str(exc),
                          "native_execution_verified":False,"Windows98_verified":False},indent=2))
        return 2
    print(json.dumps(result,indent=2))
    return 0 if result["acceptance_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
