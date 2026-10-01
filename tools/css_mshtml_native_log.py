#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strict component-only CSS/observer log protocol; logs alone are not native proof."""
import re

PREFIX = "C:\\GOPLAB\\"
FIXED = {
    "SETUP.PROFILE": "genuine-mshtml-current-css-var-consumer-v1",
    "SETUP.EXE_MODULE": PREFIX + "CSS13PR.EXE",
    "SETUP.SCOPE": "DOM fixture attributes to actual width/background styles; no selector/cascade/layout-engine/fullCSS claim",
    "SETUP.ACP": "949", "SETUP.CSS_MODULE": PREFIX + "M98CSS.DLL",
    "SETUP.MSHTML_VERSION_MAJOR": "5", "SETUP.MSHTML_VERSION_MINOR": "0",
    "SETUP.MSHTML_VERSION_BUILD": "2614", "SETUP.MSHTML_VERSION_REVISION": "3500",
    "INITIAL_SEQUENCE.INITIAL_CAPTURE_REQUIRED": "two gray32px boxes in real MSHTML; log is not pixel proof",
    "MODIFIED_SEQUENCE.MODIFIED_CAPTURE_REQUIRED": "blue parent/green child168px plus Korean label; independent review required",
    "EXIT.FAILURES": "0", "EXIT.STATUS": "PASS_COMPONENT_ONLY",
    "EXIT.NATIVE_PAINT_REVIEW": "required separately; logs are not pixel proof",
    "EXIT.FULL_MODERN_CSS": "not certified",
}
CHECKS = set()
HRESULTS = set()


def names(target, phase, values):
    target.update(phase + "." + name for name in values.split())


names(CHECKS, "SETUP", "ACTUAL_WIN98_SE KOREAN_ACP949 EXACT_ADJACENT_CSS_COMPONENT WINDOW_CLASS VISIBLE_NATIVE_MSHTML_HOST ACTUAL_SYSTEM_MSHTML EXACT_MSHTML_5_00_2614_3500 UI_TIMER")
names(HRESULTS, "SETUP", "COM_STA_INITIALIZE ACTUAL_MSHTML_CREATE MSHTML_OLE_OBJECT MSHTML_CLIENT_SITE REAL_DOCUMENT_INIT REAL_VIEW_INPLACE_ACTIVATION GENUINE_DOCUMENT_WRITE GENUINE_DOCUMENT_CLOSE REAL_DOCUMENT3")
for phase, parent, pixels in (("INITIAL_PARENT", True, 32), ("INITIAL_CHILD", False, 32),
                               ("FINAL_PARENT", True, 168), ("FINAL_CHILD", False, 168)):
    names(CHECKS, phase, "ACTUAL_BACKGROUND_TYPED_VALUE")
    FIXED[phase + ".ACTUAL_BACKGROUND_VARTYPE"] = "8"
    stem = "PARENT" if parent else "CHILD"
    FIXED[phase + "." + stem + "_STYLE_PIXEL_WIDTH"] = str(pixels)
    FIXED[phase + "." + stem + "_ACTUAL_OFFSET_WIDTH"] = str(pixels)
names(CHECKS, "INITIAL_SEQUENCE", "INITIAL_REAL_STYLES_AND_GEOMETRY")
names(HRESULTS, "INITIAL_SEQUENCE", "REAL_PARENT_ELEMENT REAL_CHILD_ELEMENT")
names(CHECKS, "PARENTAGE", "REAL_DOM_PARENT_CANONICAL_IDENTITY")
for phase in ("PARENT_SNAPSHOT", "CHILD_SNAPSHOT"):
    names(HRESULTS, phase, "REAL_DOM_WIDTH_ATTRIBUTE REAL_DOM_COLOR_ATTRIBUTE")
    names(CHECKS, phase, "ACTUAL_DLL_COMPUTED_SNAPSHOT")
for phase in ("PARENT_APPLY", "CHILD_APPLY"):
    names(HRESULTS, phase, "REAL_DOM_USE_WIDTH GENUINE_STYLE_INTERFACE GENUINE_PIXEL_WIDTH_SETTER GENUINE_BACKGROUND_SETTER")
    names(CHECKS, phase, "ACTUAL_DLL_VAR_SUBSTITUTION ACTUAL_DLL_COMPUTED_COLOR REAL_TOKEN_INTEGER_PX REAL_TOKEN_HEX_COLOR")
names(CHECKS, "CHILD_APPLY", "PARENT_RELEASED_BEFORE_CHILD_CONSUMPTION")
names(HRESULTS, "KOREAN_MUTATION", "REAL_STATUS_ELEMENT GENUINE_KOREAN_TEXT_SETTER")
names(CHECKS, "KOREAN_MUTATION", "INDEPENDENT_FULL_KOREAN_TEXT_READBACK")
names(CHECKS, "MUTATION_CLEANUP", "ALL_CORE_ALLOCATIONS_RELEASED")
names(CHECKS, "FINAL_SEQUENCE", "FINAL_REAL_STYLES_AND_GEOMETRY")
names(CHECKS, "COMPLETE_SEQUENCE", "REAL_DOCUMENT_STYLE_SEQUENCE_COMPLETED")
names(HRESULTS, "COM_CLEANUP", "VIEW_UI_DEACTIVATE VIEW_HIDE VIEW_CLOSE VIEW_DETACH OLE_CLOSE OLE_DETACH")
names(CHECKS, "COM_CLEANUP", "CLIENT_SITE_REFS_RELEASED")
names(CHECKS, "EXIT", "ALL_CORE_ALLOCATIONS_RELEASED_AT_EXIT CSS_MODULE_RELEASE")
TIMES = {"INITIAL_SEQUENCE.INITIAL_TICK", "MODIFIED_SEQUENCE.MODIFIED_TICK",
         "MODIFIED_SEQUENCE.INITIAL_HOLD_MS", "COMPLETE_SEQUENCE.MODIFIED_HOLD_MS"}
DYNAMIC = TIMES | {"SETUP.MSHTML_MODULE"}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fields(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 65536 and raw.endswith(b"\r\n"),
         "empty/large/partial native log")
    lines = raw[:-2].decode("ascii").split("\r\n")
    result = {}
    for line in lines:
        need(0 < len(line) <= 512 and "=" in line and "\r" not in line and "\n" not in line,
             "malformed native log row")
        key, value = line.split("=", 1)
        need(key and key not in result, "duplicate native log key")
        result[key] = value
    return result


def uint(value):
    need(re.fullmatch(r"0|[1-9][0-9]{0,9}", value) and int(value) <= 0xffffffff,
         "invalid native DWORD")
    return int(value)


def component(raw):
    observed = fields(raw)
    need(set(observed) == set(FIXED) | CHECKS | HRESULTS | DYNAMIC,
         "native CSS log is incomplete or has unexpected diagnostics")
    need(all(observed[k] == v for k, v in FIXED.items()) and
         all(observed[k] == "PASS" for k in CHECKS), "native CSS component failed")
    for key in HRESULTS:
        need(re.fullmatch(r"[0-9a-f]{8}", observed[key]) and int(observed[key], 16) < 0x80000000,
             "native HRESULT failure: " + key)
    need(re.fullmatch(r"[A-Za-z]:\\[A-Za-z0-9 _-]{1,64}\\SYSTEM\\MSHTML\.DLL",
                      observed["SETUP.MSHTML_MODULE"], re.I), "invalid system MSHTML path")
    times = {k: uint(observed[k]) for k in TIMES}
    initial, modified = times["INITIAL_SEQUENCE.INITIAL_TICK"], times["MODIFIED_SEQUENCE.MODIFIED_TICK"]
    initial_hold = times["MODIFIED_SEQUENCE.INITIAL_HOLD_MS"]
    modified_hold = times["COMPLETE_SEQUENCE.MODIFIED_HOLD_MS"]
    elapsed = (modified - initial) & 0xffffffff
    need(10000 <= initial_hold <= elapsed < 45000 and 12000 <= modified_hold < 45000 and
         elapsed + modified_hold < 45000, "CSS phase hold/deadline evidence differs")
    return dict(mshtml_module=observed["SETUP.MSHTML_MODULE"],
                initial_hold_ms=initial_hold, modified_hold_ms=modified_hold,
                verified_initial_geometry=32, verified_modified_geometry=168,
                korean_full_bstr_readback=True, native_paint_verified=False)


def observer(raw, nonce):
    observed = fields(raw)
    expected = dict(scope="actual-win98-css-owned-child-observer", nonce=nonce,
        profile="genuine-mshtml-css-variable-consumer", WIN98_IDENTIFIED="1")
    expected.update({"os.major": "4", "os.minor": "10", "os.build-low": "2222", "os.platform": "1",
        "child.path": PREFIX + "CSS13PR.EXE", "child.stdout": PREFIX + "CSOUT.LOG",
        "child.created": "1", "child.create-error": "0", "child.wait": "0", "child.exit-query": "1",
        "child.exit-query-error": "0", "child.exit-code": "0", "child.stdout-flushed": "1",
        "child.handles-closed": "1", "child.success": "1", "supervisor.requested-exit-code": "0"})
    need(set(observed) == set(expected) | {"child.pid"} and
         all(observed[k] == v for k, v in expected.items()), "actual owned child completion missing")
    pid = uint(observed["child.pid"])
    need(pid > 0, "actual child PID required")
    return pid
