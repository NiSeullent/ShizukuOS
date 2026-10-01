#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the exact production modal function with callback/heap lifetime adapters.

The adapter revokes access to a destroyed dialog's state page. This makes the
original dangling-pointer reads deterministic, independent of allocator reuse.
This host check does not prove actual HWND, rendering or guest behavior; those
contracts are exercised by t_dialog_lifetime.c in the guest.
"""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ADAPTER = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
typedef int BOOL;
typedef intptr_t INT_PTR;
typedef uintptr_t HWND;
typedef void *HINSTANCE;
typedef const void *LPCDLGTEMPLATEW;
typedef void *DLGPROC;
typedef intptr_t LPARAM;
typedef struct { uintptr_t wParam; } MSG;
typedef struct { int ended; INT_PTR result; HWND focus; int modal; } dlginfo_t;
#define DLLAPI
#define WINAPI
#define TRUE 1
#define FALSE 0
#define GWL_STYLE 0
#define WS_CHILD 0x40000000
#define GA_ROOT 2
#define SW_SHOWNORMAL 1
#define ERROR_NOT_ENOUGH_MEMORY 8
static dlginfo_t *state;
static int live, owner_enabled, mode, shown, painted, dispatched, messages, quits, error, destroyed;
static BOOL IsWindow(HWND h) { return h == 1 ? live : h == 2; }
static dlginfo_t *dlg_info(HWND h, int create) { (void)create; return h == 1 && live ? state : NULL; }
static BOOL DestroyWindow(HWND h) {
    assert(h == 1 && live); live = 0; ++destroyed;
    if (state) assert(!mprotect(state, 4096, PROT_NONE));
    return TRUE;
}
static void __attribute__((unused)) SetLastError(int e) { error = e; }
static int GetWindowLongW(HWND h, int what) { (void)h; (void)what; return 0; }
static HWND GetAncestor(HWND h, int kind) { (void)kind; return h; }
static HWND CreateDialogIndirectParamW(HINSTANCE inst, LPCDLGTEMPLATEW tpl, HWND owner, DLGPROC proc, LPARAM init) {
    (void)inst; (void)tpl; (void)owner; (void)proc; (void)init;
    live = 1;
    if (mode != 10) {
        state = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(state != MAP_FAILED);
    }
    if (mode == 4) { DestroyWindow(1); return 0; }
    return 1;
}
static BOOL IsWindowEnabled(HWND h) { assert(h == 2); return owner_enabled; }
static BOOL EnableWindow(HWND h, BOOL enabled) {
    assert(h == 2); owner_enabled = enabled;
    if (!enabled && mode == 1) DestroyWindow(1);
    if (!enabled && mode == 5) { state->ended = 1; state->result = 73; }
    if (enabled && mode == 8 && live) DestroyWindow(1);
    return TRUE;
}
static BOOL ShowWindow(HWND h, int cmd) {
    assert(h == 1 && cmd == SW_SHOWNORMAL); ++shown;
    if (live && mode == 2) DestroyWindow(1);
    return TRUE;
}
static BOOL UpdateWindow(HWND h) {
    assert(h == 1); ++painted;
    if (live && mode == 3) DestroyWindow(1);
    return TRUE;
}
static BOOL GetMessageW(MSG *msg, HWND h, unsigned first, unsigned last) {
    (void)h; (void)first; (void)last; ++messages;
    assert(messages == 1);
    msg->wParam = 73;
    if (mode == 6) DestroyWindow(1);  /* sent callback dispatched inside GetMessage */
    if (mode == 11) { state->ended = 1; state->result = 73; }
    return mode != 9;
}
static void PostQuitMessage(int code) { assert(code == 73); ++quits; }
static BOOL IsDialogMessageW(HWND h, MSG *msg) { (void)h; (void)msg; if (mode == 12) DestroyWindow(1); return FALSE; }
static BOOL TranslateMessage(MSG *msg) { (void)msg; return TRUE; }
static intptr_t DispatchMessageW(MSG *msg) {
    (void)msg; ++dispatched;
    if (mode == 7) DestroyWindow(1);
    else if (live) { state->ended = 1; state->result = 73; }
    return 0;
}
static BOOL SetForegroundWindow(HWND h) { assert(h == 2); return TRUE; }
'''

HARNESS = r'''
int main(int argc, char **argv) {
    INT_PTR result;
    assert(argc == 2); mode = atoi(argv[1]);
    owner_enabled = 1;
    result = DialogBoxIndirectParamW(NULL, NULL, 2, NULL, 0);
    assert(result == ((mode == 0 || mode == 5 || mode == 11) ? 73 : -1));
    assert(owner_enabled == 1 && !live && destroyed == 1);
    if (mode >= 1 && mode <= 5) assert(messages == 0 && dispatched == 0);
    if (mode == 1 || mode == 4 || mode == 5 || mode == 10) assert(shown == 0 && painted == 0);
    if (mode == 2) assert(shown == 1 && painted == 0);
    if (mode == 3) assert(shown == 1 && painted == 1);
    if (mode == 6 || mode == 11 || mode == 12) assert(messages == 1 && dispatched == 0);
    if (mode == 9) assert(messages == 1 && dispatched == 0 && quits == 1);
    if (mode == 10) assert(error == ERROR_NOT_ENOUGH_MEMORY);
    if (state) assert(!munmap(state, 4096));
    printf("production modal callback case %d passed\n", mode);
    return 0;
}
'''


def function(source, signature):
    """Extract unchanged definition text, including its exact production body."""
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    return source[start:end]


def build(source_path, out, tag):
    source = source_path.read_text()
    bodies = []
    if "static dlginfo_t *live_dialog_info(" in source:
        bodies.append(function(source, "static dlginfo_t *live_dialog_info("))
    bodies.append(function(source, "DLLAPI INT_PTR WINAPI DialogBoxIndirectParamW("))
    generated = out / f"{tag}.c"
    generated.write_text(ADAPTER + "\n" + "\n".join(bodies) + "\n" + HARNESS)
    binary = out / tag
    command = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(generated), "-o", str(binary)]
    subprocess.run(command, check=True, timeout=30)
    return binary, command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--baseline-before", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    source = root / "dlls/user32/user32_dlg.c"
    out = args.build_dir or Path(tempfile.mkdtemp(prefix="shz-dialog-lifetime-"))
    out.mkdir(parents=True, exist_ok=True)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    binary, command = build(source, out, "fixed")
    cases = []
    for mode in range(13):
        result = subprocess.run([str(binary), str(mode)], capture_output=True, text=True, timeout=5)
        if result.returncode:
            raise AssertionError(f"case {mode}: {result.returncode}: {result.stderr}")
        cases.append(result.stdout.strip())
    counterfactual = []
    if args.baseline_before:
        baseline, _ = build(args.baseline_before, out, "before")
        for mode in (1, 2, 3):
            result = subprocess.run([str(baseline), str(mode)], capture_output=True, text=True, timeout=5)
            assert result.returncode == -11, f"baseline case {mode} did not expose the stale pointer: {result.returncode}"
            counterfactual.append({"case": mode, "returncode": result.returncode, "signal": "SIGSEGV on revoked destroyed-state page"})
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    receipt = {"mode": "exact production modal body with host callback and revoked-heap adapters",
               "source": str(source), "source_sha256": before, "command": command,
               "passed": cases, "baseline_counterfactual": counterfactual,
               "guest_execution": "not covered by this host check"}
    (out / "host-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"production modal lifetime: {len(cases)} callback cases passed; {len(counterfactual)} original stale reads reproduced")


if __name__ == "__main__":
    main()
