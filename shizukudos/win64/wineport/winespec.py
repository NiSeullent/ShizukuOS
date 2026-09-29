# SPDX-License-Identifier: GPL-2.0-only
"""Wine .spec file reader and stub classifier for the Wine port (external-reuse profile).

A .spec line is `ordinal calltype [flags] name(args) [implementation | forward.target]`. Only the entries that
winebuild would emit for x86_64 are kept (-arch= filtering).  Every kept entry is classified:

  real      the exported function has a body in the DLL's C sources that does work
  stub      `@ stub Name` in the spec, or a C body that is a FIXME("stub") / not-implemented / E_NOTIMPL shell
  semistub  a C body whose FIXME says semi-stub / partial: it does part of the work (exported, reported separately)
  forward   spec forward to another DLL (`Name(...) other.Name`)
  import    `-import` entries (implemented by another DLL and re-exported through the import table by winebuild)
  extern    data export
  unlocated no C definition was found (assembly, macro-generated or in a file not compiled); exported as real

Only real/semistub/extern (and forwards whose target is itself provided) become exports; stubs never do, so an
application that imports a Wine stub fails to load with STATUS_ENTRYPOINT_NOT_FOUND instead of calling a
function that pretends to succeed.
"""
import re
from pathlib import Path

ARCH = {"x86_64", "win64"}
ARCH_ALL = {"i386", "x86_64", "arm", "arm64", "arm64ec", "win32", "win64"}

_ENTRY = re.compile(r"^\s*(@|\d+)\s+(stdcall|cdecl|varargs|thiscall|fastcall|pascal|extern|stub)\b(.*)$")
_FLAG = re.compile(r"^-([a-z0-9]+)(?:=([^\s]+))?")


class Entry:
    __slots__ = ("ordinal", "calltype", "flags", "name", "args", "target", "kind", "reason", "noname")

    def __init__(self):
        self.ordinal = None
        self.calltype = ""
        self.flags = {}
        self.name = ""
        self.args = []
        self.target = None
        self.kind = "real"
        self.reason = ""
        self.noname = False

    def as_dict(self):
        return {"name": self.name, "ordinal": self.ordinal, "calltype": self.calltype, "kind": self.kind,
                "target": self.target, "reason": self.reason}


def arch_ok(spec):
    """-arch=a,b,!c : keep an entry for x86_64 when a listed architecture matches, or when only negations are listed
    and none of them matches."""
    if spec is None:
        return True
    want, exclude = set(), set()
    for tok in spec.split(","):
        if tok.startswith("!"):
            exclude.add(tok[1:])
        else:
            want.add(tok)
    if want:
        return bool(want & ARCH)
    return not (exclude & ARCH)


def parse_spec(path):
    entries = []
    for raw in Path(path).read_text(errors="replace").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        m = _ENTRY.match(line)
        if not m:
            continue
        e = Entry()
        e.ordinal = None if m.group(1) == "@" else int(m.group(1))
        e.calltype = m.group(2)
        rest = m.group(3).strip()
        while rest.startswith("-"):
            f = _FLAG.match(rest)
            if not f:
                break
            e.flags[f.group(1)] = f.group(2) if f.group(2) is not None else True
            rest = rest[f.end():].strip()
        if "i386" in e.flags:
            e.flags["arch"] = "i386"
        if not arch_ok(e.flags.get("arch")):
            continue
        e.noname = "noname" in e.flags
        if e.calltype in ("extern", "stub"):
            parts = rest.split()
            if not parts:
                continue
            e.name = parts[0]
            e.target = parts[1] if len(parts) > 1 else None
            e.kind = "extern" if e.calltype == "extern" else "stub"
            if e.kind == "stub":
                e.reason = "spec stub"
        else:
            nm = re.match(r"^([A-Za-z0-9_@?$.]+)\s*\(([^)]*)\)\s*(.*)$", rest)
            if not nm:
                continue
            e.name = nm.group(1)
            e.args = nm.group(2).split()
            tail = nm.group(3).strip()
            e.target = tail.split()[0] if tail else None
            if e.target and "." in e.target:
                e.kind = "forward"
            elif "import" in e.flags:
                e.kind = "import"
        entries.append(e)
    return entries


# ---------------------------------------------------------------- C-body classification
_STUB_WORDS = re.compile(r"\bstub\b|not implemented|unimplemented|not supported yet|no-?op", re.I)
_SEMI_WORDS = re.compile(r"semi-?stub|partial", re.I)
_NOTIMPL = re.compile(r"\b(E_NOTIMPL|STATUS_NOT_IMPLEMENTED|ERROR_CALL_NOT_IMPLEMENTED|ERROR_NOT_SUPPORTED|HRESULT_FROM_WIN32\s*\(\s*ERROR_CALL_NOT_IMPLEMENTED\s*\))\b")


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", lambda m: " " * m.group(0).count("\n") if False else "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def _find_bodies(text):
    """Yield (name, body) for every top-level function definition in a C file (heuristic, brace-matched)."""
    for m in re.finditer(r"(?m)^[A-Za-z_][^;{}#]*?\b([A-Za-z_]\w*)\s*\(([^;{}]*?)\)\s*(?:__attribute__\s*\(\([^)]*\)\)\s*)?\{", text):
        name = m.group(1)
        if name in ("if", "for", "while", "switch", "return", "sizeof", "defined", "WINE_DEFAULT_DEBUG_CHANNEL"):
            continue
        depth, i, start = 0, m.end() - 1, m.end()
        n = len(text)
        while i < n:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    yield name, text[start:i]
                    break
            elif c == '"' or c == "'":
                q = c
                i += 1
                while i < n and text[i] != q:
                    if text[i] == "\\":
                        i += 1
                    i += 1
            i += 1


def _depth_at(body, pos):
    """Brace depth of position pos inside a function body (0 = the body's own level); strings are skipped."""
    depth, i = 0, 0
    while i < pos:
        c = body[i]
        if c == '"' or c == "'":
            q = c
            i += 1
            while i < pos and body[i] != q:
                i += 2 if body[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return depth


_NOT_WORK = {"if", "for", "while", "switch", "return", "sizeof", "TRACE", "FIXME", "WARN", "ERR", "TRACE_", "FIXME_",
             "WARN_", "ERR_", "SetLastError", "debugstr_a", "debugstr_w", "debugstr_guid", "wine_dbgstr_w", "wine_dbgstr_a",
             "debugstr_an", "debugstr_wn", "wine_dbg_sprintf", "HRESULT_FROM_WIN32", "RtlSetLastWin32Error", "V_VT",
             "memset", "ZeroMemory", "TRACE_ON", "WINE_TRACE", "WINE_FIXME", "WINE_WARN", "WINE_ERR", "FAILED", "SUCCEEDED"}


def _does_work(body):
    """True when the body calls anything besides logging, SetLastError and trivial helpers."""
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", _strip_strings(body)):
        if m.group(1) not in _NOT_WORK:
            return True
    return False


def _strip_strings(text):
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)


def classify_body(body):
    """-> ("real" | "stub" | "semistub", reason)
    A FIXME that says stub/unimplemented at the body's own level of a short function marks a stub. The same FIXME
    inside a branch (an unsupported case of a function that does its work in the other branches) marks a partial
    implementation ("semistub", exported and reported separately); so does a long body with such a FIXME."""
    fixmes = [(m.group(1), m.start()) for m in
              re.finditer(r"FIXME(?:_\(\w+\))?\s*\(\s*\"((?:[^\"\\]|\\.)*)\"", body)]
    statements = body.count(";")
    for msg, _ in fixmes:
        if _SEMI_WORDS.search(msg):
            return "semistub", f'FIXME("{msg[:60]}")'
    for msg, pos in fixmes:
        if _STUB_WORDS.search(msg):
            if not _does_work(body):
                return "stub", f'FIXME("{msg[:60]}"), no other work'
            in_branch = _depth_at(body, pos) > 0 or re.search(r"\belse\s*$", body[:pos])
            if in_branch:
                return "semistub", f'FIXME("{msg[:50]}") in one branch'
            if statements <= 12:
                return "stub", f'FIXME("{msg[:60]}")'
            return "semistub", f'long body with FIXME("{msg[:50]}")'
    m = _NOTIMPL.search(body)
    if statements <= 6 and m and "return" in body:
        if _depth_at(body, m.start()) > 0 and statements > 3:
            return "semistub", f"returns {m.group(1)} in one branch"
        return "stub", "returns " + m.group(1)
    return "real", ""


def classify_entries(entries, sources):
    """Look up every entry's implementation in the given C files and set kind/reason for stubs."""
    bodies = {}
    for src in sources:
        text = _strip_comments(Path(src).read_text(errors="replace"))
        for name, body in _find_bodies(text):
            bodies.setdefault(name, (body, Path(src).name))
    for e in entries:
        if e.kind not in ("real",):
            continue
        impl = e.target or e.name
        found = bodies.get(impl)
        if not found:
            e.kind, e.reason = "unlocated", "no C definition found"
            continue
        kind, reason = classify_body(found[0])
        if kind != "real":
            e.kind, e.reason = kind, f"{found[1]}: {reason}"
    return entries


def def_lines(library, entries, forward_ok):
    """The EXPORTS block for mingw ld/dlltool. forward_ok(target) says whether a forward target is itself provided."""
    out = [f"LIBRARY {library}", "EXPORTS"]
    kept = []
    for e in entries:
        if e.kind in ("stub", "import", "unported", "missing"):
            continue
        if e.kind == "forward":
            if not forward_ok(e.target):
                e.kind, e.reason = "forward-missing", f"target {e.target} not provided"
                continue
            line = f"  {e.name} = {e.target}"
        elif e.kind == "extern":
            line = f"  {e.name} DATA" if not e.target else f"  {e.name} = {e.target} DATA"
        elif e.target and e.target != e.name:
            line = f"  {e.name} = {e.target}"
        else:
            line = f"  {e.name}"
        if e.ordinal is not None:
            line += f" @{e.ordinal}"
            if e.noname:
                line += " NONAME"
        out.append(line)
        kept.append(e)
    return out, kept


if __name__ == "__main__":
    import json
    import sys
    spec = Path(sys.argv[1])
    ents = parse_spec(spec)
    classify_entries(ents, sorted(spec.parent.glob("*.c")))
    counts = {}
    for e in ents:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    print(json.dumps(counts))
    for e in ents:
        if e.kind != "real":
            print(f"{e.kind:14} {e.name:40} {e.reason}")
