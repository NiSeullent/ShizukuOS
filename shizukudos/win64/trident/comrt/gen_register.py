#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate register_table.h: the registry keys tridentrt seeds for the Wine browser modules (register.c).

What Wine writes when the modules' DllRegisterServer runs (advpack RegInstall of the .inf, the widl-generated
registration scripts of the IDL files with `#pragma makedep register` / `regtypelib`, and the modules' own .rgs
scripts) is reproduced from the pinned Wine tree, without running any of it on Shizuku:
  - widl -r / widl -t output of every registration IDL (the same scripts Wine's makefiles build into the DLLs),
  - the .rgs scripts the modules' .rc files embed as WINE_REGISTRY resources,
  - the AddReg sections of the RegisterDll section of mshtml.inf and urlmon.inf, with mshtml's CLSID string table
    (dlls/mshtml/main.c register_server).
%MODULE% becomes C:\\SHZ\\SYS64\\<dll>. Left out on purpose: the HKCR\\Interface keys (proxy/stub and typelib
marshaler registrations; there is no cross-apartment marshaling here, and they are most of the volume) and the
HKCR\\Component Categories names. Added: Wine's Gecko location for mshtml (HKLM\\Software\\Wine\\MSHTML\\2.47.4
GeckoPath = C:\\SHZ\\SYS64\\gecko, dlls/mshtml/nsembed.c find_wine_gecko_reg), where the fake-Gecko xul.dll lives.

Usage: python3 gen_register.py   (needs build/upstream/wine configured by wineport/build.py: tools/widl/widl)
"""
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
WINE = REPO / "build" / "upstream" / "wine"
SYS64 = "C:\\SHZ\\SYS64\\"

# (wine path, widl mode or "rgs", DLL that %MODULE% names[, HKCR subtrees to leave out])
SCRIPTS = [
    ("dlls/mshtml/mshtml_classes.idl", "-r", "mshtml.dll"),
    ("dlls/mshtml.tlb/mshtml_tlb.idl", "-t", "mshtml.tlb"),
    ("dlls/urlmon/urlmon_urlmon.idl", "-r", "urlmon.dll"),
    ("dlls/urlmon/urlmon.rgs", "rgs", "urlmon.dll"),
    ("dlls/ieframe/ieframe_v1.idl", "-r", "ieframe.dll"),
    ("dlls/ieframe/ieframe_v1.idl", "-t", "ieframe.dll"),
    ("dlls/ieframe/ieframe.rgs", "rgs", "ieframe.dll"),
    ("dlls/jscript/jscript_classes.idl", "-r", "jscript.dll"),
    ("dlls/jscript/jsglobal.idl", "-t", "jscript.dll"),
    ("dlls/jscript/jscript.rgs", "rgs", "jscript.dll"),
    # Wine's msxml.dll and msxml2.dll are forwarders whose DllGetClassObject is msxml3's (msxml.spec, msxml2.spec):
    # their classes (Microsoft.XMLDOM, Microsoft.XMLHTTP, DOMDocument 2.6, ...) are registered to msxml3.dll
    # directly; their type libraries (in msxml.dll/msxml2.dll, not ported) are not registered. msxml3 comes after
    # them, so the version-independent Msxml2.* ProgIDs they share end up at the 3.0 classes, as on Windows with
    # MSXML 3 (and as Wine's registration order leaves them).
    ("dlls/msxml/msxml_tlb.idl", "-t", "msxml3.dll", {"Typelib"}),
    ("dlls/msxml/msxml.rgs", "rgs", "msxml3.dll"),
    ("dlls/msxml2/msxml2_tlb.idl", "-t", "msxml3.dll", {"Typelib"}),
    ("dlls/msxml3/msxml3_v1.idl", "-t", "msxml3.dll"),
    ("dlls/msxml3/xmlparser.idl", "-r", "msxml3.dll"),
    ("dlls/oleacc/oleacc_classes.idl", "-r", "oleacc.dll"),
    ("dlls/oleacc/oleacc_classes.idl", "-t", "oleacc.dll"),
    ("dlls/stdole2.tlb/stdole2.idl", "-t", "stdole2.tlb"),
]
INFS = [("dlls/mshtml/mshtml.inf", "RegisterDll"), ("dlls/urlmon/urlmon.inf", "RegisterDll")]
SKIP_SUBTREES = {("HKCR", "Interface"), ("HKCR", "Component Categories")}
ROOTS = {"HKCR": "HKEY_CLASSES_ROOT", "HKCU": "HKEY_CURRENT_USER", "HKLM": "HKEY_LOCAL_MACHINE",
         "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
         "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE"}


def show(path):
    return subprocess.run(["git", "-C", str(WINE), "show", f"HEAD:{path}"], capture_output=True, check=True).stdout


class Entry:
    def __init__(self, root, key, name, kind, data, source):
        self.root, self.key, self.name, self.kind, self.data, self.source = root, key, name, kind, data, source


# ---------------------------------------------------------------- .rgs (ATL registrar syntax, as widl writes it)
def rgs_tokens(text):
    for m in re.finditer(r"'((?:[^']|'')*)'|([{}=])|([^\s{}=']+)", text):
        if m.group(1) is not None:
            yield ("str", m.group(1).replace("''", "'"))
        elif m.group(2):
            yield (m.group(2), m.group(2))
        else:
            yield ("word", m.group(3))


def rgs_entries(text, module, source, skip_extra=()):
    toks = list(rgs_tokens(text))
    skipped = {(ROOTS[r], k.lower()) for r, k in SKIP_SUBTREES} | {("HKEY_CLASSES_ROOT", k.lower()) for k in skip_extra}
    out, i = [], 0

    def subst(s):
        return s.replace("%MODULE%", SYS64 + module).replace("%%", "%")

    def value(j):                                           # type letter + value token
        kind, (t, v) = toks[j][1], toks[j + 1]
        if kind == "s":
            return ("sz", subst(v)), j + 2
        if kind == "e":
            return ("expand_sz", subst(v)), j + 2
        if kind == "d":
            return ("dword", int(v, 0)), j + 2
        if kind == "b":
            return ("binary", bytes.fromhex(v)), j + 2
        raise SystemExit(f"{source}: unsupported rgs value type {kind}")

    def body(j, root, path, skip):
        while toks[j][0] != "}":
            j = key(j, root, path, skip)
        return j + 1

    def key(j, root, path, skip):
        if toks[j][1] == "val":                             # val name = type 'data'
            name = toks[j + 1][1]
            assert toks[j + 2][0] == "="
            v, j = value(j + 3)
            if not skip:
                out.append(Entry(root, "\\".join(path), name, v[0], v[1], source))
            return j
        while toks[j][1] in ("NoRemove", "ForceRemove", "Delete"):
            j += 1
        name = subst(toks[j][1])
        j += 1
        sub = path + [name]
        sub_skip = skip or (root, "\\".join(sub).lower()) in skipped
        if j < len(toks) and toks[j][0] == "=":
            v, j = value(j + 1)
            if not sub_skip:
                out.append(Entry(root, "\\".join(sub), None, v[0], v[1], source))
        elif not sub_skip:
            out.append(Entry(root, "\\".join(sub), None, "key", None, source))
        if j < len(toks) and toks[j][0] == "{":
            j = body(j + 1, root, sub, sub_skip)
        return j

    while i < len(toks):
        root = ROOTS[toks[i][1]]
        assert toks[i + 1][0] == "{", source
        i = body(i + 2, root, [], False)
    return out


def widl_script(idl, mode, tmp):
    """The WINE_REGISTRY text widl embeds for `idl` (-r: register resource, -t: the typelib's registration)."""
    src = tmp / idl
    out = tmp / (src.stem + ("_r.res" if mode == "-r" else "_t.res"))
    cmd = [str(WINE / "tools/widl/widl"), "-o", str(out), "-m64", "--nostdinc", "-L", str(tmp), "-I", str(src.parent),
           "-I", str(WINE / "include"), "-I", str(WINE / "include/msvcrt"), "-D_UCRT", "-D__WINESRC__", str(src)]
    subprocess.run(cmd, check=True)
    data = out.read_bytes()
    start = data.find(b"HKCR")
    if start < 0:
        start = min(p for p in (data.find(b"HKLM"), data.find(b"HKCU")) if p >= 0)
    end = data.find(b"\0", start)
    return data[start:end].decode("ascii")


# ---------------------------------------------------------------- .inf AddReg
def inf_entries(path, section, strings):
    text = show(path).decode("latin-1")
    sections, cur = {}, None
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            cur = sections.setdefault(m.group(1).lower(), [])
            continue
        if cur is not None:
            cur.append((n, line))
    for n, line in sections.get("strings", []):
        k, _, v = line.partition("=")
        strings[k.strip()] = v.strip().strip('"')
    out = []

    def fields(line):
        res, cur, q, i = [], "", False, 0
        while i < len(line):
            c = line[i]
            if c == '"':
                if q and i + 1 < len(line) and line[i + 1] == '"':
                    cur += '"'
                    i += 1
                else:
                    q = not q
            elif c == "," and not q:
                res.append(cur.strip())
                cur = ""
            elif c == ";" and not q:
                break
            else:
                cur += c
            i += 1
        res.append(cur.strip())
        return res

    folded = {k.lower(): v for k, v in strings.items()}     # INF string keys are case-insensitive

    def subst(s):
        return re.sub(r"%([^%]*)%", lambda m: "%" if not m.group(1) else folded[m.group(1).lower()], s)

    addreg = []
    for n, line in sections[section.lower()]:
        k, _, v = line.partition("=")
        if k.strip().lower() == "addreg":
            addreg += [s.strip() for s in v.split(",")]
    for sec in addreg:
        for n, line in sections[sec.lower()]:
            f = fields(line)
            root, key, name = ROOTS[f[0]], subst(f[1]), subst(f[2]) if len(f) > 2 and f[2] else None
            flags = int(f[3], 0) if len(f) > 3 and f[3] else 0
            data = f[4:]
            src = f"{path}:{n}"
            if flags & 0x10 or (not name and not any(data) and not flags):  # FLG_ADDREG_KEYONLY, or nothing to set
                out.append(Entry(root, key, name, "key", None, src))
            elif flags & 0xffff0001 == 0x10001:                          # FLG_ADDREG_TYPE_DWORD
                out.append(Entry(root, key, name, "dword", int(data[0], 0), src))
            elif flags & 1:                                              # FLG_ADDREG_BINVALUETYPE
                out.append(Entry(root, key, name, "binary", bytes(int(b, 16) for b in data if b), src))
            elif flags & 0x20000:                                        # FLG_ADDREG_TYPE_EXPAND_SZ
                out.append(Entry(root, key, name, "expand_sz", subst(data[0]), src))
            else:                                                        # REG_SZ (NOCLOBBER 0x2 is how we write all)
                out.append(Entry(root, key, name, "sz", subst(data[0]) if data else "", src))
    return out


def mshtml_strings():
    """%CLSID_x% of mshtml.inf: mshtml register_server's table (main.c INF_SET_CLSID), from mshtml_classes.idl."""
    idl = show("dlls/mshtml/mshtml_classes.idl").decode()
    s = {f"CLSID_{m.group(2)}": "{" + re.search(r"uuid\(([^)]*)\)", m.group(1)).group(1).upper() + "}"
         for m in re.finditer(r"\[([^\]]*)\]\s*coclass\s+(\w+)", idl)}
    s["CLSID_IImageDecodeFilter"] = "{607FD4E8-0A03-11D1-AB1D-00C04FC9B304}"     # dlls/mshtml/main.c:672
    s["LIBID_MSHTML"] = "{3050F1C5-98B5-11CF-BB82-00AA00BDCE0B}"
    s["16422"] = "C:\\Program Files"                                            # DIRID_PROGRAM_FILES
    return s


# ---------------------------------------------------------------- C output
def c_str(s):
    return 'L"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    entries = []
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        needed = {"dlls/stdole2.tlb/stdole2.idl"} | {p for p, m, *_ in SCRIPTS if m != "rgs"}
        for p in sorted(needed):                            # each IDL with the module-local files next to it
            d = Path(p).parent
            names = subprocess.run(["git", "-C", str(WINE), "ls-tree", "--name-only", "HEAD", f"{d}/"],
                                   capture_output=True, text=True, check=True).stdout.split()
            for f in names:
                if f.endswith((".idl", ".h")):
                    (tmp / f).parent.mkdir(parents=True, exist_ok=True)
                    (tmp / f).write_bytes(show(f))
        subprocess.run([str(WINE / "tools/widl/widl"), "-o", str(tmp / "stdole2.tlb"), "-m64", "--nostdinc",
                        "-I", str(WINE / "include"), "-I", str(WINE / "include/msvcrt"), "-D_UCRT", "-D__WINESRC__",
                        "-t", str(tmp / "dlls/stdole2.tlb/stdole2.idl")], check=True)
        for path, mode, module, *skip in SCRIPTS:
            text = show(path).decode() if mode == "rgs" else widl_script(path, mode, tmp)
            src = path if mode == "rgs" else f"widl {mode} {path}"
            entries += rgs_entries(text, module, src, *skip)
    strings = mshtml_strings()
    for path, section in INFS:
        entries += inf_entries(path, section, dict(strings))
    entries.append(Entry("HKEY_LOCAL_MACHINE", "Software\\Wine\\MSHTML\\2.47.4", "GeckoPath", "sz",
                         SYS64 + "gecko", "Shizuku: dlls/mshtml/nsembed.c find_wine_gecko_reg (GECKO_VERSION 2.47.4)"))

    # one entry per (root, key, name): later sources win, as a later RegInstall/registration would overwrite
    final, order = {}, []
    for e in entries:
        k = (e.root, e.key.lower(), (e.name or "").lower() if e.kind != "key" else None)
        if k not in final:
            order.append(k)
        final[k] = e
    keys_with_values = {(e.root, e.key.lower()) for e in final.values() if e.kind != "key"}
    rows, size, last_src = [], 0, None
    for k in order:
        e = final[k]
        if e.kind == "key" and (e.root, e.key.lower()) in keys_with_values:
            continue                                        # the key is created by its values anyway
        if e.source != last_src:
            rows.append(f"    /* {e.source} */")
            last_src = e.source
        name = c_str(e.name) if e.name is not None else "NULL"
        if e.kind in ("sz", "expand_sz"):
            t = "REG_SZ" if e.kind == "sz" else "REG_EXPAND_SZ"
            rows.append(f"    {{ {e.root}, {c_str(e.key)}, {name}, {t}, {c_str(e.data)}, 0, NULL }},")
            size += 2 * (len(e.data) + 1)
        elif e.kind == "dword":
            rows.append(f"    {{ {e.root}, {c_str(e.key)}, {name}, REG_DWORD, NULL, {e.data:#x}, NULL }},")
            size += 4
        elif e.kind == "binary":
            hexs = "".join(f"\\x{b:02x}" for b in e.data)
            rows.append(f'    {{ {e.root}, {c_str(e.key)}, {name}, REG_BINARY, NULL, {len(e.data)}, "{hexs}" }},')
            size += len(e.data)
        else:
            rows.append(f"    {{ {e.root}, {c_str(e.key)}, NULL, REG_NONE, NULL, 0, NULL }},")
        size += 2 * (len(e.key) + len(e.name or ""))
    count = sum(1 for r in rows if r.startswith("    {"))
    stamp = int(hashlib.sha256("\n".join(rows).encode()).hexdigest()[:8], 16)
    head = f"""/* SPDX-License-Identifier: LGPL-2.1-or-later
 * GENERATED by shizukudos/win64/trident/comrt/gen_register.py from the pinned Wine tree - do not edit.
 *
 * The registry keys the Wine browser modules' DllRegisterServer would write (see gen_register.py for the sources),
 * seeded by register.c. The data is Wine's (LGPL-2.1-or-later): registration scripts generated by widl from Wine's
 * IDL files, Wine's .rgs scripts and the AddReg sections of Wine's mshtml.inf and urlmon.inf.
 * Each group is preceded by its source: "widl -r|-t <idl>" (a widl registration script), "<file>.rgs" or
 * "<file>.inf:<line>". REG_NONE rows create a key that has no value of its own.
 * {count} rows, about {size // 1024} KiB of key names and data.
 */
#define TRT_REG_STAMP {stamp:#010x}u   /* first 32 bits of the SHA-256 of the rows below */
static const struct trt_reg_row trt_reg_rows[] =
{{"""
    text = head + "\n" + "\n".join(rows) + "\n};\n"
    (HERE / "register_table.h").write_text(text)
    print(f"register_table.h: {count} rows, ~{size // 1024} KiB")


if __name__ == "__main__":
    main()
