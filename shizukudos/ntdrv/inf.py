#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Windows driver INF parser and PnP matcher (host side).

Implements the documented INF file syntax as Windows 10 SetupAPI reads it for a PnP driver package:

  * sections, `key = value, value, ...` entries, `;` comments, `\\` line continuation, quoted strings with `""` escapes;
  * `%token%` substitution from [Strings] / [Strings.<lang>] (undefined tokens and numeric dirids stay literal);
  * [Version] (Signature, Class, ClassGuid, Provider, DriverVer, CatalogFile.*);
  * [Manufacturer] with TargetOSVersion decorations (NTamd64, NTamd64.10.0, NTamd64.10.0...16299, NT.6.1, ...):
    the applicable decoration with the highest version wins (Microsoft "INF Manufacturer Section"); for non-x86
    targets the decoration must name the architecture and undecorated models sections are not used;
  * models sections: description = DDInstall-section, hardware-id [, compatible-id ...];
  * DDInstall decoration search (X.NTamd64 > X.NT > X) and the .Services / .HW / .CoInstallers / .Wdf extensions;
  * CopyFiles (@file and file-list sections), DestinationDirs / dirids, SourceDisksFiles;
  * AddReg entries with the documented FLG_ADDREG_* encoding (high word = registry type when BINVALUETYPE is set);
  * AddService / service-install sections (ServiceType, StartType, ErrorControl, ServiceBinary, LoadOrderGroup, ...);
  * KmdfService / KmdfLibraryVersion (WDF version the driver needs);
  * PCI hardware/compatible ID generation (Microsoft "Identifiers for PCI devices") and driver ranking
    (Microsoft "How Windows Ranks Drivers": rank 0xSSGGTHHH = signature score, FeatureScore, identifier score;
    identifier score per "Identifier Score (Windows Vista and later)"; equal ranks broken by DriverVer date, then
    version).

It is a static tool: nothing here installs anything. The runtime counterpart is the Win64 CLI shzpnp
(shizukudos/win64/apps/shzpnp/), which implements the same rules in C; tests/test_inf.py checks this module against
the documented rules and shizukudos/ntdrv/tests/test_shzpnp.py checks shzpnp against this module.
"""
import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------------------------------------- target OS

@dataclass(frozen=True)
class Target:
    arch: str = "amd64"          # amd64 | x86 | arm64 | arm | ia64
    major: int = 10
    minor: int = 0
    build: int = 22631           # the version Kernel64 reports (registry CurrentBuild, PEB): 10.0.22631
    product_type: int = 1        # 1 workstation, 2 domain controller, 3 server
    suite: int = 0
    # Windows x64 ignores arch-less and undecorated Models sections. ReactOS's setupapi accepts them, and ReactOS's own
    # INFs rely on that; legacy=True reproduces that leniency (never the default: it is not Windows behaviour).
    legacy: bool = False

    @property
    def nt_decoration(self):
        return "NT" + self.arch


TARGET_WIN10_AMD64 = Target()                                 # the ShizukuDOS 10 profile

_ARCHES = ("amd64", "x86", "arm64", "arm", "ia64")


def parse_target_os(dec):
    """'NTamd64.10.0...16299' -> dict(arch, major, minor, product_type, suite, build) or None if not an NT decoration.
    Fields left empty in the decoration are None. Case-insensitive."""
    m = re.fullmatch(r"nt([a-z0-9]*)((?:\.[0-9a-fx]*)*)", dec.strip(), re.I)
    if not m:
        return None
    arch = m.group(1).lower()
    if arch and arch not in _ARCHES:
        return None
    fields = m.group(2).split(".")[1:] if m.group(2) else []
    if len(fields) > 5:
        return None

    def num(i):
        if i < len(fields) and fields[i] != "":
            try:
                return int(fields[i], 0)
            except ValueError:
                return -1
        return None
    return {"arch": arch or None, "major": num(0), "minor": num(1), "product_type": num(2), "suite": num(3), "build": num(4)}


def decoration_applies(dec, target):
    """Does a TargetOSVersion decoration select this target? Returns a specificity key (higher = more specific) or None."""
    d = parse_target_os(dec)
    if d is None or -1 in d.values():
        return None
    if d["arch"] and d["arch"] != target.arch:
        return None
    if not d["arch"] and target.arch != "x86" and not target.legacy:
        return None                                          # "Architecture must be specified ... for non-x86" (since 2003 SP1)
    if d["major"] is not None and d["minor"] is None:
        d["minor"] = 0                                       # NTamd64.10 means 10.0
    if d["major"] is not None:
        if (d["major"], d["minor"]) > (target.major, target.minor):
            return None
    if d["product_type"] is not None and d["product_type"] != target.product_type:
        return None
    if d["suite"] is not None and (d["suite"] & target.suite) != d["suite"]:
        return None
    if d["build"] is not None:
        if d["major"] is None:
            return None                                      # a build number needs the major.minor it belongs to
        if (d["major"], d["minor"]) == (target.major, target.minor) and d["build"] > target.build:
            return None
    # "the section with the highest version numbers that are not higher than the OS version" (INF Manufacturer Section):
    # version fields decide first; a decoration that names the architecture only breaks ties.
    return (d["major"] or 0, d["minor"] or 0, d["build"] or 0,
            1 if d["product_type"] is not None else 0, 1 if d["suite"] is not None else 0, 1 if d["arch"] else 0)


# ------------------------------------------------------------------------------------------------------------- lexing

def _split_outside_quotes(text, sep):
    """Split on `sep` characters that are not inside "..." (with "" as an escaped quote). Returns raw pieces."""
    out, cur, inq, i = [], [], False, 0
    while i < len(text):
        c = text[i]
        if c == '"':
            if inq and i + 1 < len(text) and text[i + 1] == '"':
                cur.append('""')
                i += 2
                continue
            inq = not inq
            cur.append(c)
        elif c == sep and not inq:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


def _strip_comment(line):
    """Remove a `;` comment that is not inside quotes; returns (text, ends_with_continuation)."""
    inq, i = False, 0
    while i < len(line):
        c = line[i]
        if c == '"':
            inq = not inq
        elif c == ";" and not inq:
            line = line[:i]
            break
        i += 1
    line = line.rstrip()
    if line.endswith("\\") and not inq:
        return line[:-1].rstrip(), True
    return line, False


def _unquote(tok):
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        return tok[1:-1].replace('""', '"')
    if tok.startswith('"'):                                   # unterminated quote: SetupAPI takes the rest literally
        return tok[1:].replace('""', '"')
    return tok


@dataclass
class Line:
    key: str                     # "" for value-only lines
    values: list                 # substituted, unquoted values
    raw: str
    lineno: int

    @property
    def field0(self):
        return self.values[0] if self.values else ""


@dataclass
class Section:
    name: str
    lines: list = field(default_factory=list)

    def get(self, key):
        """All values of every line with this key (case-insensitive), concatenated in file order."""
        out = []
        for ln in self.lines:
            if ln.key.lower() == key.lower():
                out += ln.values
        return out

    def first(self, key, default=None):
        for ln in self.lines:
            if ln.key.lower() == key.lower():
                return ln.values[0] if ln.values else ""
        return default

    def keys(self):
        return [ln.key for ln in self.lines]


# ----------------------------------------------------------------------------------------------------------- the INF

class InfError(Exception):
    pass


class Inf:
    ADDREG_ROOTS = {"HKR", "HKLM", "HKCR", "HKU", "HKCU"}

    def __init__(self, text, path=None, locale="0409"):
        self.path = Path(path) if path else None
        self.name = self.path.name if self.path else "<inline>"
        self.locale = locale
        self.sections = {}                                   # lower name -> Section
        self.order = []
        self.strings = {}                                    # lower token -> value
        self.warnings = []
        self._parse(text)

    # ---- parsing
    @classmethod
    def load(cls, path, locale="0409"):
        raw = Path(path).read_bytes()
        if raw.startswith(b"\xff\xfe"):
            text = raw.decode("utf-16-le", errors="replace")
        elif raw.startswith(b"\xfe\xff"):
            text = raw.decode("utf-16-be", errors="replace")
        elif raw.startswith(b"\xef\xbb\xbf"):
            text = raw[3:].decode("utf-8", errors="replace")
        else:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("cp1252", errors="replace")
        return cls(text, path=path, locale=locale)

    def _parse(self, text):
        cur = None
        pending, pending_start = [], 0
        rawlines = []                                        # (section, key_raw, value_raw, lineno)
        for n, phys in enumerate(text.splitlines(), 1):
            body, cont = _strip_comment(phys.strip("\ufeff").rstrip("\r\n"))
            if not pending:
                pending_start = n
            pending.append(body)
            if cont:
                continue
            line = " ".join(p.strip() for p in pending).strip()
            pending = []
            if not line:
                continue
            if line.startswith("["):
                end = line.find("]")
                if end < 0:
                    self.warnings.append(f"{self.name}:{pending_start}: unterminated section header")
                    continue
                name = line[1:end].strip()
                cur = self.sections.get(name.lower())
                if cur is None:
                    cur = Section(name)
                    self.sections[name.lower()] = cur
                    self.order.append(name)
                continue
            if cur is None:
                self.warnings.append(f"{self.name}:{pending_start}: entry before the first section ignored")
                continue
            rawlines.append((cur, line, pending_start))
        # pass 1: [Strings] (+ locale-specific overrides), no substitution inside
        for cur, line, n in rawlines:
            low = cur.name.lower()
            if low == "strings" or low.startswith("strings."):
                k, v = self._split_kv(line)
                if k is None:
                    continue
                vals = [_unquote(x) for x in _split_outside_quotes(v, ",")]
                val = vals[0] if vals else ""
                if low == "strings":
                    self.strings.setdefault(k.lower(), val)
                elif low == "strings." + self.locale.lower():
                    self.strings[k.lower()] = val                # the locale-specific table overrides the generic one
        # pass 2: everything, with substitution
        for cur, line, n in rawlines:
            k, v = self._split_kv(line)
            low = cur.name.lower()
            in_strings = low == "strings" or low.startswith("strings.")
            if k is None:
                vals = [self._sub(_unquote(x)) if not in_strings else _unquote(x) for x in _split_outside_quotes(line, ",")]
                cur.lines.append(Line("", vals, line, n))
            else:
                vals = [self._sub(_unquote(x)) if not in_strings else _unquote(x) for x in _split_outside_quotes(v, ",")]
                key = self._sub(_unquote(k)) if not in_strings else _unquote(k)
                cur.lines.append(Line(key, vals, line, n))

    @staticmethod
    def _split_kv(line):
        parts = _split_outside_quotes(line, "=")
        if len(parts) == 1:
            return None, line
        return parts[0].strip(), "=".join(parts[1:]).strip()

    _TOKEN = re.compile(r"%([^%]*)%")

    def _sub(self, s):
        if "%" not in s:
            return s
        out, i = [], 0
        while i < len(s):
            if s[i] != "%":
                out.append(s[i])
                i += 1
                continue
            if s.startswith("%%", i):
                out.append("%")
                i += 2
                continue
            j = s.find("%", i + 1)
            if j < 0:
                out.append(s[i:])
                break
            tok = s[i + 1:j]
            val = self.strings.get(tok.lower())
            if val is None:
                out.append(s[i:j + 1])                        # dirid (%12%) or undefined token: left literal
            else:
                out.append(val)
            i = j + 1
        return "".join(out)

    # ---- section access
    def section(self, name):
        return self.sections.get(name.lower()) if name else None

    def has(self, name):
        return name.lower() in self.sections

    def find_decorated(self, base, target, ext=""):
        """DDInstall-style lookup: base.NT<arch><ext> > base.NT<ext> > base<ext>. Returns (name, Section) or (None, None)."""
        for dec in (f".{target.nt_decoration}", ".NT", ""):
            nm = f"{base}{dec}{ext}"
            if self.has(nm):
                return nm, self.section(nm)
        return None, None

    # ---- [Version]
    @property
    def version(self):
        v = self.section("Version")
        out = {"Signature": "", "Class": "", "ClassGuid": "", "Provider": "", "DriverVer": "", "CatalogFile": ""}
        if not v:
            return out
        for k in list(out):
            val = v.first(k)
            if val is not None:
                out[k] = val
        out["DriverVer"] = ", ".join(v.get("DriverVer")) if v.get("DriverVer") else ""
        for ln in v.lines:                                   # CatalogFile.NTamd64 etc.
            if ln.key.lower().startswith("catalogfile.") and ln.key.lower().endswith(target_arch_suffix()):
                out["CatalogFile"] = ln.field0
        return out

    # ---- [Manufacturer] + models
    def models(self, target=TARGET_WIN10_AMD64):
        """Every model line applicable to the target: list of dicts with description, install, hwids, compat_ids, mfg, section."""
        mfg = self.section("Manufacturer")
        out = []
        if not mfg:
            return out
        for ln in mfg.lines:
            if not ln.values:
                continue
            base = ln.values[0].strip()
            decorations = [d.strip() for d in ln.values[1:] if d.strip()]
            chosen = None
            if not decorations:
                if target.arch == "x86" or target.legacy:
                    chosen = base                            # undecorated models section: x86 only (or legacy mode)
                else:
                    self.warnings.append(f"{self.name}: manufacturer '{ln.key}' has no TargetOSVersion decoration: "
                                         f"not used on {target.arch}")
            else:
                best = None
                for d in decorations:
                    spec = decoration_applies(d, target)
                    if spec is None:
                        continue
                    if best is None or spec > best[0]:
                        best = (spec, d)
                if best:
                    chosen = f"{base}.{best[1]}"
            if chosen is None:
                continue
            sec = self.section(chosen)
            if sec is None:
                self.warnings.append(f"{self.name}: models section [{chosen}] referenced by [Manufacturer] is missing")
                continue
            for m in sec.lines:
                if not m.values:
                    continue
                install = m.values[0].strip()
                ids = [x.strip() for x in m.values[1:] if x.strip()]
                if not ids:
                    continue
                out.append({"description": m.key, "install": install, "hwids": [ids[0]], "compat_ids": ids[1:],
                            "mfg": ln.key, "section": sec.name, "lineno": m.lineno})
        return out

    # ---- DDInstall
    def install(self, base, target=TARGET_WIN10_AMD64):
        """Resolve a DDInstall section and its extensions. Returns a dict describing what an installation would do."""
        name, sec = self.find_decorated(base, target)
        res = {"install": base, "section": name, "copyfiles": [], "addreg": [], "delreg": [], "services": [],
               "hw_addreg": [], "coinstallers": [], "include": [], "needs": [], "feature_score": None,
               "wdf": None, "driverver": None, "warnings": []}
        if sec is None:
            res["warnings"].append(f"DDInstall section [{base}] not found (tried .{target.nt_decoration}, .NT, undecorated)")
            return res
        dec = name[len(base):]                               # "", ".NT" or ".NTamd64"
        res["include"] = sec.get("Include")
        res["needs"] = sec.get("Needs")
        fs = sec.first("FeatureScore")
        if fs is not None:
            try:
                res["feature_score"] = int(fs, 0)
            except ValueError:
                res["warnings"].append(f"bad FeatureScore {fs!r}")
        if sec.get("DriverVer"):
            res["driverver"] = ", ".join(sec.get("DriverVer"))
        res["copyfiles"] = self._copyfiles(sec, res["warnings"])
        for regsec in sec.get("AddReg"):
            res["addreg"] += self.addreg(regsec, res["warnings"])
        for regsec in sec.get("DelReg"):
            s = self.section(regsec)
            res["delreg"] += [ln.values for ln in s.lines] if s else []
        # Extensions follow the decoration of the DDInstall section actually used; fall back to less decorated names.
        for ext, handler in ((".Services", self._services), (".HW", self._hw), (".CoInstallers", self._coinst), (".Wdf", self._wdf)):
            ext_name, ext_sec = None, None
            for d in [dec] + [x for x in (f".{target.nt_decoration}", ".NT", "") if x != dec]:
                if self.has(base + d + ext):
                    ext_name, ext_sec = base + d + ext, self.section(base + d + ext)
                    break
            if ext_sec:
                handler(ext_sec, res)
        for n in res["needs"]:
            sub = self.install(n, target)
            for k in ("copyfiles", "addreg", "services", "hw_addreg"):
                res[k] += sub[k]
            res["warnings"] += [f"Needs={n}: {w}" for w in sub["warnings"]]
        return res

    def _copyfiles(self, sec, warnings):
        out = []
        for cf in sec.get("CopyFiles"):
            cf = cf.strip()
            if not cf:
                continue
            if cf.startswith("@"):
                out.append({"dest": cf[1:], "source": cf[1:], "dirid": self.dest_dir(None), "section": None, "flags": 0})
                continue
            s = self.section(cf)
            if not s:
                warnings.append(f"CopyFiles section [{cf}] not found")
                continue
            dirid = self.dest_dir(cf)
            for ln in s.lines:
                vals = ([ln.key] if ln.key else []) + ln.values
                if not vals or not vals[0]:
                    continue
                dest = vals[0]
                src = vals[1] if len(vals) > 1 and vals[1] else dest
                flags = 0
                if len(vals) > 3 and vals[3]:
                    try:
                        flags = int(vals[3], 0)
                    except ValueError:
                        pass
                out.append({"dest": dest, "source": src, "dirid": dirid, "section": s.name, "flags": flags})
        return out

    def dest_dir(self, file_list_section):
        """[DestinationDirs]: 'section = dirid[, subdir]' or DefaultDestDir. Returns (dirid:int, subdir:str)."""
        dd = self.section("DestinationDirs")
        ent = None
        if dd:
            if file_list_section:
                for ln in dd.lines:
                    if ln.key.lower() == file_list_section.lower():
                        ent = ln.values
                        break
            if ent is None:
                for ln in dd.lines:
                    if ln.key.lower() == "defaultdestdir":
                        ent = ln.values
                        break
        if not ent:
            return (12, "")                                  # SetupAPI default for driver files is... none; drivers ship with 12
        try:
            dirid = int(ent[0], 0)
        except ValueError:
            dirid = 12
        return (dirid, ent[1] if len(ent) > 1 else "")

    # AddReg flags (FLG_ADDREG_*, Microsoft "INF AddReg Directive")
    FLG_BINVALUETYPE, FLG_NOCLOBBER, FLG_DELVAL, FLG_APPEND, FLG_KEYONLY, FLG_OVERWRITEONLY = 1, 2, 4, 8, 0x10, 0x20
    REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 0, 1, 2, 3, 4, 7, 11

    @classmethod
    def addreg_type(cls, flags):
        hi = (flags >> 16) & 0xFFFF
        if flags & cls.FLG_BINVALUETYPE:
            return {0: cls.REG_BINARY, 1: cls.REG_DWORD, 2: cls.REG_NONE}.get(hi, hi)   # 0x000B0001 -> REG_QWORD (11)
        return {0: cls.REG_SZ, 1: cls.REG_MULTI_SZ, 2: cls.REG_EXPAND_SZ}.get(hi, cls.REG_SZ)

    def addreg(self, secname, warnings=None):
        """Decode an add-registry-section into entries {root, subkey, name, flags, type, data}."""
        warnings = warnings if warnings is not None else self.warnings
        s = self.section(secname)
        out = []
        if not s:
            warnings.append(f"AddReg section [{secname}] not found")
            return out
        for ln in s.lines:
            vals = ([ln.key] if ln.key else []) + ln.values
            if not vals:
                continue
            root = vals[0].strip().upper()
            if root not in self.ADDREG_ROOTS:
                warnings.append(f"[{secname}]:{ln.lineno}: unknown registry root {vals[0]!r}")
                continue
            subkey = vals[1] if len(vals) > 1 else ""
            name = vals[2] if len(vals) > 2 else ""
            flags = 0
            if len(vals) > 3 and vals[3].strip():
                try:
                    flags = int(vals[3], 0)
                except ValueError:
                    warnings.append(f"[{secname}]:{ln.lineno}: bad flags {vals[3]!r}")
            data_tokens = vals[4:]
            rtype = self.addreg_type(flags)
            data = None
            if not (flags & self.FLG_KEYONLY):
                if rtype == self.REG_DWORD:
                    try:
                        data = int(data_tokens[0], 0) & 0xFFFFFFFF if data_tokens else 0
                    except ValueError:
                        warnings.append(f"[{secname}]:{ln.lineno}: bad DWORD {data_tokens[0]!r}")
                        data = 0
                elif rtype == self.REG_QWORD:
                    try:
                        data = int(data_tokens[0], 0) & 0xFFFFFFFFFFFFFFFF if data_tokens else 0
                    except ValueError:
                        data = 0
                elif rtype in (self.REG_BINARY, self.REG_NONE) or (flags & self.FLG_BINVALUETYPE):
                    b = bytearray()
                    for t in data_tokens:
                        t = t.strip()
                        if not t:
                            continue
                        try:
                            b.append(int(t, 16) & 0xFF)
                        except ValueError:
                            warnings.append(f"[{secname}]:{ln.lineno}: bad hex byte {t!r}")
                    data = bytes(b)
                elif rtype == self.REG_MULTI_SZ:
                    data = [t for t in data_tokens]
                else:                                        # REG_SZ / REG_EXPAND_SZ: a single string (later fields ignored)
                    data = data_tokens[0] if data_tokens else ""
            out.append({"root": root, "subkey": subkey, "name": name, "flags": flags, "type": rtype, "data": data,
                        "section": s.name, "lineno": ln.lineno})
        return out

    def _services(self, sec, res):
        for ln in sec.lines:
            if ln.key.lower() == "addservice":
                v = ln.values + [""] * 4
                svc = {"name": v[0].strip(), "flags": 0, "section": v[2].strip(), "eventlog": v[3].strip() or None}
                try:
                    svc["flags"] = int(v[1], 0) if v[1].strip() else 0
                except ValueError:
                    res["warnings"].append(f"AddService {svc['name']}: bad flags {v[1]!r}")
                svc.update(self.service_install(svc["section"], res["warnings"]))
                res["services"].append(svc)
            elif ln.key.lower() == "delservice":
                res["services"].append({"name": ln.field0, "delete": True})

    def service_install(self, secname, warnings=None):
        warnings = warnings if warnings is not None else self.warnings
        s = self.section(secname)
        out = {"ServiceType": None, "StartType": None, "ErrorControl": None, "ServiceBinary": None, "LoadOrderGroup": None,
               "DisplayName": None, "Description": None, "StartName": None, "Dependencies": [], "AddReg": [], "Security": None}
        if not s:
            warnings.append(f"service-install section [{secname}] not found")
            return out
        for k in ("ServiceType", "StartType", "ErrorControl"):
            v = s.first(k)
            if v is not None:
                try:
                    out[k] = int(v, 0)
                except ValueError:
                    warnings.append(f"[{secname}]: bad {k} {v!r}")
        for k in ("ServiceBinary", "LoadOrderGroup", "DisplayName", "Description", "StartName", "Security"):
            out[k] = s.first(k)
        out["Dependencies"] = s.get("Dependencies")
        for regsec in s.get("AddReg"):
            out["AddReg"] += self.addreg(regsec, warnings)
        return out

    def _hw(self, sec, res):
        for regsec in sec.get("AddReg"):
            res["hw_addreg"] += self.addreg(regsec, res["warnings"])

    def _coinst(self, sec, res):
        for regsec in sec.get("AddReg"):
            res["coinstallers"] += self.addreg(regsec, res["warnings"])

    def _wdf(self, sec, res):
        for ln in sec.lines:
            if ln.key.lower() == "kmdfservice" and len(ln.values) >= 2:
                w = self.section(ln.values[1])
                res["wdf"] = {"service": ln.values[0], "section": ln.values[1],
                              "KmdfLibraryVersion": w.first("KmdfLibraryVersion") if w else None, "kind": "KMDF"}
            elif ln.key.lower() == "umdfservice" and len(ln.values) >= 2:
                w = self.section(ln.values[1])
                res["wdf"] = {"service": ln.values[0], "section": ln.values[1],
                              "UmdfLibraryVersion": w.first("UmdfLibraryVersion") if w else None, "kind": "UMDF"}

    # ---- source files
    def source_files(self, target=TARGET_WIN10_AMD64):
        """[SourceDisksFiles(.arch)]: filename -> (diskid, subdir). The arch-decorated section overrides the plain one."""
        out = {}
        for nm in ("SourceDisksFiles", f"SourceDisksFiles.{target.arch}"):
            s = self.section(nm)
            if not s:
                continue
            for ln in s.lines:
                if ln.key:
                    out[ln.key.lower()] = (ln.field0, ln.values[1] if len(ln.values) > 1 else "")
        return out

    # ---- summary used by the store index
    def summary(self, target=TARGET_WIN10_AMD64):
        ver = self.version
        entries = []
        for m in self.models(target):
            inst = self.install(m["install"], target)
            entries.append({**m, "services": [{k: s.get(k) for k in ("name", "flags", "ServiceBinary", "StartType", "ServiceType",
                                                                       "ErrorControl", "LoadOrderGroup", "delete")} for s in inst["services"]],
                            "copyfiles": inst["copyfiles"], "feature_score": inst["feature_score"], "wdf": inst["wdf"],
                            "include": inst["include"], "needs": inst["needs"], "warnings": inst["warnings"]})
        return {"inf": self.name, "version": ver, "models": entries, "warnings": list(self.warnings)}


def target_arch_suffix(target=TARGET_WIN10_AMD64):
    return "nt" + target.arch


# ------------------------------------------------------------------------------------------------------ PCI identifiers

@dataclass
class Device:
    """A PnP device as the bus driver reports it: an ordered hardware-ID list and an ordered compatible-ID list."""
    instance: str
    hwids: list
    compat_ids: list
    description: str = ""

    @classmethod
    def pci(cls, vendor, device, subsys=None, rev=None, class_code=None, instance=None, dt=None):
        """Microsoft "Identifiers for PCI devices": the exact ID strings and their order. subsys is PCI config dword
        0x2C (subsystem id << 16 | subsystem vendor), printed as SUBSYS_s(4)n(4); class_code is 24-bit ccsspp;
        dt is the PCI Express device/port type (compatible IDs PCI\CC_..&DT_.., PCI Express only)."""
        v, d = f"{vendor:04X}", f"{device:04X}"
        hw, cp = [], []
        if subsys is not None:
            if rev is not None:
                hw.append(f"PCI\\VEN_{v}&DEV_{d}&SUBSYS_{subsys:08X}&REV_{rev:02X}")
            hw.append(f"PCI\\VEN_{v}&DEV_{d}&SUBSYS_{subsys:08X}")
        if rev is not None:
            hw.append(f"PCI\\VEN_{v}&DEV_{d}&REV_{rev:02X}")
        hw.append(f"PCI\\VEN_{v}&DEV_{d}")
        if class_code is not None:
            cc = f"{class_code:06X}"
            hw.append(f"PCI\\VEN_{v}&DEV_{d}&CC_{cc}")
            hw.append(f"PCI\\VEN_{v}&DEV_{d}&CC_{cc[:4]}")
        if rev is not None:
            cp.append(f"PCI\\VEN_{v}&DEV_{d}&REV_{rev:02X}")
        cp.append(f"PCI\\VEN_{v}&DEV_{d}")
        if class_code is not None:
            cc = f"{class_code:06X}"
            cp += [f"PCI\\VEN_{v}&CC_{cc}", f"PCI\\VEN_{v}&CC_{cc[:4]}", f"PCI\\VEN_{v}"]
            if dt is not None:
                cp.append(f"PCI\\CC_{cc}&DT_{dt:04X}")
            cp.append(f"PCI\\CC_{cc}")
            if dt is not None:
                cp.append(f"PCI\\CC_{cc[:4]}&DT_{dt:04X}")
            cp.append(f"PCI\\CC_{cc[:4]}")
        else:
            cp.append(f"PCI\\VEN_{v}")
        inst = instance or f"PCI\\VEN_{v}&DEV_{d}"
        return cls(inst, hw, cp)

    @classmethod
    def parse(cls, spec):
        """Accepts: 'VVVV:DDDD[:SSSSSSSS[:RR[:CCSSPP]]]' (hex fields, '-' for absent), a full 'PCI\\VEN_..' hardware ID
        (used as the only hardware ID), or a Kernel64 log line 'K64 pci: b:d.f vvvv:dddd class ccsspp irq n'."""
        spec = spec.strip()
        m = re.match(r"K64 pci:\s*(\w+):(\w+)\.(\w+)\s+([0-9a-fA-F]+):([0-9a-fA-F]+)\s+class\s+([0-9a-fA-F]+)", spec)
        if m:
            cc = int(m.group(6), 16)
            return cls.pci(int(m.group(4), 16), int(m.group(5), 16), class_code=cc,
                           instance=f"PCI\\{m.group(1)}:{m.group(2)}.{m.group(3)}")
        if "\\" in spec:
            return cls(spec, [spec], [])
        f = spec.split(":")
        if len(f) < 2:
            raise ValueError(f"cannot parse device spec {spec!r}")

        def hx(i):
            return int(f[i], 16) if i < len(f) and f[i] not in ("", "-") else None
        return cls.pci(int(f[0], 16), int(f[1], 16), subsys=hx(2), rev=hx(3), class_code=hx(4))


# ------------------------------------------------------------------------------------------------------------ ranking

# "How Windows Ranks Drivers (Windows Vista and later)": rank = 0xSSGGTHHH, lower is better.
#   SS  signature score. Windows ranks trusted-signed packages best, then unsigned packages whose DDInstall section has
#       an .NT platform extension, then unsigned undecorated ones, then unknown signing state; it does not publish the
#       byte values. ShizukuDOS verifies no signatures, so every package is "unsigned"; the two unsigned classes are
#       kept, with our own byte values (only their order is Windows').
#   GG  FeatureScore directive of the DDInstall section (0x00-0xFF), 0xFF when absent.
#   THHH identifier score ("Identifier Score (Windows Vista and later)"), positions zero-based:
#       device hardware ID   = INF hardware ID    0x0000 + position of the device hardware ID
#       device hardware ID   = INF compatible ID  0x1000 + position of the device hardware ID
#       device compatible ID = INF hardware ID    0x2000 + position of the device compatible ID
#       device compatible ID = INF compatible ID  0x3000 + j + k*0x100 (j: device compatible ID position,
#                                                  k: position of the compatible ID in the INF Models entry)
RANK_HW_HW, RANK_HW_CP, RANK_CP_HW, RANK_CP_CP = 0x0000, 0x1000, 0x2000, 0x3000
SIGNATURE_TRUSTED = 0x00                                      # never produced: no signature verification here
SIGNATURE_UNSIGNED_NT = 0x80                                  # unsigned, DDInstall with .NT/.NT<arch> extension
SIGNATURE_UNSIGNED = 0xC0                                     # unsigned, undecorated DDInstall
FEATURE_SCORE_DEFAULT = 0xFF
MATCH_KINDS = {RANK_HW_HW: "hardware-id/hardware-id", RANK_HW_CP: "device-hardware-id/inf-compatible-id",
               RANK_CP_HW: "device-compatible-id/inf-hardware-id", RANK_CP_CP: "compatible-id/compatible-id"}


def identifier_score(device, model):
    """Best (lowest) identifier score of one Models entry for a device: (score, kind, inf_id, device_id) or None."""
    best = None

    def consider(score, kind, inf_id, dev_id):
        nonlocal best
        if best is None or score < best[0]:
            best = (score, kind, inf_id, dev_id)
    dev_hw = {d.lower(): i for i, d in reversed(list(enumerate(device.hwids)))}
    dev_cp = {d.lower(): j for j, d in reversed(list(enumerate(device.compat_ids)))}
    for inf_id in model["hwids"]:
        low = inf_id.lower()
        if low in dev_hw:
            consider(RANK_HW_HW + dev_hw[low], RANK_HW_HW, inf_id, device.hwids[dev_hw[low]])
        if low in dev_cp:
            consider(RANK_CP_HW + dev_cp[low], RANK_CP_HW, inf_id, device.compat_ids[dev_cp[low]])
    for k, inf_id in enumerate(model["compat_ids"]):
        low = inf_id.lower()
        if low in dev_hw:
            consider(RANK_HW_CP + dev_hw[low], RANK_HW_CP, inf_id, device.hwids[dev_hw[low]])
        if low in dev_cp:
            consider(RANK_CP_CP + dev_cp[low] + k * 0x100, RANK_CP_CP, inf_id, device.compat_ids[dev_cp[low]])
    return best


def match_device(device, inf, target=TARGET_WIN10_AMD64):
    """Every model line of `inf` that matches `device`, each with its rank (lower is better) and why."""
    hits = []
    for m in inf.models(target):
        best = identifier_score(device, m)
        if not best:
            continue
        inst = inf.install(m["install"], target)
        fs = inst["feature_score"] if inst["feature_score"] is not None else FEATURE_SCORE_DEFAULT
        decorated = bool(inst["section"]) and inst["section"].lower() != m["install"].lower()
        sig = SIGNATURE_UNSIGNED_NT if decorated else SIGNATURE_UNSIGNED
        rank = (sig << 24) | ((fs & 0xFF) << 16) | best[0]
        hits.append({"rank": rank, "signature_score": sig, "identifier_score": best[0], "feature_score": fs,
                     "inf_id": best[2], "device_id": best[3], "match": MATCH_KINDS[best[1]], "model": m, "install": inst,
                     "inf": inf.name, "driverver": inst["driverver"] or inf.version["DriverVer"]})
    hits.sort(key=lambda h: (h["rank"], h["model"]["lineno"]))
    return hits


def driverver_key(dv):
    """'mm/dd/yyyy, a.b.c.d' -> sortable tuple (date, version); missing parts sort lowest."""
    m = re.match(r"\s*(\d{1,2})/(\d{1,2})/(\d{4})\s*(?:,\s*([\d.]+))?", dv or "")
    if not m:
        return ((0, 0, 0), (0,))
    ver = tuple(int(x) for x in (m.group(4) or "0").split(".") if x.isdigit())
    return ((int(m.group(3)), int(m.group(1)), int(m.group(2))), ver)


def rank_candidates(device, infs, target=TARGET_WIN10_AMD64):
    """All matches over several INFs, best first. Ties in rank are broken by DriverVer (newest first), as Windows does."""
    hits = []
    for inf in infs:
        hits += match_device(device, inf, target)
    hits.sort(key=lambda h: (h["rank"], tuple(-x for d in driverver_key(h["driverver"]) for x in d)))
    return hits


# ------------------------------------------------------------------------------------------------------- directory ids

DIRIDS = {                                                   # SetupAPI dirid -> ShizukuDOS path (docs/shizukudos10/DRIVER_INSTALL.md)
    10: "C:\\SHZ", 11: "C:\\SHZ\\SYS64", 12: "C:\\SHZ\\SYS64\\DRIVERS", 13: "C:\\DRIVERS", 24: "C:\\", 1: "<package>",
    17: "C:\\SHZ\\INF", 18: "C:\\SHZ\\HELP", 20: "C:\\SHZ\\FONTS", 21: "C:\\SHZ\\SYS64\\VIEWERS", 23: "C:\\SHZ\\SYS64\\SPOOL\\DRIVERS",
    25: "C:\\SHZ\\SYSTEM", 30: "C:\\", 50: "C:\\SHZ\\SYSTEM", 51: "C:\\SHZ\\SYS64\\SPOOL", 52: "C:\\SHZ\\SYS64\\SPOOL\\DRIVERS",
    53: "C:\\USERS\\DEFAULT", 54: "C:\\", 55: "C:\\SHZ\\SYS64\\SPOOL\\PRTPROCS",
    -1: "<absolute>",
}


def resolve_dirid(spec, package_dir="C:\\DRIVERS\\<package>"):
    """'%12%\\foo.sys' or a (dirid, subdir) tuple -> ShizukuDOS path."""
    if isinstance(spec, tuple):
        dirid, sub = spec
        base = DIRIDS.get(dirid, f"<dirid {dirid}>")
        if dirid in (1, 13):
            base = package_dir
        return base + ("\\" + sub.strip("\\") if sub else "")
    m = re.match(r"%(-?\d+)%(.*)", spec)
    if not m:
        return spec
    return resolve_dirid((int(m.group(1)), ""), package_dir) + m.group(2)


# -------------------------------------------------------------------------------------------------------------- CLI

def _target_from_args(args):
    return Target(arch=args.arch, major=args.os_major, minor=args.os_minor, build=args.os_build, legacy=args.legacy)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arch", default="amd64", choices=_ARCHES)
    ap.add_argument("--os-major", type=int, default=10)
    ap.add_argument("--os-minor", type=int, default=0)
    ap.add_argument("--os-build", type=int, default=Target.build)
    ap.add_argument("--legacy", action="store_true", help="accept arch-less / undecorated Models sections (ReactOS setupapi behaviour)")
    ap.add_argument("--locale", default="0409")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("dump", help="parse an INF and print its version, models, install actions and services as JSON")
    p.add_argument("inf", type=Path)
    p = sub.add_parser("ids", help="print the hardware and compatible IDs of every model applicable to the target")
    p.add_argument("inf", type=Path, nargs="+")
    p = sub.add_parser("match", help="rank the models of the given INFs against devices ('8086:1533:00008086:03:020000', 'PCI\\VEN_...' or K64 log lines)")
    p.add_argument("--inf", type=Path, action="append", required=True)
    p.add_argument("devices", nargs="+")
    p = sub.add_parser("pci-ids", help="print the hardware/compatible ID lists Windows generates for a PCI function")
    p.add_argument("devices", nargs="+")
    args = ap.parse_args(argv)
    target = _target_from_args(args)

    if args.cmd == "dump":
        inf = Inf.load(args.inf, locale=args.locale)
        print(json.dumps(inf.summary(target), indent=1, default=_json_default))
    elif args.cmd == "ids":
        for path in args.inf:
            inf = Inf.load(path, locale=args.locale)
            for m in inf.models(target):
                print(f"{inf.name}\t{m['install']}\t{m['description']}\tHW={m['hwids'][0]}\tCOMPAT={','.join(m['compat_ids'])}")
    elif args.cmd == "match":
        infs = [Inf.load(p, locale=args.locale) for p in args.inf]
        for spec in args.devices:
            dev = Device.parse(spec)
            print(f"device {dev.instance}")
            hits = rank_candidates(dev, infs, target)
            if not hits:
                print("  no driver")
            for h in hits:
                svc = h["install"]["services"][0]["name"] if h["install"]["services"] else "-"
                binp = h["install"]["services"][0].get("ServiceBinary") if h["install"]["services"] else "-"
                print(f"  rank {h['rank']:#010x} id {h['identifier_score']:#06x} {h['match']:44} {h['inf']} [{h['model']['install']}] "
                      f"'{h['model']['description']}' service={svc} binary={binp} matched {h['inf_id']}")
    elif args.cmd == "pci-ids":
        for spec in args.devices:
            dev = Device.parse(spec)
            print(dev.instance)
            for i in dev.hwids:
                print(f"  HW  {i}")
            for i in dev.compat_ids:
                print(f"  CP  {i}")
    return 0


def _json_default(o):
    if isinstance(o, bytes):
        return o.hex()
    if isinstance(o, Path):
        return str(o)
    raise TypeError(type(o))


if __name__ == "__main__":
    sys.exit(main())
