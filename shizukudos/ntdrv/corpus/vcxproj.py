# SPDX-License-Identifier: GPL-2.0-only
"""Minimal MSBuild evaluation of WDK driver projects (.vcxproj), enough to attempt the virtio-win drivers with the
corpus toolchain (build.py): configuration "Win10 Release|x64", PropertyGroup / ItemDefinitionGroup / ClCompile items
with their Conditions, <Import> of the project's own .props files, and the WDK defaults a WindowsKernelModeDriver10.0
project gets (target Windows 10: NTDDI_VERSION 0x0A000000, KMDF version macros for KMDF projects).

What the WDK provides and ReactOS does not (wdm.lib, BufferOverflowFastFailK.lib, displib.lib, the WDK headers
themselves) is recorded as missing instead of being substituted; the ReactOS sdk/include headers stand in for the
WDK headers, which is exactly what the attempt measures.
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

NS = "{http://schemas.microsoft.com/developer/msbuild/2003}"
CONFIG, PLATFORM = "Win10 Release", "x64"
# WDK (WindowsKernelModeDriver10.0, TargetVersion=Windows10, x64) compiler defaults
WDK_DEFINES = ["-D_WIN64", "-D_AMD64_", "-DAMD64", "-DDEPRECATE_DDK_FUNCTIONS=1", "-DMSC_NOOPT", "-D_WIN32_WINNT=0x0A00",
               "-DWINVER=0x0A00", "-DWINNT=1", "-DNTDDI_VERSION=0x0A000000", "-DPOOL_NX_OPTIN=1"]
# WDK .lib -> ReactOS import library / static library name; None = WDK-only (no ReactOS counterpart)
LIBS = {"ntoskrnl.lib": ("import", "ntoskrnl"), "hal.lib": ("import", "hal"), "ndis.lib": ("import", "ndis"),
        "storport.lib": ("import", "storport"), "scsiport.lib": ("import", "scsiport"), "wmilib.lib": ("import", "wmilib"),
        "hidclass.lib": ("import", "hidclass"), "hidparse.lib": ("import", "hidparse"), "ksecdd.lib": (None, None),
        "wdm.lib": (None, None), "bufferoverflowfastfailk.lib": (None, None), "displib.lib": (None, None),
        "netio.lib": (None, None), "wpprecorder.lib": (None, None), "ntstrsafe.lib": (None, None)}


def _cond_true(cond, props):
    if not cond or not cond.strip():
        return True
    c = expand(cond, props)
    parts = re.split(r"\s+(?:OR|or)\s+", c)
    for p in parts:
        m = re.fullmatch(r"\s*'([^']*)'\s*(==|!=)\s*'([^']*)'\s*", p)
        if m:
            eq = m.group(1).strip().lower() == m.group(3).strip().lower()
            if eq == (m.group(2) == "=="):
                return True
        elif re.fullmatch(r"\s*(exists|Exists)\(.*\)\s*", p):
            continue
    return False


def expand(s, props):
    for _ in range(6):
        n = re.sub(r"\$\(([A-Za-z0-9_]+)\)", lambda m: props.get(m.group(1), ""), s)
        if n == s:
            break
        s = n
    return s


class Project:
    def __init__(self, path, intdir):
        self.path = Path(path)
        self.dir = self.path.parent
        self.props = {"Configuration": CONFIG, "Platform": PLATFORM, "MSBuildProjectDirectory": str(self.dir),
                      "ProjectDir": str(self.dir) + "/", "IntDir": str(intdir) + "/", "OutDir": str(intdir) + "/",
                      "KernelBufferOverflowLib": "BufferOverflowFastFailK.lib", "DDK_LIB_PATH": "", "DEP_LIB_PATH": "",
                      "_BUILD_MAJOR_VERSION_": "100", "_BUILD_MINOR_VERSION_": "0", "_RHEL_RELEASE_VERSION_": "0",
                      "_NT_TARGET_VERSION": "0xA00", "_NT_TARGET_MAJ": "10", "TargetOS": "Win10", "TargetArch": "amd64"}
        self.meta = {"ClCompile": {"AdditionalIncludeDirectories": "", "PreprocessorDefinitions": ""},
                     "Link": {"AdditionalDependencies": ""}}
        self.sources = []
        self.imports = []
        self._load(self.path)

    def _load(self, path, depth=0):
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError):
            return
        for el in root:
            tag = el.tag.replace(NS, "")
            if not _cond_true(el.get("Condition"), self.props):
                continue
            if tag == "PropertyGroup":
                for p in el:
                    if _cond_true(p.get("Condition"), self.props):
                        self.props[p.tag.replace(NS, "")] = expand(p.text or "", self.props)
            elif tag == "Import" and depth < 4:
                proj = expand(el.get("Project", ""), self.props).replace("\\", "/")
                if proj and "VCTargetsPath" not in el.get("Project", "") and "UserRootDir" not in el.get("Project", ""):
                    ip = Path(proj) if Path(proj).is_absolute() else Path(path).parent / proj
                    if ip.exists():
                        self.imports.append(str(ip))
                        self._load(ip, depth + 1)
            elif tag == "ItemDefinitionGroup":
                for tool in el:
                    t = tool.tag.replace(NS, "")
                    if t not in self.meta:
                        continue
                    for m in tool:
                        name = m.tag.replace(NS, "")
                        if not _cond_true(m.get("Condition"), self.props):
                            continue
                        old = self.meta[t].get(name, "")
                        self.meta[t][name] = expand((m.text or "").replace(f"%({name})", old), self.props)
            elif tag == "ItemGroup":
                for it in el:
                    if it.tag.replace(NS, "") != "ClCompile" or not it.get("Include"):
                        continue
                    if not _cond_true(it.get("Condition"), self.props):
                        continue
                    excluded = any(x.tag.replace(NS, "") == "ExcludedFromBuild" and _cond_true(x.get("Condition"), self.props)
                                   and (x.text or "").strip().lower() == "true" for x in it)
                    if not excluded:
                        self.sources.append(Path(path).parent / expand(it.get("Include"), self.props).replace("\\", "/"))

    @property
    def driver_type(self):
        return self.props.get("DriverType", "")

    def includes(self):
        out = []
        for d in self.meta["ClCompile"].get("AdditionalIncludeDirectories", "").split(";"):
            d = d.strip().replace("\\", "/")
            if d and "%(" not in d:
                out.append(str(Path(d) if Path(d).is_absolute() else (self.dir / d)))
        return out

    def defines(self):
        return ["-D" + d.strip() for d in self.meta["ClCompile"].get("PreprocessorDefinitions", "").split(";")
                if d.strip() and "%(" not in d]

    def libs(self):
        return [Path(x.strip().replace("\\", "/")).name.lower() for x in self.meta["Link"].get("AdditionalDependencies", "").split(";")
                if x.strip() and "%(" not in x]
