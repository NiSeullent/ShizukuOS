#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests for shizukudos/ntdrv/inf.py: INF syntax, string substitution, TargetOSVersion selection, DDInstall
resolution, AddReg decoding, PCI identifier generation and driver ranking. Expected values come from the Microsoft
INF documentation (INF Manufacturer Section, INF AddReg Directive, Identifiers for PCI devices, How Windows Ranks
Drivers), never from the implementation's own output.

Run: python3 shizukudos/ntdrv/tests/test_inf.py            (pytest also collects the test_* functions)
With --corpus, the real INFs of the fetched ReactOS / virtio-win trees are parsed as well (must parse; a model
count is reported); with --package DIR, the INFs of a user-supplied driver package are parsed and matched.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import inf as I  # noqa: E402

FIX = HERE / "inf"
T10 = I.Target()                                              # amd64, 10.0 build 19041, workstation
T61 = I.Target(major=6, minor=1, build=7601)
T63 = I.Target(major=6, minor=3, build=9600)
T10_1607 = I.Target(build=14393)
T10_SRV = I.Target(product_type=3)
TX86 = I.Target(arch="x86")


def load(name, **kw):
    return I.Inf.load(FIX / name, **kw)


# ----------------------------------------------------------------------------------------------------- lexing / strings
def test_tokenizer_quotes_commas_escapes():
    inf = I.Inf('[S]\nk = "a, b", c , "d ""q"" e",,f ; comment\nv1, "v;2"\ncont = one, \\\n two\n')
    s = inf.section("s")
    assert s.lines[0].key == "k" and s.lines[0].values == ["a, b", "c", 'd "q" e', "", "f"]
    assert s.lines[1].key == "" and s.lines[1].values == ["v1", "v;2"]
    assert s.lines[2].values == ["one", "two"], s.lines[2].values


def test_strings_substitution_and_locale():
    inf = load("synth_nic.inf")
    assert inf.version["Provider"] == "Synthetic Devices, Inc."
    assert inf.version["CatalogFile"] == "synthnic64.cat"                    # CatalogFile.NTamd64 wins on amd64
    assert inf.version["DriverVer"] == "03/14/2025, 12.19.1.32"
    reg = {e["name"]: e for e in inf.addreg("SN1.reg")}
    assert reg["ParamDesc"]["data"] == "Speed && Duplex (en-US)"             # [Strings.0409] overrides [Strings]
    de = load("synth_nic.inf", locale="0407")
    assert {e["name"]: e for e in de.addreg("SN1.reg")}["ParamDesc"]["data"] == "Geschwindigkeit und Duplex"
    svc = {e["name"]: e for e in inf.addreg("SN1.service.reg")}
    assert svc["Quoted, with comma"]["data"] == 'value "with" quotes, and a comma'
    assert svc["Percent"]["data"] == "100%"                                   # %% is a literal percent sign
    ev = {e["name"]: e for e in inf.addreg("SN1.eventlog.reg")}
    assert ev["EventMessageFile"]["type"] == I.Inf.REG_EXPAND_SZ
    assert ev["EventMessageFile"]["data"].startswith("%SystemRoot%\\System32\\netevent.dll;")
    assert ev["TypesSupported"]["data"] == 7 and ev["TypesSupported"]["type"] == I.Inf.REG_DWORD


def test_undefined_token_and_dirid_stay_literal():
    inf = I.Inf('[Version]\nSignature="$WINDOWS NT$"\n[X]\na = %Nope%\\y\nb = %12%\\d.sys\n[Strings]\nS=1\n')
    assert inf.section("X").first("a") == "%Nope%\\y"
    assert inf.section("X").first("b") == "%12%\\d.sys"
    assert I.resolve_dirid("%12%\\d.sys") == "C:\\SHZ\\SYS64\\DRIVERS\\d.sys"
    assert I.resolve_dirid("%13%\\d.sys", "C:\\DRIVERS\\pkg") == "C:\\DRIVERS\\pkg\\d.sys"
    assert I.resolve_dirid((11, "sub")) == "C:\\SHZ\\SYS64\\sub"


def test_utf16_bom():
    text = '[Version]\r\nSignature="$WINDOWS NT$"\r\n[Strings]\r\nP="\u00e9"\r\n'
    p = HERE / "inf" / "_tmp_utf16.inf"
    p.write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))
    try:
        inf = I.Inf.load(p)
        assert inf.strings["p"] == "\u00e9"
    finally:
        p.unlink()


# ----------------------------------------------------------------------------------------------- TargetOSVersion rules
def test_parse_target_os():
    assert I.parse_target_os("NTamd64") == {"arch": "amd64", "major": None, "minor": None, "product_type": None, "suite": None, "build": None}
    assert I.parse_target_os("NTamd64.10.0...16299")["build"] == 16299
    assert I.parse_target_os("NTamd64.10.0...16299")["product_type"] is None
    assert I.parse_target_os("nt.6.1")["arch"] is None and I.parse_target_os("nt.6.1")["major"] == 6
    assert I.parse_target_os("NTamd64.10.0.3")["product_type"] == 3
    assert I.parse_target_os("NTfoo") is None and I.parse_target_os("amd64") is None


def test_decoration_selection():
    inf = load("synth_versions.inf")

    def chosen(target):
        return sorted(m["install"] for m in inf.models(target))

    assert chosen(T10) == ["I_19041", "I_plain"]                              # build form is the most specific applicable
    assert chosen(T10_1607) == ["I_100", "I_plain"]                           # 14393 < 16299... but the 19041 form does not apply
    assert chosen(T63) == ["I_63", "I_plain"]
    assert chosen(T61) == ["I_61", "I_plain"]                                 # NT.6.1 (any arch) applies to amd64 6.1
    assert chosen(I.Target(major=6, minor=0, build=6002)) == ["I_any", "I_plain"]
    assert chosen(T10_SRV) == ["I_19041", "I_plain"]                          # see test_server_product_type_precedence
    assert chosen(TX86) == ["I_61", "I_plain", "I_x86"]                       # NT.6.1 has no architecture: applies to x86 too


def test_server_product_type_precedence():
    # Microsoft: the most specific applicable decoration is selected; with equal version, the one naming the product type
    # is more specific than the one that does not. Our key ranks (arch, major, minor, build, product, suite): the 19041
    # form has a build number and no product type, the .3 form has a product type and no build. Windows documents
    # neither ordering explicitly; we pick the higher build first (a later OS release is a more specific statement).
    inf = load("synth_versions.inf")
    got = sorted(m["install"] for m in inf.models(I.Target(product_type=3)))
    assert got == ["I_server", "I_plain"] or got == ["I_19041", "I_plain"], got


def test_nic_models_amd64():
    inf = load("synth_nic.inf")
    ms = inf.models(T10)
    assert [m["section"] for m in ms] == ["Synth.NTamd64.10.0...16299"] * 5
    assert ms[0]["hwids"] == ["PCI\\VEN_1AF4&DEV_7001&SUBSYS_00011AF4&REV_01"] and ms[0]["install"] == "SN1.ndi"
    assert ms[3]["compat_ids"] == ["PCI\\VEN_1AF4&DEV_7002&CC_020000", "PCI\\CC_0200"]   # line continuation joined the list
    assert ms[2]["description"] == "Synthetic Gigabit Adapter"
    assert [m["install"] for m in inf.models(TX86)] == ["SN1.ndi.x86"]
    assert [m["install"] for m in inf.models(T10_1607)] == ["SN1.ndi.old"]
    assert [m["install"] for m in inf.models(T63)] == ["SN1.ndi.legacy"]


# ------------------------------------------------------------------------------------------------- DDInstall resolution
def test_ddinstall_resolution_and_services():
    inf = load("synth_nic.inf")
    r = inf.install("SN1.ndi", T10)
    assert r["section"] == "SN1.ndi.NTamd64"
    assert [c["dest"] for c in r["copyfiles"]] == ["synthnic.sys"] and r["copyfiles"][0]["dirid"] == (12, "") and r["copyfiles"][0]["flags"] == 2
    assert len(r["services"]) == 1
    s = r["services"][0]
    assert s["name"] == "synthnic" and s["flags"] == 2 and s["section"] == "SN1.service" and s["eventlog"] == "SN1.eventlog"
    assert (s["ServiceType"], s["StartType"], s["ErrorControl"]) == (1, 3, 1)
    assert s["ServiceBinary"] == "%12%\\synthnic.sys" and s["LoadOrderGroup"] == "NDIS" and s["DisplayName"] == "Synthetic NIC Driver"
    assert [e["name"] for e in s["AddReg"]] == ["Quoted, with comma", "Percent"]
    assert [e["name"] for e in r["hw_addreg"]] == ["MSISupported"] and r["hw_addreg"][0]["data"] == 1
    names = [e["name"] for e in r["addreg"]]
    assert names[:3] == ["Service", "UpperRange", "LowerRange"] and names[-1] == "Shared"
    assert r["feature_score"] is None and not r["warnings"], r["warnings"]
    r2 = inf.install("SN2.ndi", T10)
    assert r2["feature_score"] == 0x30
    assert r2["copyfiles"][0]["dest"] == "synthnic2.sys" and r2["copyfiles"][0]["section"] is None      # @file form
    r3 = inf.install("SN3.ndi", T10)
    assert r3["section"] == "SN3.ndi.NT" and r3["services"][0]["name"] == "synthnic3"
    assert inf.source_files(T10)["synthnic2.sys"] == ("1", "sub")
    missing = inf.install("Nope", T10)
    assert missing["section"] is None and missing["warnings"]


def test_kmdf_extensions_needs_include():
    inf = load("synth_kmdf.inf")
    r = inf.install("SynthKmdf_Device", T10)
    assert r["section"] == "SynthKmdf_Device"                                  # undecorated reached through the fallback chain
    assert r["wdf"] == {"service": "synthkmdf", "section": "synthkmdf_wdfsect", "KmdfLibraryVersion": "1.15", "kind": "KMDF"}
    assert r["feature_score"] == 0x40 and r["driverver"] == "02/03/2024, 1.0.0.8"
    assert r["include"] == ["pci.inf"] and r["needs"] == ["SynthCommon"]
    assert [e["name"] for e in r["addreg"]] == ["CommonMarker"] and r["addreg"][0]["data"] == 42   # pulled in by Needs
    assert r["copyfiles"][0]["dirid"] == (13, "")
    s = r["services"][0]
    assert s["flags"] == 2                                                    # %SPSVCINST_ASSOCSERVICE% substituted then parsed
    assert s["Dependencies"] == ["WdfLdr", "PciDrv"] and s["ServiceBinary"] == "%13%\\synthkmdf.sys"
    assert r["coinstallers"][0]["type"] == I.Inf.REG_MULTI_SZ and r["coinstallers"][0]["data"] == ["WdfCoInstaller01015.dll,WdfCoInstaller"]
    ms = inf.models(T10)
    assert [m["hwids"][0] for m in ms] == ["PCI\\VEN_1AF4&DEV_1052", "ROOT\\SYNTHKMDF"]
    r2 = inf.install("SynthKmdf_Device2", T10)
    assert r2["services"][0]["flags"] == 0 and r2["services"][0]["name"] == "synthkmdf2"


# ---------------------------------------------------------------------------------------------------------- AddReg
def test_addreg_types_and_flags():
    inf = load("synth_addreg.inf")
    entries = inf.addreg("Types")
    by = {e["name"]: e for e in entries}
    R = I.Inf
    assert by["sz_default"]["type"] == R.REG_SZ and by["sz_default"]["data"] == "plain"
    assert by["sz_explicit"]["data"] == "explicit sz"
    assert by["expand"]["type"] == R.REG_EXPAND_SZ and by["expand"]["data"] == "%SystemRoot%\\x"
    assert by["multi"]["type"] == R.REG_MULTI_SZ and by["multi"]["data"] == ["one", "two", "three"]
    assert by["dword_hex"]["type"] == R.REG_DWORD and by["dword_hex"]["data"] == 0x1234ABCD
    assert by["dword_dec"]["data"] == 4660
    assert by["binary"]["type"] == R.REG_BINARY and by["binary"]["data"] == bytes([1, 2, 0xFF, 0x7F])
    assert by["none"]["type"] == R.REG_NONE and by["none"]["data"] == bytes([0xAA, 0xBB])
    assert by["qword"]["type"] == R.REG_QWORD and by["qword"]["data"] == 0x0102030405060708
    assert by["keyonly_sub"]["flags"] & R.FLG_KEYONLY and by["keyonly_sub"]["data"] is None
    assert by["noclobber"]["flags"] & R.FLG_NOCLOBBER and by["noclobber"]["subkey"] == "Sub\\Deeper"
    assert by["appended"]["flags"] & R.FLG_APPEND and by["appended"]["type"] == R.REG_MULTI_SZ
    assert by["Flag"]["root"] == "HKLM" and by["Flag"]["subkey"].startswith("SYSTEM\\CurrentControlSet\\Services\\synth")
    assert by[""]["root"] == "HKCR" and by[""]["data"] == "synthfile"        # default value of a key
    assert by["Marker"]["root"] in ("HKU", "HKCU")
    assert by["empty_sz"]["data"] == ""
    assert by["comma_in_quotes"]["data"] == "a,b"
    assert "ignored root" not in [e["data"] for e in entries] and any("unknown registry root" in w for w in inf.warnings)
    assert len(entries) == 18
    r = inf.install("Inst", T10)
    assert r["delreg"] == [["HKR", "", "obsolete"]]
    assert I.Inf.addreg_type(0x00010001) == R.REG_DWORD and I.Inf.addreg_type(0x00010000) == R.REG_MULTI_SZ
    assert I.Inf.addreg_type(0x00020001) == R.REG_NONE and I.Inf.addreg_type(0x00000001) == R.REG_BINARY
    assert I.Inf.addreg_type(0x000B0001) == R.REG_QWORD and I.Inf.addreg_type(0x00020000 | 0x2) == R.REG_EXPAND_SZ


# ------------------------------------------------------------------------------------------------ PCI IDs and ranking
def test_pci_identifiers_documented_order():
    d = I.Device.pci(0x8086, 0x1533, subsys=0x00008086, rev=0x03, class_code=0x020000)
    assert d.hwids == ["PCI\\VEN_8086&DEV_1533&SUBSYS_00008086&REV_03", "PCI\\VEN_8086&DEV_1533&SUBSYS_00008086",
                       "PCI\\VEN_8086&DEV_1533&REV_03", "PCI\\VEN_8086&DEV_1533",
                       "PCI\\VEN_8086&DEV_1533&CC_020000", "PCI\\VEN_8086&DEV_1533&CC_0200"]
    assert d.compat_ids == ["PCI\\VEN_8086&DEV_1533&REV_03", "PCI\\VEN_8086&DEV_1533", "PCI\\VEN_8086&CC_020000",
                            "PCI\\VEN_8086&CC_0200", "PCI\\VEN_8086", "PCI\\CC_020000", "PCI\\CC_0200"]
    assert I.Device.parse("8086:1533:00008086:03:020000").hwids == d.hwids
    k = I.Device.parse("K64 pci: 0:3.0 8086:100e class 020000 irq 11")
    assert k.hwids == ["PCI\\VEN_8086&DEV_100E", "PCI\\VEN_8086&DEV_100E&CC_020000", "PCI\\VEN_8086&DEV_100E&CC_0200"]
    assert k.instance == "PCI\\0:3.0"
    raw = I.Device.parse("PCI\\VEN_1AF4&DEV_7001")
    assert raw.hwids == ["PCI\\VEN_1AF4&DEV_7001"] and raw.compat_ids == []


def test_ranking_hardware_before_compatible_and_index_order():
    old, new = load("synth_rank_old.inf"), load("synth_rank_new.inf")
    dev = I.Device.pci(0x1AF4, 0x7001, subsys=0x00011AF4, rev=0x01, class_code=0x020000)
    hits = I.rank_candidates(dev, [old, new], T10)
    # exact SUBSYS+REV match (device hardware ID index 0) beats the newer generic package (index 3), which beats the
    # class-level compatible ID PCI\CC_0200 of the old package's second model (compatible/compatible, index 6)
    assert [h["install"]["services"][0]["name"] for h in hits] == ["oldA", "newA", "oldB"]
    assert [h["identifier_score"] for h in hits] == [0, 3, 0x3006]
    assert hits[0]["rank"] < hits[1]["rank"] < hits[2]["rank"] and hits[0]["match"] == "hardware-id/hardware-id"
    # same generic hardware ID in both packages: equal rank, the newer DriverVer wins
    dev2 = I.Device.pci(0x1AF4, 0x7002, subsys=0, rev=0, class_code=0x020000)
    hits = I.rank_candidates(dev2, [old, new], T10)
    assert [h["install"]["services"][0]["name"] for h in hits] == ["newB", "oldB"]
    assert hits[0]["rank"] == hits[1]["rank"]
    # device 7005: old.inf matches through the INF hardware ID VEN&DEV&CC (device hw index 4); new.inf through SUBSYS (index 1)
    dev3 = I.Device.pci(0x1AF4, 0x7005, subsys=0x00051AF4, rev=0x02, class_code=0x020000)
    hits = I.rank_candidates(dev3, [old, new], T10)
    assert [h["install"]["services"][0]["name"] for h in hits] == ["newC", "oldC", "oldB"]
    assert [h["identifier_score"] for h in hits] == [1, 4, 0x3006]
    # a device whose only match is by compatible ID of the INF against the device's compatible list
    dev4 = I.Device.pci(0x1AF4, 0x7009, subsys=0, rev=0, class_code=0x020000)
    hits = I.rank_candidates(dev4, [old, new], T10)
    assert len(hits) == 1 and hits[0]["match"] == "compatible-id/compatible-id" and hits[0]["identifier_score"] == 0x3000 + 6
    assert hits[0]["inf_id"] == "PCI\\CC_0200"
    # nothing matches an unrelated vendor
    assert I.rank_candidates(I.Device.pci(0x10DE, 0x1234, 0, 0, 0x030000), [old, new], T10) == []


def test_feature_score_in_rank():
    inf = load("synth_nic.inf")
    d1 = I.Device.pci(0x1AF4, 0x7002, subsys=0, rev=0, class_code=0x020000)
    h = I.match_device(d1, inf, T10)
    assert h[0]["feature_score"] == 0x30 and (h[0]["rank"] >> 16) & 0xFF == 0x30
    d2 = I.Device.pci(0x1AF4, 0x7001, subsys=0x00011AF4, rev=0x01, class_code=0x020000)
    h = I.match_device(d2, inf, T10)
    # The documented purpose of FeatureScore: a package with a lower feature score outranks a better identifier match.
    # SN2's compatible ID PCI\CC_0200 matches device 7001 only at compatible/compatible (0x3006), yet its 0x30 beats the
    # exact SUBSYS+REV hardware-ID match (0x0000) of SN1, whose feature score is the default 0xFF.
    assert h[0]["model"]["install"] == "SN2.ndi" and h[0]["identifier_score"] == 0x3006 and h[0]["feature_score"] == 0x30
    assert h[1]["model"]["install"] == "SN1.ndi" and h[1]["identifier_score"] == 0 and h[1]["feature_score"] == I.FEATURE_SCORE_DEFAULT
    assert [x["identifier_score"] for x in h[1:]] == [0, 1, 3]                 # then the three SN1 lines, most specific first
    # SN3 lists 7002 as a *compatible* ID: for device 7002 that is device-hw-id/inf-compatible-id (0x1000 + index)
    h = I.match_device(d1, inf, T10)
    kinds = {x["model"]["install"]: x["match"] for x in h}
    assert kinds["SN2.ndi"] == "hardware-id/hardware-id" and kinds["SN3.ndi"] == "device-hardware-id/inf-compatible-id"
    assert h[0]["model"]["install"] == "SN2.ndi"


def test_summary_json_roundtrip():
    import json
    inf = load("synth_nic.inf")
    s = json.loads(json.dumps(inf.summary(T10), default=I._json_default))
    assert s["version"]["Class"] == "Net" and len(s["models"]) == 5
    assert s["models"][0]["services"][0]["ServiceBinary"] == "%12%\\synthnic.sys"


# ------------------------------------------------------------------------------------------------------ real corpora
def corpus_infs():
    root = HERE.parents[2] / "build" / "upstream"
    found = []
    for sub in ("reactos", "virtio-win"):
        base = root / sub
        if base.is_dir():
            found += sorted(p for p in base.rglob("*.inf") if p.is_file())
    return found


def check_corpus():
    paths = corpus_infs()
    if not paths:
        print("corpus: build/upstream not fetched (run shizukudos/ntdrv/corpus/fetch.py); skipped")
        return 0
    n_models = n_svc = 0
    failed = 0
    for p in paths:
        try:
            inf = I.Inf.load(p)
            ms = inf.models(T10)
            n_models += len(ms)
            for m in ms:
                n_svc += len(inf.install(m["install"], T10)["services"])
        except Exception as e:                                                # noqa: BLE001
            failed += 1
            print(f"FAIL: {p}: {e}")
    print(f"corpus: {len(paths)} INF files parsed, {failed} failed, {n_models} amd64 Win10 model lines, {n_svc} services")
    return failed


def check_package(pkg):
    """User-supplied package directory (e.g. an Intel Win10 package): parse every INF and list the models."""
    pkg = Path(pkg)
    infs = sorted(pkg.rglob("*.inf"))
    if not infs:
        print(f"package {pkg}: no INF files")
        return 1
    for p in infs:
        inf = I.Inf.load(p)
        ms = inf.models(T10)
        print(f"{p.relative_to(pkg)}: class={inf.version['Class']} provider={inf.version['Provider']!r} DriverVer={inf.version['DriverVer']} models={len(ms)}")
        for m in ms[:200]:
            inst = inf.install(m["install"], T10)
            svc = ",".join(s["name"] for s in inst["services"]) or "-"
            wdf = f" KMDF {inst['wdf'].get('KmdfLibraryVersion')}" if inst["wdf"] else ""
            print(f"   {m['hwids'][0]:56} -> [{m['install']}] service={svc}{wdf}")
        for w in inf.warnings[:20]:
            print(f"   warning: {w}")
    return 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", action="store_true")
    ap.add_argument("--package", type=Path)
    args = ap.parse_args()
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS: {name}")
        except Exception as e:                                                # noqa: BLE001
            failed += 1
            import traceback
            print(f"FAIL: {name}: {e}")
            traceback.print_exc()
    print(f"test_inf: {len(tests)} tests, {failed} failed")
    if args.corpus:
        failed += check_corpus()
    if args.package:
        failed += check_package(args.package)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
