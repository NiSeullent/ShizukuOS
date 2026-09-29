# SPDX-License-Identifier: GPL-2.0-only
"""Host side of T_INTS: parse INTS.TXT, check it against the specs, compare two boot paths.

T_INTS.COM (shizukudos/dos16/tests/t_ints.asm) records raw register results of the
PC BIOS services a DOS IO.SYS-class kernel uses. This module

  * parses the file (``parse``),
  * checks each run on its own against RBIL / IBM PS/2 BIOS / Phoenix EDD /
    ACPI E820 / VBE 3.0 semantics and against bytes the host reads from the disk
    image itself (``verify``), and
  * compares a legacy-BIOS run with a UEFI+CSMWrap run of the *same* image on the
    *same* QEMU hardware (``compare``): every value must match unless it is in
    EXPECTED_DIFF, and every expected difference is re-derived from evidence of
    its own path (for example the CSM path's E820 map must be CSMWrap's map built
    from the UEFI memory map, and E801h/88h must follow from that map).
"""
import datetime
import re

SECTOR = 512
PART_START = 63
WRITE_TAGS = {2: (b"SHZ-INTS-CHS-W02", 0xA5), 3: (b"SHZ-INTS-LBA-W03", 0x5A)}

# Where the pinned FreeDOS kernel (ke2046, 5ffb5502) and its FAT16 boot sector call each service,
# from a grep of build/upstream/freedos-kernel/{kernel,drivers,boot}. "-" = the kernel never calls it.
FREEDOS_USE = {
    "INT 11h": "main.c InitPrinters/InitSerialPorts; initdisk.c (floppy count)",
    "INT 12h": "kernel.asm (moves init code below the top of memory); initoem.c init_oem",
    "INT 13h 00h": "initdisk.c BIOS_drive_reset; drivers/floppy.asm FL_RESET; kernel.asm fatal path",
    "INT 13h 02h": "boot/boot.asm (CHS read); initdisk.c partition scan in CHS mode; floppy.asm via dsk.c",
    "INT 13h 03h": "drivers/floppy.asm fl_readwrite via dsk.c (CHS write)",
    "INT 13h 08h": "initdisk.c (geometry, BIOS_nrdrives)",
    "INT 13h 15h": "initdisk.c init_readdasd",
    "INT 13h 41h": "initdisk.c LBA detection; boot/boot.asm LBA detection",
    "INT 13h 42h": "boot/boot.asm (LBA read); initdisk.c partition scan; floppy.asm fl_lba_ReadWrite (dsk.c LBA_READ)",
    "INT 13h 43h": "floppy.asm fl_lba_ReadWrite (dsk.c LBA_WRITE, 4302h write+verify when VERIFY is on)",
    "INT 13h 48h": "initdisk.c (LBA disk size)",
    "INT 15h E820h/E801h/88h/C0h/2400h-2403h": "- (no INT 15h call in the kernel; XMS drivers such as HIMEMX use "
                                               "E820h/E801h/88h, and the kernel reaches A20 through XMS)",
    "INT 16h 00h/01h/10h/11h": "kernel/console.asm (10h/11h when BDA 0040:0096 bit 4 is set); config.c boot prompt; "
                               "intr.asm KEYCHECK; kernel.asm fatal path",
    "INT 16h 02h/12h": "- (config.c reads the shift flags from BDA 0040:0017 directly)",
    "INT 1Ah 00h": "drivers/rdpcclk.asm ReadPCClock (DOS time of day)",
    "INT 1Ah 02h/04h": "initclk.c (RTC time and date at boot)",
    "INT 10h 0Eh": "kernel/console.asm (CON output), kernel.asm, boot/boot.asm",
    "INT 10h 0Fh": "kernel.asm cpu_abort",
    "INT 10h 03h/12h/1Ah/4F00h/4F01h": "- (not called by the kernel; used by DOS programs and drivers)",
}


def parse(text):
    """INTS.TXT -> ordered list of (key, fields, rest). Key-value tokens are 'NAME=VALUE'."""
    records = []
    for line in text.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        key, _, rest = line.partition(" ")
        if "=" in key:                       # FAILMASK=xxxxxxxx
            k, _, v = key.partition("=")
            records.append((k, {k: v}, ""))
            continue
        fields = {}
        if not key.endswith(("_OEM", "_VENDOR", "_PRODUCT")):
            for tok in rest.split():
                if "=" in tok:
                    k, _, v = tok.partition("=")
                    fields[k] = v
        records.append((key, fields, rest))
    return records


def index(records):
    """Stable ids for repeated keys: disk lines by LBA, keyboard lines by state, A20 status by order."""
    out = {}
    counts = {}
    for key, fields, rest in records:
        if key in ("I13_02", "I13_42", "I13_RB", "I13_03", "I13_43"):
            ident = f"{key}@{fields.get('LBA', '?')}"
        elif key in ("I16_01", "I16_11"):
            ident = f"{key}@{fields.get('STATE', '?')}"
        elif key == "E820":
            ident = f"E820#{int(rest.split()[0], 16):02d}"
        else:
            n = counts.get(key, 0)
            counts[key] = n + 1
            ident = key if n == 0 else f"{key}#{n}"
        out[ident] = fields if fields else {"TEXT": rest}
    return out


def fnv1a32(data):
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def write_pattern(lba):
    tag, seed = WRITE_TAGS[lba]
    return tag + bytes(((i & 0xFF) ^ seed) for i in range(16, SECTOR))


def e820_entries(ix):
    ents = []
    for ident in sorted(k for k in ix if k.startswith("E820#")):
        f = ix[ident]
        ents.append({"base": int(f["BASE"], 16), "len": int(f["LEN"], 16), "type": int(f["TYPE"], 16),
                     "ecx": int(f["ECX"], 16), "ext": int(f["EXT"], 16)})
    return ents


def ram_contiguous_from(ents, start):
    """Bytes of type-1 RAM contiguous from `start` (ranges may be unsorted or adjacent)."""
    end = start
    changed = True
    while changed:
        changed = False
        for e in ents:
            if e["type"] == 1 and e["base"] <= end < e["base"] + e["len"]:
                end = e["base"] + e["len"]
                changed = True
    return end - start


def _h(ix, ident, field, default=None):
    try:
        return int(ix[ident][field], 16)
    except (KeyError, ValueError):
        return default


def _check(name, ok, detail=""):
    return {"check": name, "status": "PASS" if ok else "FAIL", "detail": detail}


def _bcd(v, lo, hi):
    return all(((v >> s) & 0xF) <= 9 for s in range(0, 8, 4)) and lo <= int(f"{v:02x}") <= hi


def verify(text, image, disk_after, run_utc=None):
    """Checks for one run. image/disk_after: bytes of the disk before and after the run."""
    records = parse(text)
    ix = index(records)
    checks = [_check("INTS.TXT framed (INTS 1 ... END)", records[:1] and records[0][0] == "INTS"
                     and records[0][2] == "1" and records[-1][0] == "END", f"{len(records)} lines")]
    checks.append(_check("guest-side mandatory mask is zero", ix.get("FAILMASK", {}).get("FAILMASK") == "00000000",
                         str(ix.get("FAILMASK"))))
    # --- INT 11h / 12h / BDA
    checks.append(_check("INT 11h equipment word == BDA 0040:0010",
                         _h(ix, "I11", "AX") is not None and _h(ix, "I11", "AX") == _h(ix, "I11", "BDA410"),
                         str(ix.get("I11"))))
    conv = _h(ix, "I12", "AX", 0)
    ebda = _h(ix, "I12", "EBDA", 0)
    checks.append(_check("INT 12h == BDA 0040:0013, 512..640 KiB, EBDA starts where it ends",
                         conv == _h(ix, "I12", "BDA413") and 512 <= conv <= 640 and ebda * 16 == conv * 1024,
                         str(ix.get("I12"))))
    # --- INT 13h
    total = len(image) // SECTOR
    g = ix.get("I13_08", {})
    heads, spt, cyls, ndrv = _h(ix, "I13_08", "HEADS", 0), _h(ix, "I13_08", "SPT", 0), _h(ix, "I13_08", "CYLS", 0), \
        _h(ix, "I13_08", "DX", 0) & 0xFF
    checks.append(_check("INT 13h AH=08h: geometry within disk, drive count == BDA 0040:0075",
                         g.get("CF") == "0" and spt and heads and cyls * heads * spt <= total
                         and ndrv == _h(ix, "I13_08", "BDA475") and ndrv >= 1, str(g)))
    checks.append(_check("INT 13h AH=00h reset CF=0", ix.get("I13_00", {}).get("CF") == "0", str(ix.get("I13_00"))))
    d15 = (_h(ix, "I13_15", "CX", 0) << 16) | _h(ix, "I13_15", "DX", 0)
    checks.append(_check("INT 13h AH=15h: fixed disk (AH=03h), CX:DX sectors <= disk size",
                         ix.get("I13_15", {}).get("CF") == "0" and _h(ix, "I13_15", "AH") == 3 and 0 < d15 <= total,
                         f"CX:DX={d15} disk={total}"))
    checks.append(_check("INT 13h AH=41h: EDD present (BX=AA55h, CX bit0 = 42h-44h,47h,48h)",
                         ix.get("I13_41", {}).get("CF") == "0" and _h(ix, "I13_41", "BX") == 0xAA55
                         and _h(ix, "I13_41", "CX", 0) & 1 and _h(ix, "I13_41", "AH", 0) >= 0x20,
                         str(ix.get("I13_41"))))
    e48 = ix.get("I13_48", {})
    checks.append(_check("INT 13h AH=48h: size >= 1Ah, 512-byte sectors, total sectors == image size",
                         e48.get("CF") == "0" and _h(ix, "I13_48", "SIZE", 0) >= 0x1A
                         and _h(ix, "I13_48", "BPS") == SECTOR and _h(ix, "I13_48", "SECTORS") == total,
                         f"{e48.get('SIZE')} sectors={e48.get('SECTORS')} image={total}"))
    mbr, pbr = fnv1a32(image[:SECTOR]), fnv1a32(image[PART_START * SECTOR:(PART_START + 1) * SECTOR])
    for lba, want in ((0, mbr), (PART_START, pbr)):
        for fn in ("I13_02", "I13_42"):
            ident = f"{fn}@{lba:08X}"
            checks.append(_check(f"INT 13h {fn[4:]}h read LBA {lba}: bytes == host image (FNV-1a)",
                                 ix.get(ident, {}).get("CF") == "0" and _h(ix, ident, "FNV") == want,
                                 f"guest={ix.get(ident, {}).get('FNV')} host={want:08X}"))
    c, h, s = _h(ix, "I13_02@0000003F", "C"), _h(ix, "I13_02@0000003F", "H"), _h(ix, "I13_02@0000003F", "S")
    checks.append(_check("INT 13h CHS for LBA 63 derived from AH=08h geometry",
                         spt and (c * heads + h) * spt + s - 1 == PART_START, f"C/H/S={c}/{h}/{s}"))
    for lba, fn in ((2, "I13_03"), (3, "I13_43")):
        want = write_pattern(lba)
        got = disk_after[lba * SECTOR:(lba + 1) * SECTOR]
        checks.append(_check(f"INT 13h {fn[4:]}h write LBA {lba}: guest read-back and host disk bytes",
                             ix.get(f"{fn}@{lba:08X}", {}).get("CF") == "0"
                             and ix.get(f"I13_RB@{lba:08X}", {}).get("MATCH") == "1" and got == want,
                             f"host_match={got == want}"))
    untouched = all(disk_after[l * SECTOR:(l + 1) * SECTOR] == image[l * SECTOR:(l + 1) * SECTOR]
                    for l in (0, 1, 4, PART_START))
    checks.append(_check("no stray INT 13h writes (LBA 0, 1, 4, 63 unchanged)", untouched))
    # --- INT 15h E820h (ACPI "System Address Map Interfaces")
    ents = e820_entries(ix)
    e = ix.get("I15_E820", {})
    srt = sorted(ents, key=lambda x: x["base"])
    overlap = any(a["base"] + a["len"] > b["base"] for a, b in zip(srt, srt[1:]))
    checks.append(_check("E820: >= 1 entry, 'SMAP' each call, list ended by EBX=0 or CF=1",
                         len(ents) >= 1 and _h(ix, "I15_E820", "N") == len(ents) and e.get("END") in ("Z", "C"),
                         f"N={len(ents)} END={e.get('END')}"))
    checks.append(_check("E820: types 1..5, non-zero lengths, no overlaps",
                         ents and all(1 <= x["type"] <= 5 and x["len"] > 0 for x in ents) and not overlap))
    checks.append(_check("E820: entry size 20 or 24; 24-byte entries have ext. attr bit 0 set",
                         ents and all(x["ecx"] in (20, 24) and (x["ecx"] == 20 or x["ext"] & 1) for x in ents),
                         f"ECX={sorted({x['ecx'] for x in ents})}"))
    checks.append(_check("E820: 20-byte walk returns the same entries",
                         ix.get("I15_E820_20", {}).get("SAME") == "1", str(ix.get("I15_E820_20"))))
    low = next((x for x in ents if x["base"] == 0), None)
    checks.append(_check("E820: RAM at 0 of exactly INT 12h KiB; A0000-FFFFF never RAM",
                         low and low["type"] == 1 and low["len"] == conv * 1024
                         and not any(x["type"] == 1 and x["base"] < 0x100000 and x["base"] + x["len"] > 0xA0000
                                     for x in ents), str(low)))
    above1m = ram_contiguous_from(ents, 0x100000)
    ax, bx = _h(ix, "I15_E801", "AX", -1), _h(ix, "I15_E801", "BX", -1)
    want_ax = min(above1m, 15 << 20) >> 10
    want_bx = (ram_contiguous_from(ents, 16 << 20) >> 16) if above1m >= (15 << 20) else 0
    checks.append(_check("E801h: AX/BX follow from the E820 RAM contiguous from 1 MiB / 16 MiB (CX=AX, DX=BX)",
                         ix.get("I15_E801", {}).get("CF") == "0" and ax == want_ax and bx == min(want_bx, 0xFFFF)
                         and _h(ix, "I15_E801", "CX") == ax and _h(ix, "I15_E801", "DX") == bx,
                         f"AX={ax:#x}/{want_ax:#x} BX={bx:#x}/{want_bx:#x}"))
    a88 = _h(ix, "I15_88", "AX", -1)
    checks.append(_check("INT 15h AH=88h == contiguous RAM above 1 MiB in KiB (SeaBIOS caps at 63 MiB)",
                         ix.get("I15_88", {}).get("CF") == "0" and a88 == min(above1m >> 10, 0xFC00),
                         f"AX={a88:#x} e820={above1m >> 10:#x}"))
    checks.append(_check("INT 15h AH=C0h: configuration table present (length >= 8)",
                         ix.get("I15_C0", {}).get("CF") == "0" and _h(ix, "I15_C0", "LEN", 0) >= 8, str(ix.get("I15_C0"))))
    a20 = [ix.get(k, {}) for k in ("I15_2402", "I15_2402#1", "I15_2402#2")]
    checks.append(_check("A20 2400h/2401h/2402h/2403h: status tracks the gate and the FFFF:0500 wrap test",
                         ix.get("I15_2403", {}).get("CF") == "0" and _h(ix, "I15_2403", "BX", 0) & 3
                         and [(x.get("AL"), x.get("WRAP")) for x in a20] == [("01", "0"), ("00", "1"), ("01", "0")],
                         str([(x.get("AL"), x.get("WRAP")) for x in a20])))
    # --- INT 16h
    kb = [ix.get("I16_01@EMPTY", {}).get("ZF"), ix.get("I16_05", {}).get("AL"), ix.get("I16_01@QUEUED", {}).get("AX"),
          ix.get("I16_00", {}).get("AX"), ix.get("I16_11@QUEUED", {}).get("AX"), ix.get("I16_10", {}).get("AX"),
          ix.get("I16_11@EMPTY", {}).get("ZF")]
    checks.append(_check("INT 16h 01h/05h/00h/11h/10h: queue semantics without blocking",
                         kb == ["1", "00", "1E61", "1E61", "3062", "3062", "1"], str(kb)))
    checks.append(_check("INT 16h 02h == BDA 0040:0017 == low byte of 12h",
                         ix.get("I16_02", {}).get("AL") == ix.get("I16_02", {}).get("BDA417")
                         and _h(ix, "I16_12", "AX", -1) & 0xFF == _h(ix, "I16_02", "AL"), str(ix.get("I16_12"))))
    # --- INT 1Ah
    t, dd = ix.get("I1A_02", {}), ix.get("I1A_04", {})
    cx, dx, ycx, ydx = (_h(ix, "I1A_02", "CX", 0), _h(ix, "I1A_02", "DX", 0), _h(ix, "I1A_04", "CX", 0),
                        _h(ix, "I1A_04", "DX", 0))
    bcd_ok = (_bcd(cx >> 8, 0, 23) and _bcd(cx & 0xFF, 0, 59) and _bcd(dx >> 8, 0, 59)
              and _bcd(ycx >> 8, 19, 20) and _bcd(ycx & 0xFF, 0, 99) and _bcd(ydx >> 8, 1, 12) and _bcd(ydx & 0xFF, 1, 31))
    checks.append(_check("INT 1Ah 02h/04h: CF=0, valid BCD time and date", t.get("CF") == "0" and dd.get("CF") == "0"
                         and bcd_ok, f"time={t} date={dd}"))
    if bcd_ok:
        rtc_s = int(f"{cx >> 8:02x}") * 3600 + int(f"{cx & 0xFF:02x}") * 60 + int(f"{dx >> 8:02x}")
        ticks = (_h(ix, "I1A_00", "CX", 0) << 16) | _h(ix, "I1A_00", "DX", 0)
        delta = abs(ticks * 65536 / 1193180 - rtc_s)
        delta = min(delta, 86400 - delta)
        # The BIOS seeds the BDA tick count from the RTC at POST and IRQ0 advances it; DOS's time of day is
        # this count (rdpcclk.asm). 30 s tolerates lost IRQ0 ticks on a starved TCG host but not an unseeded count.
        checks.append(_check("INT 1Ah 00h tick count agrees with the RTC time (<= 30 s)", delta <= 30.0,
                             f"ticks={ticks} rtc={rtc_s}s delta={delta:.2f}s"))
        if run_utc:
            guest = datetime.date(int(f"{ycx:04x}"), int(f"{ydx >> 8:02x}"), int(f"{ydx & 0xFF:02x}"))
            host = datetime.datetime.strptime(run_utc, "%Y-%m-%dT%H:%M:%SZ").date()
            checks.append(_check("INT 1Ah 04h date == host UTC date (+-1 day; QEMU RTC base=utc)",
                                 abs((guest - host).days) <= 1, f"guest={guest} host={host}"))
    # --- INT 10h
    v = ix.get("I10_0F", {})
    checks.append(_check("INT 10h 0Fh: mode 03h, 80 columns, == BDA 0049h/004Ah",
                         v.get("AL") == "03" and v.get("AH") == "50" and v.get("BDA449") == "03"
                         and v.get("BDA44A") == "0050", str(v)))
    tt = ix.get("I10_0E", {})
    checks.append(_check("INT 10h 0Eh teletype: CR -> column 0, 6 chars -> column 6, text in B800h memory",
                         tt.get("COL0") == "00" and tt.get("COL1") == "06" and tt.get("VRAM") == "1", str(tt)))
    checks.append(_check("INT 10h 12h BL=10h: EGA/VGA info returned (BL changed, color)",
                         _h(ix, "I10_12_10", "BX", 0x10) & 0xFF != 0x10 and _h(ix, "I10_12_10", "BX", 0) >> 8 == 0,
                         str(ix.get("I10_12_10"))))
    checks.append(_check("INT 10h 1A00h: supported, active display VGA color (08h)",
                         ix.get("I10_1A", {}).get("AL") == "1A" and _h(ix, "I10_1A", "BX", 0) & 0xFF == 8,
                         str(ix.get("I10_1A"))))
    vb = ix.get("I10_4F00", {})
    checks.append(_check("VBE 4F00h: AX=004Fh, 'VESA', version >= 2.0, mode list non-empty",
                         vb.get("AX") == "004F" and vb.get("SIG") == "VESA" and _h(ix, "I10_4F00", "VER", 0) >= 0x200
                         and _h(ix, "I10_4F00", "MODES", 0) > 0, str(vb)))
    vm = ix.get("I10_4F01", {})
    checks.append(_check("VBE 4F01h mode 0101h: 640x480x8, supported, linear base set",
                         vm.get("AX") == "004F" and vm.get("XRES") == "0280" and vm.get("YRES") == "01E0"
                         and vm.get("BPP") == "08" and _h(ix, "I10_4F01", "ATTR", 0) & 1
                         and _h(ix, "I10_4F01", "PHYS", 0) != 0, str(vm)))
    for c_ in checks:
        c_["check"] = "T_INTS " + c_["check"]
    return checks, ix


# Differences that are expected between the two paths, with the reason. Anything else must match.
EXPECTED_DIFF = {
    "E820": "memory map source: legacy SeaBIOS builds it from QEMU fw_cfg; under CSMWrap it is CSMWrap's "
            "conversion of the UEFI memory map (OVMF runtime/ACPI/NVS ranges stay reserved) plus SeaBIOS CSM "
            "reservations",
    "I15_E820": "number of entries follows from the E820 map source (see E820)",
    "I15_E820_20": "number of entries follows from the E820 map source (see E820)",
    "I15_E801": "derived from the E820 RAM contiguous from 1 MiB: OVMF keeps 800000h-808000h as ACPI NVS, so the "
                "CSM path sees 7 MiB there (verified against each path's own E820 map)",
    "I15_88": "same derivation as E801h",
    "I1A_02": "wall-clock time of each run",
    "I1A_00": "tick count of each run (checked against that run's RTC time)",
    "I1A_04": "date of each run (equal unless the runs straddle midnight UTC)",
    "I10_03": "cursor row: SeaBIOS CSM prints 'Press ESC for boot menu.' and two blank lines (fw/csm.c "
              "handle_csm_0002 -> boot.c interactive_bootmenu: no fw_cfg 'etc/show-boot-menu' in a CSM build, default "
              "1, 2.5 s wait); QEMU's SeaBIOS gets show-boot-menu=0 from fw_cfg, so there DOS starts 3 rows higher",
    "I10_0E": "same 3-row offset; columns and the text-memory check must match",
    "I10_4F01.PHYS": "linear framebuffer = VGA PCI BAR, assigned by SeaBIOS (legacy) vs OVMF's PCI enumeration (UEFI); "
                     "CSMWrap keeps OVMF's BARs below 4 GiB",
}
# Fields inside otherwise-compared lines that must match anyway in COLx/VRAM; row/time fields are excluded above.
SAME_FIELDS = {"I10_0E": ("COL0", "COL1", "VRAM")}


def compare(legacy_ix, uefi_ix):
    rows = []
    maps = [";".join(f"{e['base']:x}+{e['len']:x}:{e['type']}" for e in e820_entries(ix)) for ix in (legacy_ix, uefi_ix)]
    rows.append({"item": "E820 map", "legacy": maps[0], "uefi": maps[1],
                 "class": "MATCH" if maps[0] == maps[1] else "EXPECTED-DIFF",
                 "reason": "" if maps[0] == maps[1] else EXPECTED_DIFF["E820"]})
    for ident in sorted(set(legacy_ix) | set(uefi_ix)):
        a, b = legacy_ix.get(ident), uefi_ix.get(ident)
        base = ident.split("#")[0].split("@")[0]
        if base in ("FAILMASK", "END", "INTS", "E820"):
            continue
        if ident == "I10_4F01" and a and b:
            same_wo_phys = {k: v for k, v in a.items() if k != "PHYS"} == {k: v for k, v in b.items() if k != "PHYS"}
            rows.append({"item": ident, "legacy": a, "uefi": b,
                         "class": "MATCH" if a == b else ("EXPECTED-DIFF" if same_wo_phys else "UNEXPECTED-DIFF"),
                         "reason": "" if a == b else EXPECTED_DIFF["I10_4F01.PHYS"]})
            continue
        if base in SAME_FIELDS and a and b:
            keep = SAME_FIELDS[base]
            same = all(a.get(k) == b.get(k) for k in keep)
            rows.append({"item": ident, "legacy": a, "uefi": b,
                         "class": "MATCH" if a == b else ("EXPECTED-DIFF" if same else "UNEXPECTED-DIFF"),
                         "reason": "" if a == b else EXPECTED_DIFF[base]})
            continue
        if a == b:
            rows.append({"item": ident, "legacy": a, "uefi": b, "class": "MATCH", "reason": ""})
        elif base in EXPECTED_DIFF:
            rows.append({"item": ident, "legacy": a, "uefi": b, "class": "EXPECTED-DIFF", "reason": EXPECTED_DIFF[base]})
        else:
            rows.append({"item": ident, "legacy": a, "uefi": b, "class": "UNEXPECTED-DIFF", "reason": ""})
    return rows


def csmwrap_e820_from_serial(serial_text):
    """Parse CSMWrap's 'csmwrap e820 map has N items:' block (its conversion of the UEFI memory map)."""
    m = re.search(r"csmwrap e820 map has (\d+) items:\s*\n", serial_text)
    if not m:
        return None
    ents = []
    for line in serial_text[m.end():].splitlines()[:int(m.group(1))]:
        mm = re.match(r"\s*\d+:\s*([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)\s*=\s*(\d+)", line)
        if not mm:
            return None
        start, end = int(mm.group(1), 16), int(mm.group(2), 16)
        ents.append({"base": start, "len": end - start, "type": int(mm.group(3))})
    return ents


def e820_explained_by_csmwrap(guest_ents, csm_ents):
    """Is the guest's E820 map (CSM path) CSMWrap's map of the UEFI memory map?

    SeaBIOS CSM (fw/csm.c handle_csm_0002, malloc_prepboot) may only move memory between RAM (1)
    and reserved (2) inside CSMWrap's ranges -- it reserves what it keeps and returns unused parts of
    its high PMM zone, which CSMWrap handed over as reserved. Therefore: every guest range lies
    inside one CSMWrap range; a type change is only 1<->2; every CSMWrap ACPI (3) / NVS (4) range is
    present unchanged; and both maps cover the same bytes. Returns (ok, detail).
    """
    def container(e):
        return next((p for p in csm_ents if p["base"] <= e["base"] and e["base"] + e["len"] <= p["base"] + p["len"]),
                    None)
    changed, bad = [], []
    for e in guest_ents:
        p = container(e)
        if p is None:
            bad.append(e)
        elif p["type"] != e["type"]:
            (changed if {p["type"], e["type"]} <= {1, 2} else bad).append(e)
    lost = [p for p in csm_ents if p["type"] in (3, 4) and not any(
        g["base"] == p["base"] and g["len"] == p["len"] and g["type"] == p["type"] for g in guest_ents)]
    covered = sum(e["len"] for e in guest_ents) == sum(p["len"] for p in csm_ents)
    detail = (f"{len(guest_ents)} guest entries vs {len(csm_ents)} in CSMWrap's log; SeaBIOS RAM<->reserved "
              "changes: " + (", ".join(f"{e['base']:#x}+{e['len']:#x}->type{e['type']}" for e in changed) or "none")
              + (f"; unexplained: {bad}" if bad else "") + (f"; ACPI/NVS ranges missing: {lost}" if lost else "")
              + ("" if covered else "; covered bytes differ"))
    return not bad and not lost and covered, detail


def pack_rows(rows):
    """Compact table rows for evidence JSON / reports."""
    def fmt(v):
        return " ".join(f"{k}={x}" for k, x in v.items()) if isinstance(v, dict) else str(v)
    return [{"item": r["item"], "class": r["class"], "legacy": fmt(r["legacy"]), "uefi": fmt(r["uefi"]),
             "reason": r["reason"]} for r in rows]
