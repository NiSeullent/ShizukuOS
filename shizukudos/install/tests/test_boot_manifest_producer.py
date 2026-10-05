#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host fixture of the SHZBOOT.MAN producer (install/mkpayload.py build_boot_manifest, contract routing02 C1) without
building any input: synthetic blobs -> template -> layout/offset/hash assertions -> stamping -> tamper; then the
Supervisor's own shz_bman_parse (supervisor/src/boot_manifest.c, host-compiled) as consumer, and the SHZSETUP
fat32_overwrite_file() on a small mkfs.fat image (deleted afterwards). Not a boot, install or VM proof."""
import hashlib
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHZ = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
import mkpayload  # noqa: E402

rows = []


def check(name, ok, detail=""):
    rows.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{'' if ok else '  ' + str(detail)}", flush=True)


def run(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, timeout=50, **kw)


def entry(buf, i):
    e = buf[96 + 176 * i:96 + 176 * (i + 1)]
    s = lambda a, b: e[a:b].split(b"\0")[0].decode()  # noqa: E731
    u = lambda o: struct.unpack_from("<I", e, o)[0]  # noqa: E731
    return {"component": s(0, 16), "parent": s(16, 32), "blob": s(32, 48), "path": s(48, 112), "kind": u(112),
            "dom": u(116), "depends": u(120), "flags": u(124), "caps": u(128), "reserved": u(132),
            "size": struct.unpack_from("<Q", e, 136)[0], "sha": e[144:176], "raw": e}


def main():
    blobs = {"KERNEL32.BIN": b"K32" * 1000, "KERNEL64.BIN": b"K64" * 2000, "WIN64.IMG": b"IMG" * 3000,
             "KERNEL64S.BIN": b"K6S" * 1500, "DISK.IMG": b"not a loader blob"}
    man, listed = mkpayload.build_boot_manifest(blobs)
    n = len(listed)
    hdr = struct.unpack_from("<QHHHHIIQII", man, 0)
    check("header: magic SZBTMAN1, v1, 96/176, total = 96 + n*176, loader_profile 0, flags 0",
          man[:8] == b"SZBTMAN1" and hdr[1:6] == (1, 96, 176, n, 96 + 176 * n) and len(man) == 96 + 176 * n
          and hdr[6] == 0 and hdr[9] == 0, hdr)
    check("template: install_generation [24,32) and install_id [72,88) zero, reserved [88,96) zero",
          man[24:32] == bytes(8) and man[72:88] == bytes(16) and man[88:96] == bytes(8))
    check("entries_sha256 [40,72) = SHA-256 of the entry table only", man[40:72] == hashlib.sha256(man[96:]).digest())
    es = [entry(man, i) for i in range(n)]
    want = [("ShizukuCore", "", "", 0, 0, 0x0, 1), ("ShizukuDOS", "ShizukuCore", "", 1, 2, 0x1, 1),
            ("Shizuku32", "ShizukuCore", "KERNEL32.BIN", 1, 3, 0x3, 1),
            ("Shizuku64", "ShizukuCore", "KERNEL64.BIN", 1, 4, 0x25, 1), ("ShizukuOS", "ShizukuCore", "", 1, 5, 0x1, 0),
            ("Win64Runtime", "Shizuku64", "WIN64.IMG", 2, 0, 0x1, 1),
            ("Kernel64S", "Shizuku64", "KERNEL64S.BIN", 2, 0, 0x1, 0)]
    got = [(e["component"], e["parent"], e["blob"], e["kind"], e["dom"], e["depends"], e["flags"]) for e in es]
    check("entry table (order, parent, blob, kind, domain, depends, REQUIRED) as emitted", got == want, got)
    ok = all(e["reserved"] == 0 and (e["size"] == len(blobs[e["blob"]]) and e["sha"] == hashlib.sha256(blobs[e["blob"]]).digest()
             and e["path"] == "\\SHZDOS\\" + e["blob"] if e["blob"] else e["size"] == 0 and e["sha"] == bytes(32) and not e["path"])
             for e in es)
    check("entry offsets: size@136 and sha256@144 bind the exact blob bytes; path \\SHZDOS\\<blob>", ok)
    check("no entry names SHZBOOT.MAN or DISK.IMG", all(e["blob"] not in ("SHZBOOT.MAN", "DISK.IMG") for e in es))
    gen, iid = 7, bytes(range(1, 17))
    st = mkpayload.stamp_boot_manifest(man, gen, iid)
    diff = [i for i in range(len(man)) if man[i] != st[i]]
    check("stamp changes only [24,32) and [72,88); entries_sha256 unchanged",
          all(24 <= i < 32 or 72 <= i < 88 for i in diff) and st[40:72] == man[40:72]
          and hashlib.sha256(st[96:]).digest() == st[40:72], diff[:8])
    t = dict(blobs)
    t["WIN64.IMG"] = bytes([t["WIN64.IMG"][0] ^ 1]) + t["WIN64.IMG"][1:]
    man2, _ = mkpayload.build_boot_manifest(t)
    e2 = [entry(man2, i) for i in range(n)]
    check("tampering one WIN64.IMG byte changes only its digest and the entries hash",
          e2[5]["sha"] != es[5]["sha"] and all(e2[i]["raw"] == es[i]["raw"] for i in range(n) if i != 5)
          and man2[40:72] != man[40:72])
    try:
        mkpayload.build_boot_manifest({k: v for k, v in blobs.items() if k != "KERNEL64.BIN"})
        check("missing blob is refused by the producer", False)
    except ValueError:
        check("missing blob is refused by the producer", True)
    cfg = mkpayload.SYSLINUX_CFG
    check("syslinux Kernel64 entry ends with module --- /SHZDOS/SHZBOOT.MAN",
          b"--- /SHZDOS/WIN64.IMG --- /SHZDOS/SHZBOOT.MAN\r\n" in cfg)
    drv = mkpayload.driver_metadata([(nm, "", b"") for nm, *_ in mkpayload.DRIVERS], "ab" * 32)
    check("drivers metadata: builtin rows only, match ids from DRIVERS, image sha = KERNEL64S.BIN",
          all(d["kind"] == "builtin" and d["service"] is None and d["image_sha256"] == "ab" * 32 and 1 <= len(d["match"]) <= 8
              for d in drv) and [d["match"] for d in drv] == [m for *_, m in mkpayload.DRIVERS])

    with tempfile.TemporaryDirectory(prefix="shz-bman-") as tmp:
        tmp = Path(tmp)
        cc = shutil.which("gcc") or shutil.which("cc")
        exe = tmp / "bman_consumer"
        r = run([cc, "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror", "-include", "string.h",
                 "-I", SHZ / "supervisor" / "src", "-I", SHZ / "supervisor" / "include",
                 HERE / "bman_consumer_host.c", SHZ / "supervisor" / "src" / "boot_manifest.c", "-o", exe])
        if r.returncode:
            check("consumer harness compiles boot_manifest.c on the host", False, r.stderr[-600:])
        else:
            for name, data in blobs.items():
                (tmp / name).write_bytes(data)
            (tmp / "tpl.man").write_bytes(man)
            (tmp / "st.man").write_bytes(st)
            sup = [f"{b}={tmp / b}" for b in ("KERNEL32.BIN", "KERNEL64.BIN", "WIN64.IMG")]
            a = run([exe, tmp / "st.man", 0, 1, *sup])
            check("consumer shz_bman_parse: stamped manifest + Supervisor-route blobs admitted (KERNEL64S optional absent)",
                  a.returncode == 0 and "PARSE-OK entries=7 present=0x3f generation=7" in a.stdout, a.stdout + a.stderr)
            a = run([exe, tmp / "st.man", 0, 1, *sup, f"KERNEL64S.BIN={tmp / 'KERNEL64S.BIN'}"])
            check("consumer: with KERNEL64S.BIN supplied every entry is present", "present=0x7f" in a.stdout, a.stdout)
            a = run([exe, tmp / "tpl.man", 0, 1, *sup])
            check("consumer: the unstamped template is refused (generation/install_id zero)",
                  a.returncode == 1 and "PARSE-FAIL" in a.stdout, a.stdout)
            (tmp / "WIN64.IMG").write_bytes(t["WIN64.IMG"])
            a = run([exe, tmp / "st.man", 0, 1, *sup])
            check("consumer: a tampered WIN64.IMG is refused by SHA-256", a.returncode == 1 and "SHA-256" in a.stdout and "WIN64.IMG" in a.stdout, a.stdout)
            a = run([exe, tmp / "st.man", 1, 1, *sup])
            check("consumer: a different loader_profile is refused", a.returncode == 1 and "profile" in a.stdout, a.stdout)

        # fat32_overwrite_file on a 36 MiB FAT32 image (512-byte clusters so the manifest spans 3 clusters)
        ow = tmp / "fat32_overwrite"
        r = run([cc, "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror", HERE / "fat32_overwrite_host.c",
                 SHZ / "win64" / "setup" / "fat32fmt.c", "-o", ow])
        tools = all(shutil.which(x) for x in ("mkfs.fat", "mcopy", "fsck.fat"))
        if r.returncode or not tools:
            check("fat32_overwrite_file host harness builds (mkfs.fat/mtools present)", False, r.stderr[-600:])
        else:
            img = tmp / "esp.img"
            with open(img, "wb") as fh:
                fh.truncate(36 << 20)
            env = {"MTOOLS_SKIP_CHECK": "1", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
            run(["mkfs.fat", "-F", "32", "-S", "512", "-s", "1", "-n", "SHZESP", "-i", "53485A45", img], env=env)
            run(["mmd", "-i", img, "::/SHZDOS"], env=env)
            run(["mcopy", "-i", img, tmp / "tpl.man", "::/SHZDOS/SHZBOOT.MAN"], env=env)
            run(["mcopy", "-i", img, tmp / "KERNEL32.BIN", "::/SHZDOS/KERNEL32.BIN"], env=env)
            before = img.read_bytes()
            off = before.find(man)
            a = run([ow, img, "/SHZDOS/SHZBOOT.MAN", tmp / "st.man"])
            after = img.read_bytes()
            d = [i for i in range(len(before)) if before[i] != after[i]] if a.returncode == 0 else []
            check("overwrite: OK and the image differs only at the stamp bytes of the file's data",
                  a.returncode == 0 and "OVERWRITE-OK" in a.stdout and off > 0 and d and
                  all(off + 24 <= i < off + 32 or off + 72 <= i < off + 88 for i in d), (a.stdout, d[:6]))
            f = run(["fsck.fat", "-n", img])
            check("overwrite: fsck.fat -n clean (no FAT/dirent change)", f.returncode == 0, f.stdout[-300:])
            m = run(["mcopy", "-n", "-i", img, "::/SHZDOS/SHZBOOT.MAN", tmp / "rb.man"], env=env)
            check("overwrite: mtools reads back the stamped bytes", m.returncode == 0 and (tmp / "rb.man").read_bytes() == st)
            (tmp / "short.man").write_bytes(st[:-176])
            a = run([ow, img, "/SHZDOS/SHZBOOT.MAN", tmp / "short.man"])
            check("overwrite: a size mismatch is refused and nothing is written",
                  a.returncode == 1 and "OVERWRITE-REFUSED" in a.stdout and img.read_bytes() == after, a.stdout)
            a = run([ow, img, "/SHZDOS/ABSENT.MAN", tmp / "st.man"])
            check("overwrite: an absent file is refused", a.returncode == 1 and "not found" in a.stdout, a.stdout)
            img.unlink()
    print(f"{sum(rows)}/{len(rows)} PASS")
    return 0 if all(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
