#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-side cross-checks for the user-mode system DLL sources, against independent implementations (Python's OpenSSL
backed hashlib / hmac / pbkdf2_hmac and its Unicode database). Nothing here runs inside Kernel64; it is what backs the
claim in t_u_bcrypt.c that its expected values are not the implementation's own output.

  1. every hash / HMAC / PBKDF2 vector literal in tests/t_u_bcrypt.c equals the OpenSSL result;
  2. dlls/bcrypt/hashes.c (the code that ships in bcrypt.dll) compiled natively agrees with OpenSSL on ~2000 random
     message / key / chunking / iteration combinations, including every length around the block boundaries;
  3. include/shz_wupper.h (the case-insensitive comparison table) equals str.upper() for all 65536 code units.

Usage: python3 shizukudos/win64/tests/u_host_crosscheck.py      (needs gcc for parts 2 and 3)
"""
import ast
import hashlib
import hmac
import random
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

W64 = Path(__file__).resolve().parents[1]
ALG = {"MD5": "md5", "SHA1": "sha1", "SHA256": "sha256", "SHA384": "sha384", "SHA512": "sha512"}
SPEC = r'(S\("(?:[^"\\]|\\.)*"\)|F\(0x[0-9a-f]+, \d+\))'


def spec(t):
    if t.startswith("S("):
        return ast.literal_eval(t[2:-1]).encode("latin1")
    b, n = re.match(r"F\((0x[0-9a-f]+), (\d+)\)", t).groups()
    return bytes([int(b, 16)]) * int(n)


def check_literal_vectors():
    src = (W64 / "tests" / "t_u_bcrypt.c").read_text()

    def table(name):
        return re.search(r"static const struct \{[^}]*\} " + name + r"\[\] = \{(.*?)\n\};", src, re.S).group(1)

    bad = total = 0
    for m in re.finditer(r'\{ "(\w+)", ' + SPEC + r',\s*"([0-9a-f]+)" \}', table("hash_vectors")):
        total += 1
        if hashlib.new(ALG[m.group(1)], spec(m.group(2))).hexdigest() != m.group(3):
            bad += 1
            print("HASH vector mismatch:", m.group(1), m.group(2)[:40])
    for m in re.finditer(r'\{ "(\w+)", ' + SPEC + ", " + SPEC + r',\s*"([0-9a-f]+)" \}', table("hmac_vectors")):
        total += 1
        if hmac.new(spec(m.group(2)), spec(m.group(3)), ALG[m.group(1)]).hexdigest() != m.group(4):
            bad += 1
            print("HMAC vector mismatch:", m.group(1), m.group(2)[:30])
    for m in re.finditer(r'\{ "(\w+)", ' + SPEC + ", " + SPEC + r', (\d+), (\d+), "([0-9a-f]+)" \}', table("pbkdf2_vectors")):
        total += 1
        if hashlib.pbkdf2_hmac(ALG[m.group(1)], spec(m.group(2)), spec(m.group(3)), int(m.group(4)), int(m.group(5))).hex() != m.group(6):
            bad += 1
            print("PBKDF2 vector mismatch:", m.group(1), m.group(4), m.group(5))
    print(f"literal vectors in t_u_bcrypt.c: {total} checked, {bad} mismatches")
    return bad == 0 and total >= 40


DRIVER = r'''
#include <stdio.h>
#include <string.h>
#include "hashes.h"
static size_t unhex(const char *s, uint8_t *o) { size_t n = strlen(s) / 2, i; for (i = 0; i < n; ++i) { unsigned v; sscanf(s + 2 * i, "%2x", &v); o[i] = (uint8_t)v; } return n; }
int main(void)
{
    static char op[32], a[16], k[8192], m[400000];
    static uint8_t kb[4096], mb[200000], out[512];
    while (scanf("%31s %15s %8191s %399999s", op, a, k, m) == 4) {
        unsigned alg = !strcmp(a, "md5") ? SHZ_H_MD5 : !strcmp(a, "sha1") ? SHZ_H_SHA1 : !strcmp(a, "sha256") ? SHZ_H_SHA256 : !strcmp(a, "sha384") ? SHZ_H_SHA384 : SHZ_H_SHA512;
        size_t kl = strcmp(k, "-") ? unhex(k, kb) : 0, ml = strcmp(m, "-") ? unhex(m, mb) : 0, dl = shz_hash_digest_len(alg), i;
        if (!strcmp(op, "hash")) {
            shz_hash_ctx c; size_t off = 0, step = kl ? kb[0] + 1 : 1000000;
            shz_hash_init(&c, alg);
            while (off < ml) { size_t t = ml - off < step ? ml - off : step; shz_hash_update(&c, mb + off, t); off += t; step = step % 97 + 1; }
            shz_hash_final(&c, out);
        } else if (!strcmp(op, "hmac")) {
            shz_hmac_ctx c; shz_hmac_init(&c, alg, kb, kl); shz_hmac_update(&c, mb, ml); shz_hmac_final(&c, out);
        } else {
            unsigned n = 0, len = 0; sscanf(op, "pbkdf2:%u:%u", &n, &len);
            shz_pbkdf2(alg, kb, kl, mb, ml, n, out, len); dl = len;
        }
        for (i = 0; i < dl; ++i) printf("%02x", out[i]);
        printf("\n");
    }
    return 0;
}
'''


def check_hashes_native(tmp):
    exe = tmp / "hosthash"
    (tmp / "driver.c").write_text(DRIVER)
    subprocess.run(["gcc", "-O1", "-Wall", "-Wextra", "-o", str(exe), "-I", str(W64 / "dlls" / "bcrypt"), str(tmp / "driver.c"),
                    str(W64 / "dlls" / "bcrypt" / "hashes.c")], check=True)
    random.seed(12345)
    lines, expect = [], []
    for a in ALG.values():
        for n in list(range(0, 300)) + [511, 512, 513, 1000, 4096, 100000]:
            msg = bytes(random.getrandbits(8) for _ in range(n))
            lines.append(f"hash {a} {random.randrange(0, 255):02x} {msg.hex() or '-'}")
            expect.append(hashlib.new(a, msg).hexdigest())
        for kl in (0, 1, 20, 63, 64, 65, 127, 128, 129, 200, 1000):
            for n in (0, 1, 55, 56, 64, 100, 128, 300):
                key = bytes(random.getrandbits(8) for _ in range(kl))
                msg = bytes(random.getrandbits(8) for _ in range(n))
                lines.append(f"hmac {a} {key.hex() or '-'} {msg.hex() or '-'}")
                expect.append(hmac.new(key, msg, a).hexdigest())
        for pw, salt, it, dl in ((b"password", b"salt", 1, 20), (b"password", b"salt", 2, 32), (b"password", b"salt", 4096, 20),
                                 (b"pass\0word", b"sa\0lt", 10, 16), (b"", b"", 3, 100), (b"k" * 200, b"s", 5, 130)):
            lines.append(f"pbkdf2:{it}:{dl} {a} {pw.hex() or '-'} {salt.hex() or '-'}")
            expect.append(hashlib.pbkdf2_hmac(a, pw, salt, it, dl).hex())
    out = subprocess.run([str(exe)], input="\n".join(lines) + "\n", capture_output=True, text=True).stdout.split("\n")
    bad = sum(1 for i, e in enumerate(expect) if out[i] != e)
    print(f"hashes.c native vs OpenSSL: {len(expect)} cases, {bad} mismatches")
    return bad == 0


def check_upper_table(tmp):
    (tmp / "up.c").write_text('#include <stdio.h>\n#include "shz_wupper.h"\nint main(void){unsigned c;for(c=0;c<0x10000;++c)printf("%u\\n",(unsigned)shz_wupper((uint16_t)c));return 0;}\n')
    exe = tmp / "up"
    subprocess.run(["gcc", "-O1", "-Wall", "-o", str(exe), "-I", str(W64 / "include"), str(tmp / "up.c")], check=True)
    got = subprocess.run([str(exe)], capture_output=True, text=True).stdout.split()
    bad = 0
    for cp in range(0x10000):
        if 0xD800 <= cp <= 0xDFFF:
            exp = cp
        else:
            u = chr(cp).upper()
            exp = ord(u) if len(u) == 1 and ord(u) < 0x10000 else cp
        bad += int(got[cp]) != exp
    print(f"shz_wupper.h vs str.upper(): 65536 code units, {bad} mismatches")
    return bad == 0


def main():
    ok = check_literal_vectors()
    if shutil.which("gcc"):
        tmp = Path(tempfile.mkdtemp(prefix="shz-crosscheck-"))
        try:
            ok = check_hashes_native(tmp) and ok
            ok = check_upper_table(tmp) and ok
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("gcc not found: skipping the native cross-checks")
    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
