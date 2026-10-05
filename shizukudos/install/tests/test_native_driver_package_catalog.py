#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Every production DRIVERS row of mkpayload.py must be accepted by the real catalog parser (kernel64/ntdrv_catalog.c,
host-compiled, no mocked matching). Not a boot, install or VM proof."""
import subprocess, sys, tempfile
from pathlib import Path
HERE = Path(__file__).resolve().parent
SHZ = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
import mkpayload  # noqa: E402

K = "a" * 64
rows = mkpayload.driver_metadata(mkpayload.driver_packages(), K)
txt = f"[Catalog]\r\nSchema=shizuku-driver-catalog/2\r\nSelection=default\r\nInstallGeneration=1\r\nKernel64Sha256={K}\r\n"
for i, r in enumerate(rows):
    txt += (f"\r\n[Driver.{i}]\r\nPackage=driver-{r['name']}\r\nKind=builtin\r\nMatch={', '.join(r['match'])}\r\n"
            f"ImageSha256={K}\r\nStart=boot\r\nPath=SHZ/x\r\nBytes=1\r\nSha256={K}\r\n")
txt += f"\r\n[Summary]\r\nCount={len(rows)}\r\n"
c = r'''#define SHZ_CATALOG_HOST 1
#include "%s/kernel64/ntdrv_catalog.c"
#include <stdio.h>
int main(void){ static char b[65536]; size_t n=fread(b,1,sizeof b,stdin); shz_cat_result_t r; shz_cat_ops_t o={0,0,0,0};
 int rc=shz_catalog_parse(b,n,&o,&r); printf("rc=%%d accepted=%%u rejected=%%u\n",rc,r.accepted,r.rejected);
 return rc==0 && r.rejected==0 && r.accepted==r.count ? 0 : 1; }
''' % SHZ
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "t.c").write_text(c)
    cc = subprocess.run(["cc", "-std=gnu11", "-Wall", "-DSHZ_CATALOG_HOST", f"-I{SHZ}/kernel64", "-o", f"{d}/t", f"{d}/t.c"],
                        capture_output=True, text=True, timeout=50)
    if cc.returncode:
        print(cc.stderr[-2000:]); sys.exit(2)
    r = subprocess.run([f"{d}/t"], input=txt, capture_output=True, text=True, timeout=30)
print(r.stdout.strip(), "rows:", [x["name"] for x in rows])
bad = {"ram", "virtio"} & {x["name"] for x in rows}
sys.exit(1 if r.returncode or bad else 0)
