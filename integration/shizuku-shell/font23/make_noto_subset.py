#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only. Recipe (NOT RUN here: fontTools absent, no installs allowed).
# Produces genuine-outline static wght=400 subsets; run later on NAS. Inputs are READ-ONLY system fonts.
import sys, hashlib
from fontTools.ttLib import TTFont, TTCollection
from fontTools.varLib.instancer import instantiateVariableFont
from fontTools import subset
LAT = ("/usr/share/fonts/google-noto-vf/NotoSans[wght].ttf", "8b23d6341a12454e68e35c2c0917f0504104ded6aa3024d18e9d462da06fadd3")
KR = ("/usr/share/fonts/google-noto-sans-cjk-vf-fonts/NotoSansCJK-VF.ttc", "d3d8256cdec8dbcb3552284bc6b20c734dd60c2ee9df83b5758e34807c4bac32")
UNI = (list(range(0x20, 0x7F)) + list(range(0xA0, 0x180)) + list(range(0x1100, 0x1200)) + list(range(0x3000, 0x3040)) +
       list(range(0x3131, 0x318F)) + list(range(0xAC00, 0xD7A4)) + list(range(0x2010, 0x2030)) + [0xFFFD, 0x20A9])
def sub(font, out):
    opt = subset.Options(); opt.layout_features = ["kern", "liga", "ccmp", "locl"]; opt.notdef_outline = True
    opt.name_IDs = ["*"]; opt.legacy_kern = True
    s = subset.Subsetter(opt); s.populate(unicodes=UNI); s.subset(font); font.save(out)
def main(outdir):
    for (path, sha) in (LAT, KR):
        if hashlib.sha256(open(path, "rb").read()).hexdigest() != sha: sys.exit("source hash mismatch " + path)
    f = TTFont(LAT[0]); f = instantiateVariableFont(f, {"wght": 400}); sub(f, outdir + "/NotoSans.ttf")
    c = TTCollection(KR[0]); f = instantiateVariableFont(c.fonts[1], {"wght": 400}); sub(f, outdir + "/NotoSansKR.otf")
    # then: verify family names, OFL text hash, size <= 16MiB archive; keep OFL.txt beside the fonts.
main(sys.argv[1])
