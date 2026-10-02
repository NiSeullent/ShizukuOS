#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native K32 provider source list; explicit gate, never launches a VM here."""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[2]
def native_provider():
    return {'entry':str(ROOT/'shizukudos/kernel64/standalone/boot_pm.asm'),
        'wrapper':str(ROOT/'shizukudos/kernel32/standalone/native_boot32.c'),
        'linker':str(ROOT/'shizukudos/kernel64/standalone/boot.ld'),
        'opt_in':['shz.k32-ap=2','shz.k32-ap=4'], 'native_guest_accepted':False,
        'supervisor_virtual_ap_accepted':False,'windows_vcpus':1}
if __name__=='__main__':print(json.dumps(native_provider(),indent=2))
