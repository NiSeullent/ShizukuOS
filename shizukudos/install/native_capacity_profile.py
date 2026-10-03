#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Measured build-owned private load budget, never source/device authority."""
import native_release_admission as admission

MIB=1<<20
PROTOCOL_MAX=512*MIB
MAPPING_MAX=1024*MIB
_KEY=object()

class CapacityProfile:
    def __init__(self,key,custody):
        admission.require(key is _KEY and type(custody) is admission.BuildCustody,
                          'actual generator-held profile required')
        import private_installer_package as package
        self._custody=custody
        self._archive_pin=None
        self._pins={role:custody.pin(role) for role in ('manifest','sim','runtime')}
        layout,budget=package.measure_layout(custody)
        self.source_bytes=max(256*MIB,package.align(self._pins['sim']['bytes'],MIB))
        self.archive_bytes=max(64*MIB,package.align(budget['archive_bytes'],MIB))
        self.ram_bytes=max(256*MIB,package.align(32*MIB+self.archive_bytes+
                            budget['sealed_snapshot_bytes']+32*MIB,2*MIB))
        admission.require(self.source_bytes<=PROTOCOL_MAX and self.ram_bytes<=MAPPING_MAX and
                          32*MIB+self.archive_bytes<=self.ram_bytes,
                          'actual private inputs exceed bounded 1GiB boot mapping/load profile')
        self._dimensions=(self.source_bytes,self.archive_bytes,self.ram_bytes)
        self._budget=budget
        self._layout=layout
        self.check()

    def check(self):
        self._custody.check()
        admission.require((self.source_bytes,self.archive_bytes,self.ram_bytes)==self._dimensions,
                          "measured compiler profile changed")
        admission.require(all(self._custody.pin(role)==row for role,row in self._pins.items()),
                          'profile original source identity changed')

    def flags(self,efi=False):
        self.check()
        return [f'-DSHZ_PRIVATE_NATIVE_SOURCE_BYTES={self.source_bytes}ull',
                f'-DSHZ_PRIVATE_NATIVE_ARCHIVE_BYTES={self.archive_bytes}ull',
                f'-DSHZ_PRIVATE_NATIVE_RAM_BYTES={self.ram_bytes}ull',
                *(['-DSHZ_PRIVATE_NATIVE_EFI_LOAD'] if efi else [])]

    def marker(self):
        self.check()
        return (f"SHZ-PRIVATE-NATIVE-LOAD:v1:{self.source_bytes}ull:"
                f"{self.archive_bytes}ull:{self.ram_bytes}ull").encode("ascii")

    def record(self):
        self.check()
        return {'schema':'MEASURED_PRIVATE_LOAD_BUDGET_NOT_AUTHORITY',
                'source_limit_bytes':self.source_bytes,'archive_limit_bytes':self.archive_bytes,
                'ram_limit_bytes':self.ram_bytes,'mapping_limit_bytes':MAPPING_MAX,
                'actual_layout':self._budget,'firmware_memory_map_verified':False,
                'Windows98_boot_verified':False}


def from_admitted_custody(custody):
    return CapacityProfile(_KEY,custody)
