# SPDX-License-Identifier: GPL-2.0-only
"""Strict archive/ROM/real Linux read-lease controls; no VM/device authority."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('stdvga_producer',Path(__file__).resolve().parents[1]/'build_stdvga_rom.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

def archive(entries):
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w') as t:
        for name,data,mode,kind in entries:
            item=tarfile.TarInfo(name);item.mode=mode;item.type=kind;item.size=len(data)
            t.addfile(item,io.BytesIO(data))
    return raw.getvalue()
def blob(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def rom():
    raw=bytearray(512);raw[:3]=b'\x55\xaa\x01';struct.pack_into('<H',raw,24,32);raw[32:36]=b'PCIR'
    struct.pack_into('<HH',raw,36,0x1234,0x1111);struct.pack_into('<H',raw,42,24)
    raw[47]=3;struct.pack_into('<H',raw,48,1);raw[53]=128;raw[-1]=(-sum(raw))&255
    return bytes(raw)

class SourceROMControls(unittest.TestCase):
    def test_exact_immutable_archive_files_and_modes(self):
        data=b'actual captured source bytes';tree={'src/main.c':('100644',blob(data))}
        self.assertEqual(p.archive_files(archive([('src/main.c',data,0o644,tarfile.REGTYPE)]),tree),{'src/main.c':(data,0o644)})
    def test_traversal_symlink_duplicate_extra_mode_and_blob_refuse(self):
        data=b'bytes';tree={'src/main.c':('100644',blob(data))}
        cases=[[('../escape',data,0o644,tarfile.REGTYPE)],[('src/main.c',data,0o644,tarfile.SYMTYPE)],
               [('src/main.c',data,0o644,tarfile.REGTYPE)]*2,[('extra',data,0o644,tarfile.REGTYPE)],
               [('src/main.c',data,0o777,tarfile.REGTYPE)],[('src/main.c',b'changed',0o644,tarfile.REGTYPE)],[]]
        for rows in cases:
            with self.subTest(rows=rows),self.assertRaises(ValueError):p.archive_files(archive(rows),tree)
    def test_exact_stdvga_x86_pcir_checksum(self):
        self.assertEqual(p.rom_metadata(rom()),{'vendor_id':0x1234,'device_id':0x1111,'image_bytes':512,'code_type':0,'last_image':128})
    def test_rom_wrong_extent_vendor_class_code_lastimage_checksum_refuse(self):
        for offset in (0,2,24,36,47,48,52,53,511):
            raw=bytearray(rom());raw[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(ValueError):p.rom_metadata(bytes(raw))
        with self.assertRaises(ValueError):p.rom_metadata(rom()+bytes(512))
    def test_actual_readonly_lease_and_late_hash_or_namespace_drift(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as directory:
            source=Path(directory)/'input';source.write_bytes(b'original');lease=p.Leases()
            try:
                lease.add(p.pin(source));lease.verify_all()
                row=lease.rows[str(source)];self.assertEqual(p.fcntl.fcntl(row['fd'],p.fcntl.F_GETLEASE),p.fcntl.F_RDLCK)
                source.rename(source.with_name('moved'))
                source.write_bytes(b'replaced')
                with self.assertRaises(ValueError):lease.check()
            finally:lease.close()
    def test_symlink_source_refused(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as directory:
            source=Path(directory)/'input';source.write_bytes(b'original');link=Path(directory)/'link';link.symlink_to(source)
            with self.assertRaises(ValueError):p.pin(link)

if __name__=='__main__':unittest.main()
