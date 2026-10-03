# SPDX-License-Identifier: GPL-2.0-only
import importlib.util,io,json,os,struct,subprocess,tempfile,unittest
from pathlib import Path
s=importlib.util.spec_from_file_location('baseline_control',Path(__file__).with_name('control.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Controls(unittest.TestCase):
    def observed(self):
        return {'schema':'shizukuos.win98-baseline-observation.v1','nonce_hex':bytes(range(32)).hex(),'platform_id':1,'major':4,'minor':10,'build_raw':0xc00008ae,'scope':'Win9x4.10 and HKLM Enum Display Class/Driver only','devices':[{'enum_key':'Enum\\PCI\\VEN_1234','driver':'Display\\0000'}],'display_count':1,'observation_only':True,'source_approval':False,'Windows98_on_ShizukuDOS':False}
    def test_nonce_version_scope_and_devices(self):
        good=self.observed();self.assertEqual(m.report(json.dumps(good).encode(),bytes(range(32))),good)
        for key,value in [('nonce_hex','00'*32),('major',10),('platform_id',2),('minor',True),('source_approval',True),('Windows98_on_ShizukuDOS',True),('display_count',0),('devices',[]),('build_raw',-1),('scope','saved approval')]:
            bad={**good,key:value}
            with self.subTest(key=key),self.assertRaises(ValueError):m.report(json.dumps(bad).encode(),bytes(range(32)))
        for nonce in (bytes(32),bytes(31),'caller nonce'):
            with self.assertRaises(ValueError):m.report(json.dumps(good).encode(),nonce)
        good['devices']*=2;good['display_count']=2
        with self.assertRaises(ValueError):m.report(json.dumps(good).encode(),bytes(range(32)))
    def test_duplicate_json_refused(self):
        with self.assertRaises(ValueError):m.report(b'{"schema":1,"schema":2}',bytes(range(32)))
    def short(self):
        row=bytearray(32);row[:11]=b'BASEOB~1JSO';row[11]=32;struct.pack_into('<H',row,26,5);struct.pack_into('<I',row,28,100);return row
    def lfn(self,short):
        checksum=0
        for value in short[:11]:checksum=(((checksum&1)<<7)+(checksum>>1)+value)&255
        name='BASEOBS.JSON';words=[ord(x) for x in name]+[0];words+=([65535]*(13-len(words)))
        raw=struct.pack('<13H',*words);row=bytearray(32);row[0]=65;row[11]=15;row[13]=checksum;row[1:11]=raw[:10];row[14:26]=raw[10:22];row[28:32]=raw[22:];return row
    def root(self,data):
        with tempfile.TemporaryFile() as f:
            f.write(bytes(512)+data+bytes(512-len(data)));f.flush()
            g={'root_cluster':0,'fat_bits':16,'start_lba':0,'reserved':1,'fats':0,'fat_sectors':0,'root_sectors':1,'spc':1,'clusters':10,'first_data':3,'total_sectors':3}
            # Actual Volume requires its complete FAT geometry, including cached FAT bytes.
            g['fats']=1;g['fat_sectors']=1;g['root_sectors']=1
            f.seek(0);f.write(bytes(512)+b'\xf8'+bytes(511)+data+bytes(512-len(data)));f.flush()
            return m.root_entries(f.fileno(),g,lambda:None)
    def test_actual_vfat_report_name(self):
        row=self.short();result=self.root(self.lfn(row)+row)
        self.assertEqual(result['BASEOBS.JSON'],{'directory':False,'cluster':5,'bytes':100})
    def test_vfat_checksum_corruption_refused(self):
        row=self.short();lfn=self.lfn(row);lfn[13]^=1
        with self.assertRaises(ValueError):self.root(lfn+row)
    def test_stale_alias_and_duplicate_refused(self):
        row=self.short();self.assertIn('BASEOB~1.JSO',self.root(row))
        with self.assertRaises(ValueError):self.root(row+row)
    def test_actual_offline_mtools_fat12_and_fat32_report_readback(self):
        # Actual Linux file operations + actual mtools; no Windows/VM execution.
        for bits,sectors,kind in ((12,2048,1),(32,81920,12)):
            with self.subTest(bits=bits),tempfile.TemporaryDirectory(dir='/var/tmp',prefix='shz-baseline-fat-') as temp:
                root=Path(temp);disk=root/'fixture.raw'
                with disk.open('wb') as f:f.truncate((32+sectors)*512)
                subprocess.run(['mkfs.fat','-F',str(bits),'-s','1','-h','32','--offset=32',str(disk),str(sectors//2)],check=True,capture_output=True)
                mbr=bytearray(512);mbr[510:]=b'\x55\xaa';mbr[446]=128;mbr[450]=kind;struct.pack_into('<II',mbr,454,32,sectors)
                with disk.open('r+b') as f:f.write(mbr)
                keep=root/'KEEP.TXT';keep.write_bytes(b'original synthetic file')
                subprocess.run(['mcopy','-i',str(disk)+'@@16384',str(keep),'::KEEP.TXT'],check=True,capture_output=True)
                with disk.open('r+b') as f:
                    g=m.geometry(f.fileno(),disk.stat().st_size);before=m.replacement.inventory(f.fileno(),g)
                    nonce=bytes(range(32));original_boot=(os.pread(f.fileno(),512,0),os.pread(f.fileno(),512,16384))
                    for name,data in [('BASEOBS.EXE',b'MZ synthetic only'),('BASENONC.BIN',nonce),('BASEOBS.JSON',json.dumps(self.observed()).encode())]:
                        src=root/name;src.write_bytes(data)
                        subprocess.run(['mcopy','-i','/proc/self/fd/%d@@16384'%f.fileno(),str(src),'::'+name],executable=str(Path('/usr/bin/mcopy').resolve()),pass_fds=(f.fileno(),),env={**os.environ,'MTOOLSRC':'/dev/null'},check=True,capture_output=True)
                    after=m.replacement.inventory(f.fileno(),g)
                    self.assertEqual(after['KEEP.TXT'],before['KEEP.TXT'])
                    self.assertEqual(original_boot,(os.pread(f.fileno(),512,0),os.pread(f.fileno(),512,16384)))
                    actual=m.root_entries(f.fileno(),g,lambda:None)['BASEOBS.JSON'];raw=io.BytesIO()
                    m.replacement.Volume(f.fileno(),g).file(actual['cluster'],actual['bytes'],raw)
                    self.assertEqual(m.report(raw.getvalue(),nonce),self.observed())
    def test_actual_owned_linux_child_cleanup_on_monitor_failure(self):
        # Actual owned Popen/pidfd and signals; this is a Linux control, no VM.
        class BrokenMonitor:
            def call(self,*_):raise RuntimeError('modeled missing QMP')
        child=subprocess.Popen(['/usr/bin/sleep','60']);pidfd=os.pidfd_open(child.pid)
        try:
            m.reap(child,pidfd,BrokenMonitor())
            self.assertIsNotNone(child.returncode)
            self.assertEqual(child.wait(),child.returncode)
        finally:
            if child.poll() is None:child.kill();child.wait()
            os.close(pidfd)
    def test_invalid_request_never_launches(self):
        for seconds in (0,601,True,'600'):
            with self.assertRaises(ValueError):m.run({'schema':'shizukuos.private-baseline-control.v1','source':{},'observer':{},'observer_receipt':{},'qemu':{},'mcopy':{},'lock':'/no','output':'/no','guest_seconds':seconds})
if __name__=='__main__':unittest.main()
