# SPDX-License-Identifier: GPL-2.0-only
"""Actual tiny input leases/copies; compilation/ESP/capacity explicitly modeled.

No compiler, large private disk, NAS, QEMU or Windows is used by these controls.
"""
import contextlib,fcntl,hashlib,importlib.util,io,json,os
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('input_lifetime_builder',HERE/'build.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)

def fixture_worker_capacity_command(real_command):
    """Test-only child capacity model; frozen worker bytes/format checks stay real."""
    def command(argv,*args,**kwargs):
        argv=list(argv)
        marker="exec(compile(body,name,'exec'),g)"
        if os.environ.get('SHZ_NATIVE_INPUT_TEST_ROOT') and '-c' in argv:
            index=argv.index('-c')+1
            if marker in str(argv[index]):
                # Reuse ActualSparseAssembly's test-only bootstrap prepend.
                # The held worker's byte pin, namespace and main remain intact.
                model="""import os,pathlib,shutil
real_usage=shutil.disk_usage
def modeled_usage(path):
 lane=pathlib.Path(os.environ['SHZ_NATIVE_INPUT_TEST_ROOT']).resolve();target=pathlib.Path(path).resolve()
 assert target==lane or lane in target.parents
 actual=real_usage(target);mem=int(next(s.split()[1] for s in pathlib.Path('/proc/meminfo').read_text().splitlines() if s.startswith('MemAvailable:')))*1024
 assert actual.free>=(6<<30)+(160<<20) and mem>=(6<<30)+(160<<20)
 assert sum(p.stat().st_blocks*512 for p in lane.rglob('*') if p.is_file())<=64<<20
 return shutil._ntuple_diskusage(actual.total+(17<<30),actual.used,actual.free+(17<<30))
shutil.disk_usage=modeled_usage
"""
                argv[index]=model+str(argv[index])
        return real_command(argv,*args,**kwargs)
    return command

class LifetimeTests(unittest.TestCase):
    def fixture(self,compile_hook=lambda *_:None,assemble_hook=lambda *_:None,sink=None,validate_only=False):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);(root/'build').mkdir()
        data={'disk':bytes(510)+b'\x55\xaa'+bytes((512<<10)-512),'rom':bytearray(B.ROM_BYTES),'config':B.config_bytes(),'kernel32':b'HOST_K32_NOT_EXECUTABLE','kernel64':b'HOST_K64_NOT_EXECUTABLE','win64-img':b'HOST_ARCHIVE_NOT_EXECUTABLE'}
        data['rom'][:7]=b'SeaBIOS';data['rom'][-16]=0xea
        (root/'inputs').mkdir();files={};args=[]
        for name,raw in data.items():
            path=root/'inputs'/name;path.write_bytes(raw);files[name]=path
            args+=['--'+name,str(path),'--'+name+'-sha256',hashlib.sha256(raw).hexdigest()]
        source=root/'shizukudos/supervisor/native_win98/compile.py';source.parent.mkdir(parents=True);source.write_text('# HOST MODELED COMPILE; NEVER EXECUTED\n')
        out=root/'build/owned';args+=['--validate-only'] if validate_only else ['--out',str(out)]
        def compile_model(argv,receipt,**kwargs):
            self.assertEqual(kwargs['timeout'],300);compile_hook(files,out)
            components=Path(argv[-1]);components.mkdir();loader=components/'BOOTX64.EFI';loader.write_bytes(b'HOST_MODELED_EFI_NOT_EXECUTABLE')
            (components/'result.json').write_text(json.dumps({'status':'PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN','artifacts':{'BOOTX64.EFI':{'sha256':B.file_sha(loader)}}}))
        def assemble_model(output,copies,loader,receipt):
            assemble_hook(files,out);esp=out/'esp.img';esp.write_bytes(b'HOST_MODELED_ESP_NOT_BOOTABLE');return esp,{}
        error=None
        stdout=io.StringIO()
        with patch.object(B,'ROOT',root),patch.object(B,'DISK_BYTES',512<<10),patch.object(B,'source_files',return_value=[source]),patch.object(B,'space'),patch.object(B,'command',compile_model),patch.object(B,'assemble',assemble_model),contextlib.redirect_stdout(stdout):
            try:B.main(args,receipt_sink=sink)
            except BaseException as caught:error=caught
        self.last_stdout=stdout.getvalue();return files,out,error
    def test_actual_earlier_disk_writer_is_blocked_during_build_after_copy(self):
        observed={};sink=[]
        def writer(files,out):
            self.assertTrue((out/'DISK.IMG').is_file())
            try:fd=os.open(files['disk'],os.O_WRONLY|os.O_NONBLOCK)
            except BlockingIOError:observed['blocked']=True
            else:os.close(fd);observed['blocked']=False
        files,out,error=self.fixture(writer,sink=sink.append)
        self.assertTrue(observed['blocked'],'earlier copied original must remain actually read-leased during build')
        self.assertIsInstance(error,RuntimeError);self.assertFalse(sink)
        self.assertEqual(json.loads((out/'result.json').read_text())['status'],'FAIL_BUILD_PRESERVED')
        self.assertEqual(files['disk'].read_bytes(),(out/'DISK.IMG').read_bytes())
    def test_all_six_original_leases_remain_live_through_assemble(self):
        observed=[]
        def check(files,out):
            found=set()
            ids={(p.stat().st_dev,p.stat().st_ino) for p in files.values()}
            for name in os.listdir('/proc/self/fd'):
                try:
                    fd=int(name);info=os.fstat(fd)
                    if (info.st_dev,info.st_ino) in ids and fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_RDLCK:found.add((info.st_dev,info.st_ino))
                except OSError:pass
            observed.append(len(found))
        files,out,error=self.fixture(check,check)
        self.assertIsNone(error);self.assertEqual(observed,[6,6])
        self.assertFalse(json.loads((out/'result.json').read_text())['Windows98_boot_verified'])
    def test_originals_are_opened_once_without_unleased_validation_reopens(self):
        opened=[];real=os.open
        def traced(path,*args,**kwargs):
            if isinstance(path,(str,Path)):opened.append(str(path))
            return real(path,*args,**kwargs)
        with patch.object(B.os,'open',traced):files,out,error=self.fixture()
        self.assertIsNone(error)
        self.assertEqual({name:opened.count(str(path)) for name,path in files.items()},{name:1 for name in files})
    def test_original_break_propagates_through_nested_helper_handler(self):
        sink=[]
        def nested(files,out):
            helper=out/'helper.py';helper.write_bytes(b'HOST_HELPER_NOT_EXECUTED')
            with B.read_leased(helper,B.file_sha(helper),helper.stat().st_size):
                with self.assertRaises(BlockingIOError):os.open(files['disk'],os.O_WRONLY|os.O_NONBLOCK)
        files,out,error=self.fixture(assemble_hook=nested,sink=sink.append)
        self.assertIsInstance(error,RuntimeError);self.assertFalse(sink)
        self.assertEqual(json.loads((out/'result.json').read_text())['status'],'FAIL_BUILD_PRESERVED')
        for path in files.values():
            fd=os.open(path,os.O_WRONLY|os.O_NONBLOCK);os.close(fd)
    def test_late_real_fd_close_failure_closes_all_originals_and_vetoes_sink(self):
        sink=[];closed=[];real=os.close;failed=[False]
        def close(fd):
            try:path=os.readlink('/proc/self/fd/%d'%fd)
            except OSError:path=''
            real(fd)
            if path.rsplit('/',1)[-1] in ('disk','rom','config','kernel32','kernel64','win64-img'):
                closed.append(path)
                if path.endswith('/win64-img') and not failed[0]:failed[0]=True;raise OSError('host modeled close failure after actual FD close')
        with patch.object(B.os,'close',close):files,out,error=self.fixture(sink=sink.append)
        self.assertIsInstance(error,OSError);self.assertTrue(failed[0]);self.assertFalse(sink)
        self.assertEqual(set(closed),{str(path) for path in files.values()})
        self.assertEqual(json.loads((out/'result.json').read_text())['status'],'FAIL_BUILD_PRESERVED')
        for path in files.values():
            fd=os.open(path,os.O_WRONLY|os.O_NONBLOCK);os.close(fd)
    def test_validate_only_close_failure_never_prints_success(self):
        real=os.close;failed=[False]
        def close(fd):
            try:path=os.readlink('/proc/self/fd/%d'%fd)
            except OSError:path=''
            real(fd)
            if path.endswith('/win64-img') and not failed[0]:failed[0]=True;raise OSError('host modeled validation close failure')
        with patch.object(B.os,'close',close):files,out,error=self.fixture(validate_only=True)
        self.assertIsInstance(error,OSError);self.assertFalse(out.exists());self.assertEqual(self.last_stdout,'')
    def test_original_path_replacement_after_copy_vetoes_final_acceptance(self):
        sink=[]
        def replace(files,out):
            original=files['disk'];original.rename(original.with_name('private-saved-fixture'));original.write_bytes(b'HOST_CHANGED_PATH')
        files,out,error=self.fixture(assemble_hook=replace,sink=sink.append)
        self.assertIsInstance(error,RuntimeError);self.assertFalse(sink)
        self.assertEqual(json.loads((out/'result.json').read_text())['status'],'FAIL_BUILD_PRESERVED')
    def test_same_inode_via_new_symlink_parent_is_refused_after_copy(self):
        sink=[]
        def alias(files,out):
            parent=files['disk'].parent;saved=parent.with_name('saved-inputs');parent.rename(saved);parent.symlink_to(saved,target_is_directory=True)
        files,out,error=self.fixture(assemble_hook=alias,sink=sink.append)
        self.assertIsInstance(error,(ValueError,RuntimeError));self.assertFalse(sink)
        self.assertEqual(json.loads((out/'result.json').read_text())['status'],'FAIL_BUILD_PRESERVED')

if __name__=='__main__':unittest.main(verbosity=2)
