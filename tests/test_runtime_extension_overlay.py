"""Real PE tables, source-bound extension plans and private wrapper restoration.

No candidate DLL, repository compiler recipe or VM is executed by these tests.
The minimal PE fixture contains real EAT/ILT/IAT/relocation data. A separately
pinned real candidate is also checked when its local receipt is available.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("extension_overlay_test", ROOT / "tools/runtime_extension_overlay.py")
extension = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extension)
theme, handoff = extension.theme, extension.handoff


def dll(exports, imports=(), identity="KERNELBASE.DLL"):
    """An actual bounded AMD64 DLL with named/ordinal EAT and named imports."""
    raw = bytearray(8192)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 60, 128)
    raw[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", raw, 132, 0x8664, 1, 0, 0, 0, 240, 0x2102)
    struct.pack_into("<H", raw, 152, 0x20B)
    struct.pack_into("<I", raw, 168, 0x1700)
    struct.pack_into("<Q", raw, 176, 0x180000000)
    struct.pack_into("<II", raw, 184, 4096, 512)
    struct.pack_into("<HH", raw, 192, 6, 0)
    struct.pack_into("<HH", raw, 200, 6, 0)
    struct.pack_into("<II", raw, 208, 12288, 512)
    struct.pack_into("<H", raw, 220, 2)
    struct.pack_into("<I", raw, 260, 16)
    raw[392:400] = b".text\0\0\0"
    struct.pack_into("<IIII", raw, 400, 7680, 4096, 7680, 512)
    struct.pack_into("<I", raw, 428, 0x60000020)
    def at(rva):
        return rva - 4096 + 512
    def text(rva, value):
        data = value.encode("ascii") + b"\0"
        raw[at(rva):at(rva)+len(data)] = data
    first, last = min(row[1] for row in exports), max(row[1] for row in exports)
    named = [row for row in exports if row[0] is not None]
    struct.pack_into("<II", raw, 264, 0x1000, 0x700)
    struct.pack_into("<IIHHIIIIIII", raw, at(0x1000), 0, 0, 0, 0, 0x12C0,
                     first, last-first+1, len(named), 0x1080, 0x1200, 0x1280)
    text(0x12C0, identity)
    cursor=0x1300
    for name, ordinal, forwarded in exports:
        target=0x1700
        if forwarded is not None:
            target=cursor;text(cursor,forwarded);cursor+=len(forwarded)+1
        struct.pack_into("<I",raw,at(0x1080)+(ordinal-first)*4,target)
    for index,(name,ordinal,_) in enumerate(named):
        struct.pack_into("<I",raw,at(0x1200)+index*4,cursor)
        struct.pack_into("<H",raw,at(0x1280)+index*2,ordinal-first)
        text(cursor,name);cursor+=len(name)+1
    if cursor >= 0x1700:
        raise ValueError("fixture export strings overflow")
    raw[at(0x1700):at(0x1700)+8] = b"\xc3\x90\x90\x90\x90\x90\x90\x90"
    if imports:
        struct.pack_into("<II",raw,272,0x1800,40)
        struct.pack_into("<5I",raw,at(0x1800),0x1880,0,0,0x1A00,0x1900)
        text(0x1A00,"KERNEL32.DLL")
        cursor=0x1B00
        for index,name in enumerate(imports):
            struct.pack_into("<H",raw,at(cursor),0);text(cursor+2,name)
            struct.pack_into("<Q",raw,at(0x1880)+index*8,cursor)
            struct.pack_into("<Q",raw,at(0x1900)+index*8,cursor)
            cursor+=len(name)+3
    struct.pack_into("<II",raw,304,0x2D00,12)
    struct.pack_into("<IIHH",raw,at(0x2D00),0x1000,12,0xA700,0)
    return bytes(raw)


def base_files():
    names=sorted(extension.IMPORTS)
    return [("\\SHZ\\SYS64\\kernel32.dll",dll([(name,i+1,None) for i,name in enumerate(names)],identity="KERNEL32.DLL")),
            (theme.THEME_PATH,dll([("Paint",1,None)],identity="UXTHEME.DLL")),
            ("\\SHZ\\DATA\\asset.bin",b"all baseline member bytes remain identical")]


def candidate(forward=None):
    rows=[(name,i+1,None) for i,name in enumerate(sorted(extension.ADAPTERS))]
    rows += [(name,i+4,(forward or {}).get(name,"KERNEL32."+name)) for i,name in enumerate(sorted(extension.IMPORTS))]
    return dll(rows,sorted(extension.IMPORTS))


class StaticPE(unittest.TestCase):
    def test_actual_pe_tables_and_real_graph(self):
        gate=extension.candidate_gate(base_files(),candidate())
        self.assertEqual(len(gate["imports"]),9)
        self.assertEqual(len(gate["forwarders"]),9)
        self.assertFalse(gate["abi_semantics_verified"])
        self.assertEqual(set(gate["candidate_pe_gate"]["exports"]),extension.ADAPTERS | extension.IMPORTS)

    def test_architecture_entry_and_relocations_rejected(self):
        for offset,fmt,value in ((132,"<H",0x14C),(168,"<I",0),(304,"<I",0),(220,"<H",3)):
            raw=bytearray(candidate());struct.pack_into(fmt,raw,offset,value)
            with self.subTest(offset=offset),self.assertRaises((ValueError,theme.ThemeRuntimeError)):
                extension.actual_pe_gate(bytes(raw))

    def test_unexpected_tls_and_delay_directories(self):
        for index in (9,10,13,14):
            raw=bytearray(candidate());struct.pack_into("<II",raw,264+index*8,0x2C00,16)
            with self.subTest(index=index),self.assertRaises(ValueError):
                extension.actual_pe_gate(bytes(raw))

    def test_wrong_dll_identity(self):
        rows=[(name,i+1,None) for i,name in enumerate(sorted(extension.ADAPTERS))]
        with self.assertRaisesRegex(ValueError,"DLL identity"):
            extension.actual_pe_gate(dll(rows,sorted(extension.IMPORTS),identity="OTHER.DLL"))

    def test_non_executable_adapter_code(self):
        raw=bytearray(candidate());struct.pack_into("<I",raw,428,0x40000040)
        with self.assertRaisesRegex(ValueError,"executable bytes"):
            extension.actual_pe_gate(bytes(raw))

    def test_forwarder_cycle_and_missing_target(self):
        name=sorted(extension.IMPORTS)[0]
        for target,reason in (("KERNELBASE."+name,"cyclic"),("KERNEL32.NotPresent","missing archive export")):
            with self.subTest(target=target),self.assertRaisesRegex(theme.ThemeRuntimeError,reason):
                extension.candidate_gate(base_files(),candidate({name:target}))

    def test_adapter_cannot_be_a_forwarder(self):
        rows=[(name,i+1,"KERNEL32.GetLastError") for i,name in enumerate(sorted(extension.ADAPTERS))]
        with self.assertRaisesRegex(ValueError,"actual implementation"):
            extension.actual_pe_gate(dll(rows,sorted(extension.IMPORTS)))

    def test_existing_kernelbase_and_case_alias_rejected(self):
        with self.assertRaisesRegex(ValueError,"already has KERNELBASE"):
            extension.candidate_gate(base_files()+[("\\SHZ\\SYS64\\kernelbase.dll",candidate())],candidate())

    def test_all_imports_must_be_actual_direct_owner_names(self):
        files=base_files();name=sorted(extension.IMPORTS)[0]
        owner=[(n,i+1,"UXTHEME.Paint" if n==name else None) for i,n in enumerate(sorted(extension.IMPORTS))]
        files[0]=(files[0][0],dll(owner,identity="KERNEL32.DLL"))
        with self.assertRaisesRegex(ValueError,"direct Kernel32"):
            extension.candidate_gate(files,candidate())


class BoundPlan(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.build=self.root/"build";self.build.mkdir()
        self.output=self.build/"extension-v1";self.provider=self.root/"provider";self.provider.mkdir()
        source_names=["LICENSE",extension.BUILDER,"ntwddm/win64/memory_bridge/bridge.c","ntwddm/win64/memory_bridge/bridge.h"]
        for name in source_names:
            p=self.provider/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text("frozen source: "+name)
        self.peer=self.root/"peer";p=self.peer/"shizukudos/kernel64/vad.c";p.parent.mkdir(parents=True);p.write_text("reviewed source; binary identity is not proven")
        self.archive=self.build/"base-WIN64.IMG";self.archive.write_bytes(theme.pack_archive(base_files()))
        self.base_path=self.build/"theme-overlay.json";self.base_path.write_text("{\"bound_theme\":true}\n")
        self.base={"runtime_worktree":str(self.peer),"runtime_source_hashes":{"runtime.py":"0"*64},
                   "archive":{"path":str(self.archive),"sha256":handoff.digest_file(self.archive)}}
        self.artifact=self.provider/"KERNELBASE.DLL";self.artifact.write_bytes(candidate())
        pe_gate=extension.actual_pe_gate(self.artifact.read_bytes())
        self.definition=self.provider/"kernelbase.def";self.definition.write_bytes(extension.definition_bytes(pe_gate["exports"]))
        frozen=self.provider/"compiler";frozen.mkdir()
        compiler=[]
        for name in ("bridge.c","bridge.h"):
            p=frozen/name;p.write_bytes((self.provider/"ntwddm/win64/memory_bridge"/name).read_bytes())
            compiler.append({"path":str(p),"sha256":handoff.digest_file(p)})
        compiler.append({"path":str(self.definition),"sha256":handoff.digest_file(self.definition)})
        modules=theme.archive_modules(base_files())
        actual_modules={name:{"member":row["archive_path"],"sha256":row["sha256"],
                              "bytes":len(dict(base_files())[row["archive_path"]]),"exports":row["names"]} for name,row in modules.items()}
        self.record={"schema":1,"status":"STATIC_CANDIDATE_READY_FOR_GUEST_TEST","structural_build_status":"PASS",
                     "source_root":str(self.provider),"source_hashes":{name:handoff.digest_file(self.provider/name) for name in source_names},
                     "artifact":{"path":str(self.artifact),"bytes":self.artifact.stat().st_size,"sha256":handoff.digest_file(self.artifact),"pe_gate":pe_gate},
                     "supported_subset":{name:"explicit basic subset" for name in extension.ADAPTERS | {"unsupported","ownership"}},
                     "generated_definition":{"path":str(self.definition),"sha256":handoff.digest_file(self.definition)},"compiler_inputs":compiler,
                     "forwarder_coverage":{"targets":{n:r["forwarder"] for n,r in pe_gate["exports"].items() if r["forwarder"]}},
                     "runtime_archive":{"path":str(self.archive),"sha256":handoff.digest_file(self.archive),"member_count":3,"dll_count":2,"modules":actual_modules},
                     "reviewed_consumer_sources":{"root":str(self.peer),"hashes":{"shizukudos/kernel64/vad.c":handoff.digest_file(self.peer/"shizukudos/kernel64/vad.c")},
                         "originals_unchanged":True,"binary_source_identity_verified":False}}
        self.receipt=self.provider/"result.json";self.rewrite()
        patchers=[patch.object(theme,"OWN_BUILD",self.build),patch.object(theme,"verified_overlay",return_value=self.base),patch.object(handoff,"check_space")]
        for patcher in patchers:
            value=patcher.start();self.addCleanup(patcher.stop)
            if patcher.attribute=="check_space":self.space=value
        self.runner=SimpleNamespace(WIN64=self.root/"original-runtime")
        self.productivity=SimpleNamespace(runner=self.runner)
        patcher=patch.object(handoff,"load_peer",return_value=(self.productivity,self.base["runtime_source_hashes"]))
        self.loader=patcher.start();self.addCleanup(patcher.stop)
        self.image=self.build/"image-receipt.json";self.image.write_text(json.dumps({"app":"signal","runtime_worktree":str(self.peer),"runtime_source_hashes":self.base["runtime_source_hashes"]}))

    def rewrite(self):
        self.receipt.write_text(json.dumps(self.record));self.receipt_sha=handoff.digest_file(self.receipt)

    def prepare(self):
        return extension.prepare(self.base_path,handoff.digest_file(self.base_path),self.receipt,self.receipt_sha,self.output)

    def test_private_append_and_source_lineage(self):
        original=self.archive.read_bytes();record=self.prepare()
        self.assertEqual(self.archive.read_bytes(),original)
        self.assertEqual(theme.parse_archive((self.output/"WIN64.IMG").read_bytes())[:-1],base_files())
        self.assertEqual(extension.verified(self.output/"extension-overlay.json"),record)
        self.assertTrue((self.output/"extension-compiler-inputs/bridge.c").exists())
        self.assertFalse(record["vm_started"]);self.assertFalse(record["modern_memory_semantics_verified"])
        self.space.assert_called()

    def test_receipt_hash_and_claimed_pe_table_bound_to_actual_bytes(self):
        self.record["artifact"]["pe_gate"]["exports"]["VirtualAlloc2"]["rva"]+=1;self.rewrite()
        with self.assertRaisesRegex(ValueError,"PE gate differs"):
            self.prepare()
        self.assertFalse(self.output.exists())
        with self.assertRaisesRegex(ValueError,"receipt digest changed"):
            extension.extension_inputs(self.receipt,"0"*64)

    def test_changed_source_header_or_frozen_compiler_copy(self):
        p=Path(self.record["compiler_inputs"][1]["path"]);p.write_text("changed frozen header")
        with self.assertRaisesRegex(ValueError,"compiler input changed"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_wrong_generated_definition_even_with_updated_digest(self):
        self.definition.write_bytes(self.definition.read_bytes().replace(b"KERNEL32.GetLastError",b"KERNEL32.Other"))
        value=handoff.digest_file(self.definition);self.record["generated_definition"]["sha256"]=value
        self.record["compiler_inputs"][2]["sha256"]=value;self.rewrite()
        with self.assertRaisesRegex(ValueError,"definition differs"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_wrong_actual_archive_binding(self):
        self.record["runtime_archive"]["sha256"]="0"*64;self.rewrite()
        with self.assertRaisesRegex(ValueError,"exact selected"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_wrong_actual_archive_module_table(self):
        self.record["runtime_archive"]["modules"]["KERNEL32.DLL"]["sha256"]="0"*64;self.rewrite()
        with self.assertRaisesRegex(ValueError,"archive modules differ"):
            self.prepare()

    def test_source_inspection_cannot_claim_binary_identity(self):
        self.record["reviewed_consumer_sources"]["binary_source_identity_verified"]=True;self.rewrite()
        with self.assertRaisesRegex(ValueError,"separate source inspection"):
            self.prepare()

    def test_output_ownership_and_existing_directory(self):
        with self.assertRaisesRegex(theme.ThemeRuntimeError,"beneath this worktree"):
            extension.prepare(self.base_path,handoff.digest_file(self.base_path),self.receipt,self.receipt_sha,self.root/"outside")
        self.output.mkdir()
        with self.assertRaisesRegex(theme.ThemeRuntimeError,"new owned"):
            self.prepare()

    def test_frozen_lineage_and_bytes_cannot_be_substituted(self):
        self.prepare();path=self.output/"extension-overlay.json"
        r=json.loads(path.read_text());r["frozen_inputs"][0]["source_path"]=str(self.provider/"other")
        path.write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,"input lineage changed"):
            extension.verified(path)

    def test_changed_derived_bytes_fail(self):
        self.prepare();p=self.output/"WIN64.IMG";raw=bytearray(p.read_bytes());raw[-1]^=1;p.chmod(0o600);p.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,"archive bytes changed"):
            extension.verified(self.output/"extension-overlay.json")

    def fake_run(self,image,out,qemu,accel,timeout,memory,firmware,mode="normal"):
        productivity,_=handoff.load_peer(self.peer)
        self.assertEqual(productivity.runner.WIN64,self.output)
        out.mkdir();private=out/"runtime-inputs";private.mkdir();derived=private/"WIN64.IMG"
        shutil.copyfile(self.output/"WIN64.IMG",derived)
        row={"source_path":str(self.output/"WIN64.IMG"),"path":str(derived),"sha256":handoff.digest_file(derived),"bytes":derived.stat().st_size}
        if mode=="outside_seal":row["path"]=str(self.output/"WIN64.IMG")
        seal=out/"runtime-seal.json"
        seal.write_text("{" if mode=="bad_seal" else json.dumps({"sealed_runtime_input_hashes":{"win64_initrd":row}}))
        if mode=="raise":raise RuntimeError("owned handoff failure")
        return 0

    def wrapper(self,mode):
        self.prepare();out=self.build/("run-"+mode)
        original=self.runner.WIN64
        with patch.object(handoff,"run_image",side_effect=lambda *args:self.fake_run(*args,mode=mode)):
            code=extension.run(self.output/"extension-overlay.json",self.image,out,Path("/usr/libexec/qemu-kvm"),"kvm",90,4096,[])
        self.assertIs(handoff.load_peer,self.loader);self.assertEqual(self.runner.WIN64,original)
        return code,json.loads((out/"extension-runtime-result.json").read_text())

    def test_wrapper_restores_globals_and_never_promotes_startup_to_functionality(self):
        code,r=self.wrapper("normal")
        self.assertEqual(code,0);self.assertEqual(r["status"],"FAIL")
        self.assertTrue(r["sealed_extension_runtime_input_verified"]);self.assertTrue(r["overlay_inputs_preserved"])
        self.assertFalse(r["app_functionality_verified"]);self.assertFalse(r["windows98_execution_verified"])

    def test_wrapper_retains_original_exception_and_restores_globals(self):
        code,r=self.wrapper("raise")
        self.assertEqual(code,2);self.assertEqual(r["handoff_error"],"owned handoff failure")

    def test_malformed_seal_does_not_mask_failure_or_leak_globals(self):
        code,r=self.wrapper("bad_seal")
        self.assertEqual(code,2);self.assertFalse(r["sealed_extension_runtime_input_verified"])
        self.assertIsNotNone(r["preservation_error"])

    def test_seal_must_point_to_exact_owned_copy(self):
        code,r=self.wrapper("outside_seal")
        self.assertEqual(code,2);self.assertFalse(r["sealed_extension_runtime_input_verified"])

    def test_changed_image_receipt_is_retained_as_a_preservation_failure(self):
        self.prepare();out=self.build/"run-image-change";before=handoff.digest_file(self.image)
        def changed(*args):
            self.fake_run(*args)
            self.image.write_text("{\"changed\":true}")
            return 0
        with patch.object(handoff,"run_image",side_effect=changed):
            code=extension.run(self.output/"extension-overlay.json",self.image,out,Path("/usr/libexec/qemu-kvm"),"kvm",90,4096,[])
        r=json.loads((out/"extension-runtime-result.json").read_text())
        self.assertEqual(code,2);self.assertFalse(r["overlay_inputs_preserved"])
        self.assertEqual(r["required_app_image_receipt"]["sha256"],before)
        self.assertIs(handoff.load_peer,self.loader)

    def test_preflight_failure_still_restores_loader(self):
        self.prepare();out=self.build/"run-preflight-failure"
        with patch.object(handoff,"run_image",side_effect=ValueError("preflight blocked")):
            with self.assertRaisesRegex(ValueError,"preflight blocked"):
                extension.run(self.output/"extension-overlay.json",self.image,out,Path("/usr/libexec/qemu-kvm"),"kvm",90,4096,[])
        self.assertIs(handoff.load_peer,self.loader);self.assertFalse(out.exists())

    def test_unexpected_second_runner_cannot_leave_first_redirected(self):
        self.prepare();out=self.build/"run-second-module";other=SimpleNamespace(WIN64=self.root/"other-runtime")
        first=self.runner.WIN64;second=other.WIN64
        self.loader.side_effect=[(self.productivity,self.base["runtime_source_hashes"]),
                                 (SimpleNamespace(runner=other),self.base["runtime_source_hashes"])]
        def mismatched(*args):
            out.mkdir()
            handoff.load_peer(self.peer);handoff.load_peer(self.peer)
        with patch.object(handoff,"run_image",side_effect=mismatched):
            code=extension.run(self.output/"extension-overlay.json",self.image,out,Path("/usr/libexec/qemu-kvm"),"kvm",90,4096,[])
        self.assertEqual(code,2);self.assertEqual(self.runner.WIN64,first);self.assertEqual(other.WIN64,second)
        self.assertIs(handoff.load_peer,self.loader)


class RealCandidate(unittest.TestCase):
    def test_pinned_actual_594_export_candidate(self):
        p=ROOT/"ntwddm/win64/memory_bridge/build/20261001T085541Z-9876aa10/result.json"
        if not p.exists():
            self.skipTest("private build receipt is not distributed with source")
        record,data,rows=extension.extension_inputs(p,"32a42d8d79d1dc8e65a159824a4fd9f25e36c38d23d14ee50b44bcfb3590af6b")
        raw=Path(record["runtime_archive"]["path"]).read_bytes()
        gate=extension.candidate_gate(theme.parse_archive(raw),data,record)
        self.assertEqual(len(gate["imports"]),9);self.assertEqual(len(gate["forwarders"]),591)
        self.assertEqual(len(gate["candidate_pe_gate"]["exports"]),594)
        self.assertTrue(any(row["relative_path"]=="extension-compiler-inputs/kernelbase.def" for row in rows))


if __name__=="__main__":
    unittest.main()
