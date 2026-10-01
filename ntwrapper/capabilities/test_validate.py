"""Source inventory gates, not Windows API behavioral or native execution tests.

Each mutation exercises a consumer-visible rejection: an invented capability,
unbound API, stale source reference, or inflated execution claim must fail closed.
SPDX-License-Identifier: GPL-2.0-only
"""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("capability_validator", HERE / "validate.py")
validator = None
if (HERE / "validate.py").is_file():
    validator = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(validator)


@unittest.skipUnless(validator is not None and (HERE / "manifest.json").is_file(), "inventory not implemented")
class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((HERE / "manifest.json").read_text())

    def check(self, manifest=None, root=ROOT):
        return validator.validate_manifest(self.manifest if manifest is None else manifest, root)

    def reject(self, text, manifest=None, root=ROOT):
        with self.assertRaisesRegex(validator.ValidationError, text):
            self.check(manifest, root)

    def provider(self, identifier):
        return next(p for p in self.manifest["providers"] if p["id"] == identifier)

    def clone_sources(self, directory):
        # Explicit references only; no VM assets, build outputs or Microsoft media.
        paths = set(self.manifest["source_contracts"].values())
        for binding in self.manifest["bindings"]:
            paths.update((binding["declaration"], binding["implementation"]))
        for evidence in self.manifest["evidence"]:
            paths.add(evidence["path"])
        for entry in self.manifest["catalog"]:
            paths.update(ref["path"] for ref in entry["backend_refs"])
        for api in self.manifest["backend_apis"]:
            paths.update((api["source"], api["declaration_source"], api["resolver_source"]))
        for path in paths:
            destination = directory / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, destination)

    def test_real_sources_produce_honest_expanded_inventory(self):
        report = self.check()
        self.assertEqual(report["validation_scope"], "source_inventory")
        self.assertFalse(report["behavior_tests_run"])
        self.assertFalse(report["win98_win64_positive"])
        self.assertEqual(report["advertised_masks"], {"ntwddm": 63, "win64": 31})
        exported = [a for a in report["apis"] if a["module"] == "NTW32.DLL"]
        self.assertEqual(len(exported), 25)
        create = next(a for a in exported if a["name"] == "NtwCreateProcess64W")
        self.assertEqual(create["calling_convention"], "stdcall")
        self.assertEqual(create["stdcall_bytes"], 16)
        self.assertEqual(create["thread_safety"], "caller_serialized")
        self.assertIsNone(create["ordinal"])
        self.assertIn("ntwrapper/core.c", report["source_sha256"])

    def test_manifest_unknown_fields_are_rejected(self):
        self.manifest["native_success"] = True
        self.reject("fields")

    def test_non_object_manifest_is_rejected(self):
        self.reject("object", [])

    def test_unknown_schema_is_rejected(self):
        self.manifest["schema"] = "invented.v9"
        self.reject("schema")

    def test_boolean_schema_version_is_rejected(self):
        self.manifest["schema"] = True
        self.reject("schema")

    def test_positive_x64_native_claim_is_rejected(self):
        self.manifest["architecture"]["win98_win64_positive"] = True
        self.reject("architecture")

    def test_backend_desktop_replacement_is_rejected(self):
        self.manifest["architecture"]["product_os"] = "Kernel64 desktop"
        self.reject("architecture")

    def test_windows_scheduler_transfer_is_rejected(self):
        self.manifest["architecture"]["windows_scheduler"] = "PMA"
        self.reject("architecture")

    def test_missing_architectural_family_is_rejected(self):
        self.manifest["catalog"] = [r for r in self.manifest["catalog"] if r["family"] != "NTSTORPORTWrapper9x"]
        self.reject("family coverage")

    def test_duplicate_family_is_rejected(self):
        self.manifest["catalog"].append(copy.deepcopy(self.manifest["catalog"][0]))
        self.reject("duplicate family")

    def test_boundary_without_implementation_cannot_be_promoted(self):
        next(r for r in self.manifest["catalog"] if r["family"] == "NTD3D11Wrapper9x")["frontend_status"] = "NATIVE"
        self.reject("catalog status")

    def test_unsupported_boundary_cannot_claim_partial_without_provider(self):
        next(r for r in self.manifest["catalog"] if r["family"] == "NTSTORPORTWrapper9x")["frontend_status"] = "PARTIAL"
        self.reject("provider-backed")

    def test_unknown_status_is_rejected(self):
        self.provider("ntwddm-software")["apis"][0]["status"] = "COMPLETE"
        self.reject("implementation status")

    def test_software_core_cannot_claim_native_gpu(self):
        self.provider("ntwddm-software")["apis"][0]["status"] = "NATIVE"
        self.reject("implementation status")

    def test_w64_frontend_cannot_claim_positive_native_implementation(self):
        self.provider("ntw64-client")["apis"][0]["status"] = "NATIVE"
        self.reject("implementation status")

    def test_w64_frontend_cannot_claim_thread_safety(self):
        self.provider("ntw64-client")["contract"]["thread_safety"] = "thread_safe"
        self.reject("contract")

    def test_event_core_cannot_lose_embedder_lock_contract(self):
        self.provider("ntwrapper-core")["contract"]["thread_safety"] = "lock_free"
        self.reject("contract")

    def test_unknown_provider_is_rejected(self):
        self.provider("ntwrapper-core")["id"] = "second-object-fabric"
        self.reject("provider")

    def test_duplicate_api_is_rejected(self):
        p = self.provider("ntw32")
        p["apis"].append(copy.deepcopy(p["apis"][0]))
        self.reject("duplicate API")

    def test_wrong_stdcall_stack_size_is_rejected(self):
        self.provider("ntw64-client")["apis"][1]["stdcall_bytes"] = 4
        self.reject("export binding")

    def test_invented_ordinal_is_rejected(self):
        self.provider("ntw64-client")["apis"][1]["ordinal"] = 999
        self.reject("ordinal")

    def test_wrong_calling_convention_is_rejected(self):
        self.provider("ntw64-client")["apis"][1]["calling_convention"] = "cdecl"
        self.reject("calling convention")

    def test_unknown_symbol_is_rejected(self):
        self.provider("ntw64-client")["apis"][1]["symbol"] = "NtwFakeCreateProcess64W"
        self.reject("symbol|export binding")

    def test_missing_export_inventory_entry_is_rejected(self):
        self.provider("ntw32")["apis"].pop()
        self.reject("export coverage")

    def test_unknown_binding_reference_is_rejected(self):
        self.provider("ntwrapper-core")["apis"][0]["binding"] = "missing"
        self.reject("binding")

    def test_stale_evidence_anchor_is_rejected(self):
        self.manifest["evidence"][0]["anchor"] = "invented successful Windows execution"
        self.reject("evidence anchor")

    def test_unbound_evidence_reference_is_rejected(self):
        self.provider("ntwrapper-core")["contract"]["evidence"] = ["missing"]
        self.reject("evidence")

    def test_negative_native_record_cannot_be_promoted_to_positive(self):
        next(e for e in self.manifest["evidence"] if e["kind"] == "RECORDED_NATIVE_NEGATIVE")["kind"] = "NATIVE_POSITIVE"
        self.reject("evidence kind")

    def test_source_path_traversal_is_rejected(self):
        self.manifest["bindings"][0]["implementation"] = "../external.c"
        self.reject("repository-relative")

    def test_absolute_source_path_is_rejected(self):
        self.manifest["bindings"][0]["implementation"] = str(ROOT / "ntwrapper/core.c")
        self.reject("repository-relative")

    def test_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp) / "repo"
            fixture.mkdir()
            self.clone_sources(fixture)
            path = fixture / "ntwrapper/core.c"
            path.unlink()
            path.symlink_to(ROOT / "ntwrapper/core.c")
            self.reject("escapes", root=fixture)

    def test_deleted_implementation_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            self.clone_sources(fixture)
            (fixture / "ntwrapper/core.c").unlink()
            self.reject("missing source", root=fixture)

    def test_prototype_alone_does_not_prove_implementation(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            self.clone_sources(fixture)
            (fixture / "ntwrapper/core.c").write_text("int ntw_initialize(void *c, const void *ops);\n")
            self.reject("definition", root=fixture)

    def test_changed_gop_mask_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            self.clone_sources(fixture)
            source = fixture / "ntwddm/src/ntwddm.c"
            source.write_text(source.read_text().replace("return NTWG_CAP_SOFTWARE_FILL |", "return NTWG_CAP_D3D |"))
            self.reject("advertised capability", root=fixture)

    def test_invented_capability_bit_is_rejected(self):
        self.manifest["capabilities"]["ntwddm"]["advertised"][0]["value"] = 128
        self.reject("capability value")

    def test_reserved_wddm_bit_cannot_be_advertised(self):
        caps = self.manifest["capabilities"]["ntwddm"]
        caps["advertised"].append(caps["unsupported"].pop(0))
        self.reject("advertised capability")

    def test_changed_win64_mask_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            self.clone_sources(fixture)
            source = fixture / "shizukudos/kernel64/subsys64.c"
            source.write_text(source.read_text().replace("SHZ_W64_CAP_POOL_ARGS;", "SHZ_W64_CAP_KILL;", 1))
            self.reject("advertised capability", root=fixture)

    def test_abi_promotion_without_header_change_is_rejected(self):
        self.manifest["capabilities"]["win64"]["minimum_abi"] = "SHZ:2.0"
        self.reject("minimum ABI")

    def test_historical_evidence_is_only_reported_not_executed(self):
        report = self.check()
        self.assertEqual(report["evidence_execution"], "not_run")
        self.assertTrue(any(e["kind"] == "RECORDED_NATIVE_NEGATIVE" for e in report["evidence"]))

    def test_existing_nt_driver_backend_is_distinct_from_frontend_acceptance(self):
        report = self.check()
        family = next(r for r in report["catalog"] if r["family"] == "NTOSKRNLWrapper9x")
        self.assertEqual(family["frontend_status"], "UNSUPPORTED")
        self.assertEqual(family["backend_source_status"], "PARTIAL")
        wait = next(a for a in report["backend_apis"] if a["name"] == "KeWaitForSingleObject")
        self.assertEqual(wait["scope"], "Kernel64_backend")
        self.assertEqual(wait["calling_convention"], "ms_x64")
        self.assertEqual(wait["test_status"], "SOURCE_BOUND")
        self.assertFalse(report["win98_win64_positive"])

    def test_backend_contract_cannot_be_reported_as_windows_frontend(self):
        self.manifest["backend_apis"][0]["scope"] = "Windows98_native"
        self.reject("backend scope")

    def test_driver_export_removed_from_table_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            self.clone_sources(fixture)
            source = fixture / "shizukudos/kernel64/ntdrv_prov.c"
            source.write_text(source.read_text().replace("E(KeWaitForSingleObject)", "E(KeNoSuchWait)"))
            self.reject("backend export", root=fixture)

    def test_driver_ms_abi_attribute_cannot_be_lost(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            self.clone_sources(fixture)
            source = fixture / "shizukudos/kernel64/ntddk.h"
            source.write_text(source.read_text().replace("#define NTAPI __attribute__((ms_abi))", "#define NTAPI"))
            self.reject("Microsoft x64 ABI", root=fixture)

    def test_driver_owner_and_irql_contract_are_required(self):
        self.manifest["backend_apis"][0]["irql"] = ""
        self.reject("IRQL")

    def test_backend_object_owner_cannot_be_promoted_to_vmm(self):
        self.manifest["backend_apis"][0]["ownership"] = "windows_vmm_objects"
        self.reject("backend ownership")

    def test_backend_sync_cannot_claim_lock_free_smp(self):
        self.manifest["backend_apis"][0]["sync_semantics"] = "lock_free_smp_dispatcher"
        self.reject("backend sync")

    def test_backend_source_status_cannot_hide_existing_api(self):
        next(r for r in self.manifest["catalog"] if r["family"] == "NTOSKRNLWrapper9x")["backend_source_status"] = "NOT_INVENTORIED"
        self.reject("backend source status")

    def test_duplicate_route_export_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            self.clone_sources(fixture)
            source = fixture / "ntwin32/routes.json"
            routes = json.loads(source.read_text())
            routes["exports"].append(copy.deepcopy(routes["exports"][0]))
            source.write_text(json.dumps(routes))
            self.reject("duplicate routing", root=fixture)

    def test_impossible_capability_shift_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            self.clone_sources(fixture)
            source = fixture / "ntwddm/include/ntwddm.h"
            source.write_text(source.read_text().replace("(UINT64_C(1) << 0)", "(UINT64_C(1) << 1000)"))
            self.reject("capability shift range", root=fixture)

    def test_comment_only_implementation_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            self.clone_sources(fixture)
            (fixture / "ntwrapper/core.c").write_text("/* int ntw_initialize(void *c, void *ops) { return 0; } */\n")
            self.reject("definition", root=fixture)

    def test_backend_symbol_ref_cannot_point_at_a_comment(self):
        row = next(r for r in self.manifest["catalog"] if r["family"] == "NTOSKRNLWrapper9x")
        row["backend_refs"][0]["symbol"] = "UnimplementedKernelMagic"
        self.reject("definition|symbol")

    def test_unsupported_backend_status_is_not_inferred_from_missing_inventory(self):
        next(r for r in self.manifest["catalog"] if r["family"] == "NTSTORPORTWrapper9x")["backend_source_status"] = "UNSUPPORTED"
        self.reject("backend source status")

    def test_read_only_cli_creates_no_receipt(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            result = subprocess.run([sys.executable, "-B", str(HERE / "validate.py")], cwd=temp,
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["validation_scope"], "source_inventory")
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_cli_error_never_writes_success_report(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            fixture = Path(temp)
            bad = fixture / "manifest.json"
            self.manifest["architecture"]["win98_win64_positive"] = True
            bad.write_text(json.dumps(self.manifest))
            out = fixture / "receipt.json"
            result = subprocess.run([sys.executable, "-B", str(HERE / "validate.py"), "--manifest", str(bad),
                                     "--out", str(out)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(out.exists())

    def test_cli_refuses_receipt_outside_build(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            out = Path(temp) / "receipt.json"
            result = subprocess.run([sys.executable, "-B", str(HERE / "validate.py"), "--out", str(out)],
                                    cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("under project build", result.stderr)
            self.assertFalse(out.exists())

    def test_duplicate_json_field_fails_cli(self):
        with tempfile.TemporaryDirectory(prefix="pma-c957-cap-test-") as temp:
            bad = Path(temp) / "manifest.json"
            bad.write_text('{"schema":"shizuku.wrapper-capabilities.v1","schema":"optimistic"}')
            result = subprocess.run([sys.executable, "-B", str(HERE / "validate.py"), "--manifest", str(bad)],
                                    cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate JSON field", result.stderr)


if __name__ == "__main__":
    unittest.main()
