#!/usr/bin/env python3
"""Validate the existing wrapper inventory against source, without executing it.

Default operation is read-only and writes JSON to stdout. --out requests a new
source-hashed receipt. This is not a loader, a second object fabric, an API test,
or an attestation that the referenced historical tests ran in this invocation.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SCHEMA = "shizuku.wrapper-capabilities.v1"
FAMILY_GROUPS = {
    "kernel": "NTOSKRNLWrapper9x NTHALWrapper9x NTDRVWrapper9x NTIRPWrapper9x NTIOWrapper9x NTMEMWrapper9x NTSYNCWrapper9x NTTHREADWrapper9x NTOBJWrapper9x NTREGWrapper9x NTSECWrapper9x NTPNPWrapper9x NTPOWERWrapper9x NTDMAWrapper9x NTPCIWrapper9x NTACPIWrapper9x NTWMIWrapper9x NTETWWrapper9x NTTIMERWrapper9x NTWORKITEMWrapper9x NTDPCWrapper9x",
    "runtime": "NTDLLWrapper9x NTPELoaderWrapper9x NTPE32PlusWrapper9x LongModeWrapper9x NTSEHWrapper9x NTTEBPEBWrapper9x NTTLSWrapper9x NTFLSWrapper9x NTRTLWrapper9x NTAPISetWrapper9x NTSxSWrapper9x NTManifestWrapper9x NTVersionWrapper9x NTUnicodeWrapper9x",
    "win32": "NTKERNEL32Wrapper9x NTKERNELBASEWrapper9x NTUSER32Wrapper9x NTGDI32Wrapper9x NTADVAPI32Wrapper9x NTRPCRT4Wrapper9x NTOLE32Wrapper9x NTOLEAUT32Wrapper9x NTCOMBASEWrapper9x NTCOMCTL32Wrapper9x NTCOMDLG32Wrapper9x NTSHELL32Wrapper9x NTSHCOREWrapper9x NTIMM32Wrapper9x NTPSAPIWrapper9x NTDBGHELPWrapper9x",
    "crt": "NTMSVCRTWrapper9x NTUCRTBaseWrapper9x NTVCRuntimeWrapper9x NTCPPStdRuntimeWrapper9x",
    "graphics": "NTWDDMWrapper9x NTDXGKRNLWrapper9x NTD3DKMTWrapper9x NTDXGIWrapper9x NTD3D9Wrapper9x NTD3D10Wrapper9x NTD3D11Wrapper9x NTD2DWrapper9x NTDWRITEWrapper9x NTDCompWrapper9x NTDWMAPIWrapper9x NTUXTHEMEWrapper9x NTGDIPLUSWrapper9x NTWIN32UWrapper9x NTWICWrapper9x",
    "storage": "NTSTORPORTWrapper9x NTSCSIPORTWrapper9x NTATAWrapper9x NTAHCIWrapper9x NTNVMEWrapper9x NTDISKWrapper9x NTCDROMWrapper9x NTVOLMGRWrapper9x NTMOUNTMGRWrapper9x NTFATWrapper9x NTCDFSWrapper9x NTCACHEWrapper9x",
    "usb_input": "NTUSBWrapper9x NTUSBHUBWrapper9x NTUHCIWrapper9x NTOHCIWrapper9x NTEHCIWrapper9x NTXHCIWrapper9x NTHIDWrapper9x NTKBDCLASSWrapper9x NTMOUCLASSWrapper9x NTGAMEINPUTWrapper9x NTXInputWrapper9x",
    "audio": "NTKSWrapper9x NTPortClsWrapper9x NTAudioWrapper9x NTWINMMWrapper9x NTMMDEVAPIWrapper9x NTAudioEndpointWrapper9x NTDirectSoundWrapper9x",
    "network": "NDISWrapper9x NTNETIOWrapper9x NTTCPIPWrapper9x NTWS2_32Wrapper9x NTIPHLPAAPIWrapper9x NTDNSAPIWrapper9x NTWINHTTPWrapper9x NTWININETWrapper9x NTHTTPWrapper9x",
    "security": "NTCRYPT32Wrapper9x NTBCRYPTWrapper9x NTBCryptPrimitivesWrapper9x NTNCRYPTWrapper9x NTSECUR32Wrapper9x NTSSPIWrapper9x NTWINTRUSTWrapper9x NTDPAPIWrapper9x",
    "media": "NTDirectShowWrapper9x NTMediaFoundationWrapper9x NTWASAPIWrapper9x",
}
ARCHITECTURE = {
    "product_os": "Windows98", "windows_scheduler": "VMM", "backend_scheduler": "Shizuku_PMA",
    "kernel32_role": "Shizuku_backend_not_Microsoft_KERNEL32_DLL",
    "kernel64_role": "backend_not_replacement_desktop",
    "objects": "reuse_existing_ntwrapper_and_kernel64_objects", "win98_win64_positive": False,
    "win98_pma_positive": False, "windows98_dos_replacement_verified": False,
}
SOURCE_CONTRACTS = {
    "ntw_header": "ntwrapper/include/ntwrapper.h", "shz_header": "shizukudos/abi/shz_abi.h",
    "ntwg_header": "ntwddm/include/ntwddm.h", "ntwg_implementation": "ntwddm/src/ntwddm.c",
    "w64_implementation": "shizukudos/kernel64/subsys64.c", "exports": "ntwin32/exports.def",
    "routes": "ntwin32/routes.json", "w64_header": "ntwin32/win64/ntw64.h",
    "vxd_native": "ntwrapper/vxd/native.c", "channel_plan": "shizukudos/supervisor/src/kdom.c",
    "ipc_header": "shizukudos/abi/shz_ipc.h", "ntddk_header": "shizukudos/kernel64/ntddk.h",
}
BINDINGS = {
    "core": ("ntwrapper/include/ntwrapper.h", "ntwrapper/core.c"),
    "ntw32": ("ntwin32/runtime.c", "ntwin32/runtime.c"),
    "ntw64": ("ntwin32/win64/ntw64.h", "ntwin32/win64/ntw64.c"),
    "vxd": ("ntwrapper/vxd/bridge.h", "ntwrapper/vxd/bridge.c"),
    "software": ("ntwddm/include/ntwddm.h", "ntwddm/src/ntwddm.c"),
    "dib": ("ntwddm/win98/adapter.h", "ntwddm/win98/adapter.c"),
}
# These are accepted source contracts, not assertions of full API compatibility.
# Status/scheduling/ownership promotions require a deliberate schema-policy update
# and new evidence, not editing an optimistic field in the machine manifest.
PROVIDERS = {
    "ntwrapper-core": ("NTWrapper9x-core", "core", "NATIVE", "cdecl", "NTW:1", "embedder_serialized",
                       "nonblocking_event_acquisition", "ntw_context_generation_handles_and_leases", "ntw_status"),
    "ntw32": ("NTW32.DLL", "ntw32", "PARTIAL", "stdcall", "Win32:x86", "per_api_native_or_owned_contract",
              "windows_native_scheduler_and_owned_sync", "windows_process_and_caller_storage", "win32_native_or_owned"),
    "ntw64-client": ("NTW32.DLL", "ntw64", "PARTIAL", "stdcall", "SHZ:1.1", "caller_serialized",
                     "request_pump_poll_deadline_and_console_ack", "ntw32_private_handles_to_kernel64_processes",
                     "win32_from_shz_or_ntstatus"),
    "vxd-transport": ("NTWRAP9X.VXD", "vxd", "PARTIAL", "cdecl", "SHZ:1.1", "up_synchronous_callback",
                      "pinned_buffers_bounded_copy_and_existing_spsc_ring", "vxd_mapping_and_sender_pool_blocks", "win32_errors"),
    "ntwddm-software": ("NTWDDMWrapper9x-core", "software", "SOFTWARE", "cdecl", "NTWG:1.0", "caller_serialized",
                         "synchronous_cpu_render_and_context_fences", "context_generation_surfaces_exclusive_maps", "ntwg_status"),
    "win98-dib": ("NTWDDMWrapper9x-Win98-DIB", "dib", "TRANSLATED", "cdecl", "NTWG:1.0", "caller_serialized",
                  "gdi_sync_before_cpu_write_and_native_paint", "app_owned_dib_and_software_surface", "ntwg_status_and_platform_failure"),
}
PROVIDER_FAMILIES = {
    "ntwrapper-core": {"NTOBJWrapper9x", "NTSYNCWrapper9x"},
    "ntw32": {"NTKERNEL32Wrapper9x", "NTSYNCWrapper9x", "NTUnicodeWrapper9x", "NTSEHWrapper9x"},
    "ntw64-client": {"NTKERNEL32Wrapper9x", "NTPE32PlusWrapper9x", "LongModeWrapper9x"},
    "vxd-transport": {"NTDRVWrapper9x", "NTIOWrapper9x", "NTSYNCWrapper9x"},
    "ntwddm-software": {"NTWDDMWrapper9x", "NTGDI32Wrapper9x"},
    "win98-dib": {"NTUSER32Wrapper9x", "NTGDI32Wrapper9x"},
}
BACKEND_SLICE = {
    "KeInitializeEvent": "ntdrv_ke.c", "KeSetEvent": "ntdrv_ke.c", "KeWaitForSingleObject": "ntdrv_ke.c",
    "KeInitializeSpinLock": "ntdrv_ke.c", "KeInsertQueueDpc": "ntdrv_ke.c", "KeSetTimer": "ntdrv_ke.c",
    "ExAllocatePoolWithTag": "ntdrv_ke.c", "IoCreateDevice": "ntdrv_io.c", "IoAllocateIrp": "ntdrv_io.c",
    "IofCallDriver": "ntdrv_io.c", "IofCompleteRequest": "ntdrv_io.c", "IoQueueWorkItem": "ntdrv_io.c",
    "ExQueueWorkItem": "ntdrv_ex.c", "MmMapIoSpace": "ntdrv_mm.c", "PsCreateSystemThread": "ntdrv_rtl.c",
    "IoGetDeviceProperty": "ntdrv_dev.c", "HalGetBusDataByOffset": "ntdrv_rtl.c",
}
BACKEND_CONTRACTS = {
    "KeInitializeEvent": ("caller_resident_dispatcher_object", "source_initializes_dispatcher_header"),
    "KeSetEvent": ("caller_resident_dispatcher_object", "up_irq_saved_state_update"),
    "KeWaitForSingleObject": ("caller_resident_dispatcher_object", "up_dispatcher_wait_or_zero_timeout_poll"),
    "KeInitializeSpinLock": ("caller_resident_spinlock", "caller_initialization_before_use"),
    "KeInsertQueueDpc": ("caller_dpc_until_dequeue_or_execution", "up_irq_saved_queue_and_dispatch_worker"),
    "KeSetTimer": ("caller_timer_and_optional_dpc", "up_timer_list_and_timer_worker"),
    "ExAllocatePoolWithTag": ("kernel_heap_allocation_caller_free", "kernel_heap_policy_no_entry_irql_check"),
    "IoCreateDevice": ("driver_device_and_namespace_record", "up_namespace_allocation_no_entry_irql_check"),
    "IoAllocateIrp": ("caller_irp_until_free_or_completion", "kernel_heap_allocation"),
    "IofCallDriver": ("device_stack_dispatch_and_caller_irp", "current_thread_ms_x64_dispatch"),
    "IofCompleteRequest": ("irp_completion_routines_and_waiter", "driver_completion_then_existing_waiter_signal"),
    "IoQueueWorkItem": ("caller_workitem_until_callback_finishes", "up_irq_saved_queue_passive_worker"),
    "ExQueueWorkItem": ("caller_workitem_until_callback_finishes", "existing_system_work_queue_or_inline_allocation_failure"),
    "MmMapIoSpace": ("driver_mmio_mapping_and_pci_claim", "kernel_mmio_mapping_policy"),
    "PsCreateSystemThread": ("kernel_thread_and_existing_kernel_handle", "kernel64_scheduler_system_thread"),
    "IoGetDeviceProperty": ("existing_pdo_and_caller_output_buffer", "existing_device_property_namespace"),
    "HalGetBusDataByOffset": ("shizuku_pci_backend_and_caller_buffer", "pci_configuration_read_no_entry_irql_check"),
}
BACKEND_DEPENDENCIES = {
    "KeSetTimer": [{"path": "shizukudos/kernel64/ntdrv_ke.c", "symbols": ["timer_set", "timer_arm"]}],
    "ExQueueWorkItem": [{"path": "shizukudos/kernel64/ntdrv_io.c", "symbols": [
        "ntdrv_queue_system_work", "syswork_run", "IoQueueWorkItem", "queue_item", "work_thread"]}],
}
BACKEND_SOURCE_SEMANTICS = {
    "KeSetTimer": {
        "return_value": "previous_Header.SignalState_nonzero",
        "inserted_state": "set_before_bounded_timer_list_admission",
        "due_time": "negative_magnitude_div_10000_minimum_one_tick_nonnegative_one_tick",
        "timer_capacity": 32,
    },
    "ExQueueWorkItem": {
        "normal_execution": "existing_PASSIVE_system_worker",
        "allocation_failure_execution": "synchronous_callback_at_caller_irql",
        "queue_type": "ignored",
    },
}
BACKEND_IRQL = {
    "KeSetTimer": "UP CR8/dispatcher model; up_timer_list_and_timer_worker",
    "ExQueueWorkItem": "UP CR8/dispatcher model; normal PASSIVE system worker; allocation failure executes synchronously at caller IRQL without lowering it",
}


class ValidationError(ValueError):
    """A source/manifest mismatch; no success receipt should be published."""


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def fields(value, expected, context):
    require(isinstance(value, dict), context + " must be an object")
    require(set(value) == set(expected), context + " fields do not match the schema")


def nonempty(value, context):
    require(isinstance(value, str) and bool(value.strip()), context + " must be a nonempty string")


def sequence(value, context):
    require(isinstance(value, list) and bool(value), context + " must be a nonempty array")


def c_text(source):
    # Narrow lexical checks only; the receipt expressly does not claim compilation.
    # Removing comments/string bodies prevents comment-only and string-only symbols.
    token = r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(token, lambda m: '""' if m.group(0).startswith(('"', "'")) else " ", source)


def definition(source, symbol):
    expression = r"(?m)^[\w\s*]+?\b" + re.escape(symbol) + r"\s*\([^;{}]*\)\s*\{"
    match = re.search(expression, c_text(source))
    require(match is not None, "missing function definition for symbol " + symbol)
    return match.group(0)


def function_body(source, symbol):
    # A brace-balanced lexical slice, not a C parser or behavioral proof. Match
    # only the selected definition so an unrelated helper/comment cannot satisfy
    # a contract after the relevant implementation has drifted.
    clean = c_text(source)
    signature = definition(source, symbol)
    start = clean.index(signature) + len(signature)
    depth = 1
    for end in range(start, len(clean)):
        if clean[end] == "{":
            depth += 1
        elif clean[end] == "}":
            depth -= 1
            if depth == 0:
                return clean[start:end]
    raise ValidationError("unterminated function definition for symbol " + symbol)


def backend_source_contract(name, source, dependencies):
    if name == "KeSetTimer":
        wrapper = function_body(source, name)
        timer = function_body(dependencies[0], "timer_set")
        arm = function_body(dependencies[0], "timer_arm")
        compact = re.sub(r"\s+", "", timer)
        require("returntimer_set(t,due.QuadPart,0,dpc);" in re.sub(r"\s+", "", wrapper),
                "timer wrapper source contract drift")
        require("uint8_twas=t->Header.SignalState!=0;" in compact and "returnwas;" in compact,
                "timer signal return source contract drift")
        require("uint64_trel_ms=due_100ns<0?(uint64_t)(-due_100ns)/10000:1;" in compact and
                "t->DueTime=ticks_now()+(rel_ms?rel_ms:1);" in compact,
                "timer due-time source contract drift")
        require("t->Header.SignalState=0;t->Header.Inserted=1;timer_arm(t);" in compact,
                "timer insertion admission source contract drift")
        require("staticKTIMER*timer_list[32];" in re.sub(r"\s+", "", c_text(dependencies[0])) and
                "if(timer_count<32)timer_list[timer_count++]=t;" in re.sub(r"\s+", "", arm),
                "timer list capacity source contract drift")
    elif name == "ExQueueWorkItem":
        wrapper = re.sub(r"\s+", "", function_body(source, name))
        helper = re.sub(r"\s+", "", function_body(dependencies[0], "ntdrv_queue_system_work"))
        dispatch = re.sub(r"\s+", "", function_body(dependencies[0], "IoQueueWorkItem"))
        queue = re.sub(r"\s+", "", function_body(dependencies[0], "queue_item"))
        callback = re.sub(r"\s+", "", function_body(dependencies[0], "syswork_run"))
        worker = re.sub(r"\s+", "", function_body(dependencies[0], "work_thread"))
        require("(void)queue_type;ntdrv_queue_system_work(w->WorkerRoutine,w->Parameter,w);" in wrapper,
                "work wrapper source contract drift")
        require("structsyswork*s=kzalloc(sizeof*s);" in helper and "if(!s){fn(ctx);return;}" in helper,
                "work allocation-failure fallback source contract drift")
        require("s->fn=fn;s->ctx=ctx;IoQueueWorkItem(&s->item,syswork_run,0,s);" in helper,
                "work provider queue source contract drift")
        require("(void)queue_type;queue_item(item,routine,0,ctx);" in dispatch and
                'thread_create("",work_thread,0)' in queue and "sem_post(&wq_sem);" in queue and
                "elseroutine(dev,ctx);" in worker,
                "work dispatch source contract drift")
        require("structsyswork*s=ctx;" in callback and "s->fn(s->ctx);kfree(s);" in callback,
                "work callback source contract drift")


def public_symbols(source, prefix):
    return set(re.findall(r"\b(" + prefix + r"[A-Za-z0-9_]*)\s*\([^;{}]*\)\s*;", c_text(source)))


def validate_manifest(manifest, root=ROOT):
    fields(manifest, ("schema", "baseline_commit", "status_scope", "architecture", "source_contracts",
                      "capabilities", "evidence", "bindings", "providers", "backend_apis", "catalog"), "manifest")
    require(manifest["schema"] == SCHEMA, "unknown manifest schema")
    require(isinstance(manifest["baseline_commit"], str) and
            re.fullmatch(r"[0-9a-f]{40}", manifest["baseline_commit"]), "invalid baseline commit SHA")
    require(manifest["status_scope"] == "listed_source_contracts_and_windows98_frontend_boundaries", "invalid status scope")
    fields(manifest["architecture"], ARCHITECTURE, "architecture")
    # Exact types also reject integer 0/1 being confused with boolean evidence flags.
    require(all(type(manifest["architecture"][k]) is type(v) and manifest["architecture"][k] == v
                for k, v in ARCHITECTURE.items()), "architecture or native evidence promotion is not permitted")
    root = Path(root).resolve()
    sources = {}
    hashes = {}

    def read(path):
        nonempty(path, "source path")
        pure = PurePosixPath(path)
        require(not pure.is_absolute() and pure.as_posix() == path and
                all(p not in (".", "..") for p in pure.parts) and "\\" not in path and "\x00" not in path,
                "source path must be canonical repository-relative: " + path)
        target = (root / path).resolve()
        require(target.is_relative_to(root), "source path escapes repository: " + path)
        require(target.is_file(), "missing source file: " + path)
        if path not in sources:
            raw = target.read_bytes()
            hashes[path] = hashlib.sha256(raw).hexdigest()
            try:
                sources[path] = raw.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValidationError("source is not UTF-8: " + path) from error
        return sources[path]

    fields(manifest["source_contracts"], SOURCE_CONTRACTS, "source contracts")
    for key, path in manifest["source_contracts"].items():
        read(path)
        require(path == SOURCE_CONTRACTS[key], "source contract binding mismatch: " + key)

    def macro(path, name):
        found = re.search(r"(?m)^#define\s+" + re.escape(name) + r"\s+(?:UINT32_C\()?(0x[0-9a-fA-F]+|[0-9]+)", c_text(read(path)))
        require(found is not None, "missing ABI macro " + name)
        return int(found.group(1), 0)

    require(macro(SOURCE_CONTRACTS["ntw_header"], "NTW_ABI_VERSION") == 1, "NTW minimum ABI changed")
    require(macro(SOURCE_CONTRACTS["shz_header"], "SHZ_ABI_MAJOR") == 1 and
            macro(SOURCE_CONTRACTS["shz_header"], "SHZ_ABI_MINOR") == 1, "SHZ minimum ABI changed")
    require(macro(SOURCE_CONTRACTS["ntwg_header"], "NTWG_ABI_VERSION") == 0x10000, "NTWG minimum ABI changed")

    sequence(manifest["evidence"], "evidence")
    evidence = {}
    kinds = {"SOURCE_TEST_DEFINITION", "RECORDED_NATIVE_NEGATIVE", "RECORDED_ARCHITECTURE_AUDIT", "RECORDED_BACKEND_COMPONENT"}
    for entry in manifest["evidence"]:
        fields(entry, ("id", "kind", "path", "anchor"), "evidence entry")
        nonempty(entry["id"], "evidence id")
        require(entry["id"] not in evidence, "duplicate evidence id")
        require(isinstance(entry["kind"], str) and entry["kind"] in kinds, "unsupported evidence kind")
        nonempty(entry["anchor"], "evidence anchor")
        require(entry["anchor"] in read(entry["path"]), "stale evidence anchor: " + entry["id"])
        if entry["kind"] == "RECORDED_NATIVE_NEGATIVE":
            require(entry["id"] == "native-v9-negative" and
                    entry["path"] == "docs/shizukudos10/reports/MODERN_APPS_CAMPAIGN.md" and
                    entry["anchor"] == "2026-10-01 09:28 UTC: nativeV9", "unbound native negative evidence")
        evidence[entry["id"]] = entry
    require("native-v9-negative" in evidence and evidence["native-v9-negative"]["kind"] == "RECORDED_NATIVE_NEGATIVE",
            "native negative boundary evidence is required")

    sequence(manifest["bindings"], "bindings")
    bindings = {}
    for binding in manifest["bindings"]:
        fields(binding, ("id", "declaration", "implementation"), "binding")
        read(binding["declaration"])
        read(binding["implementation"])
        require(isinstance(binding["id"], str) and binding["id"] in BINDINGS, "unknown source binding")
        require(binding["id"] not in bindings, "duplicate source binding")
        require((binding["declaration"], binding["implementation"]) == BINDINGS[binding["id"]], "source binding mismatch")
        bindings[binding["id"]] = binding
    require(set(bindings) == set(BINDINGS), "source binding coverage is incomplete")

    fields(manifest["capabilities"], ("ntwddm", "win64"), "capabilities")
    masks = {}
    for category, cap in manifest["capabilities"].items():
        fields(cap, ("minimum_abi", "advertised", "unsupported"), "capability family")
        wanted_abi = "NTWG:1.0" if category == "ntwddm" else "SHZ:1.1"
        require(cap["minimum_abi"] == wanted_abi, "capability minimum ABI mismatch")
        header = read(SOURCE_CONTRACTS["ntwg_header"]) if category == "ntwddm" else read("shizukudos/abi/shz_ipc.h")
        if category == "ntwddm":
            rows = re.findall(r"#define\s+(NTWG_CAP_\w+)\s+\(UINT64_C\(1\)\s*<<\s*(\d+)\)", c_text(header))
            require(all(0 <= int(shift) <= 63 for _, shift in rows), "capability shift range must fit uint64_t")
            require(len({name for name, _ in rows}) == len(rows), "duplicate capability declaration")
            declared = {name: 1 << int(shift) for name, shift in rows}
            body = read(SOURCE_CONTRACTS["ntwg_implementation"])
            advertised = re.search(r"uint64_t\s+ntwg_capabilities\s*\(void\)\s*\{\s*return\s+([^;]+);\s*\}", c_text(body))
            token_prefix = "NTWG_CAP_"
        else:
            enum = re.search(r"enum\s+shz_w64_caps\s*\{([^}]+)\}", c_text(header))
            require(enum is not None, "missing WIN64 capability enum")
            declared = {name: int(value) for name, value in re.findall(r"(SHZ_W64_CAP_\w+)\s*=\s*(\d+)", enum.group(1))}
            advertised = re.search(r"info\.capabilities\s*=\s*([^;]+);", c_text(read(SOURCE_CONTRACTS["w64_implementation"])))
            token_prefix = "SHZ_W64_CAP_"
        require(advertised is not None and declared, "missing advertised capability expression")
        expression = advertised.group(1)
        require(re.fullmatch(r"\s*" + token_prefix + r"\w+(?:\s*\|\s*" + token_prefix + r"\w+)*\s*", expression),
                "unsupported advertised capability expression")
        names = set(re.findall(token_prefix + r"\w+", expression))
        require(names <= set(declared), "unknown advertised capability symbol")
        require(isinstance(cap["advertised"], list) and isinstance(cap["unsupported"], list), "capabilities must be arrays")
        seen = set()
        advertised_names = set()
        mask = 0
        for bucket in ("advertised", "unsupported"):
            for row in cap[bucket]:
                fields(row, ("symbol", "value", "status"), "capability")
                require(isinstance(row["symbol"], str) and row["symbol"] in declared, "unknown capability symbol")
                require(row["symbol"] not in seen, "duplicate capability symbol")
                require(type(row["value"]) is int and row["value"] == declared[row["symbol"]], "capability value mismatch")
                expected_status = "UNSUPPORTED" if bucket == "unsupported" else ("SOFTWARE" if category == "ntwddm" else "PARTIAL")
                require((bucket == "advertised") == (row["symbol"] in names), "advertised capability inventory differs from implementation")
                require(row["status"] == expected_status, "capability implementation status mismatch")
                seen.add(row["symbol"])
                if bucket == "advertised":
                    advertised_names.add(row["symbol"])
                    mask |= row["value"]
        require(advertised_names == names, "advertised capability inventory differs from implementation")
        require(seen == set(declared), "capability declaration coverage is incomplete")
        # Do not mistake an extended declaration or accidental backend promotion for
        # proof that WDDM/D3D or a new service works. Schema v1 inventories this slice.
        require(mask == (63 if category == "ntwddm" else 31), "advertised capability promotion requires new evidence")
        masks[category] = mask

    export_source = read(SOURCE_CONTRACTS["exports"])
    exports = {}
    for line in export_source.splitlines():
        if line.strip() in ("LIBRARY NTW32.DLL", "EXPORTS", ""):
            continue
        match = re.fullmatch(r"\s*(\w+)=(\w+)@(\d+)\s*", line)
        require(match is not None, "unsupported NTW32 export binding or ordinal")
        name, symbol, count = match.groups()
        require(name not in exports, "duplicate named export binding")
        exports[name] = (symbol, int(count))
    try:
        routes = json.loads(read(SOURCE_CONTRACTS["routes"]))
        route_names = [r["name"] for r in routes["exports"]]
        provider_api = routes["provider_api"]
    except (KeyError, TypeError, ValueError) as error:
        raise ValidationError("unrecognized NTW32 routing inventory") from error
    sequence(provider_api, "routing provider API")
    require(all(isinstance(n, str) for n in route_names + provider_api), "invalid routing export name")
    routed_names = set(route_names)
    provider_names = set(provider_api)
    require(len(routed_names) == len(route_names) and len(provider_names) == len(provider_api),
            "duplicate routing export name")
    require(not routed_names & provider_names and set(exports) == routed_names | provider_names, "routing/export coverage mismatch")

    sequence(manifest["providers"], "providers")
    provider_ids = set()
    api_keys = set()
    exported_names = set()
    expanded = []
    for provider in manifest["providers"]:
        fields(provider, ("id", "module", "families", "contract", "apis"), "provider")
        identifier = provider["id"]
        require(isinstance(identifier, str) and identifier in PROVIDERS, "unknown provider")
        require(identifier not in provider_ids, "duplicate provider")
        provider_ids.add(identifier)
        module, binding_id, status, convention, abi, safety, sync, ownership, errors = PROVIDERS[identifier]
        require(provider["module"] == module, "provider module mismatch")
        sequence(provider["families"], "provider families")
        require(all(isinstance(f, str) for f in provider["families"]) and
                len(set(provider["families"])) == len(provider["families"]) and
                set(provider["families"]) == PROVIDER_FAMILIES[identifier], "provider family ownership mismatch")
        contract = provider["contract"]
        fields(contract, ("minimum_abi", "backend", "thread_safety", "sync_semantics", "ownership",
                          "error_model", "test_status", "evidence", "limits"), "provider contract")
        require((contract["minimum_abi"], contract["backend"], contract["thread_safety"], contract["sync_semantics"],
                 contract["ownership"], contract["error_model"], contract["test_status"]) ==
                (abi, BINDINGS[binding_id][1], safety, sync, ownership, errors, "SOURCE_BOUND"), "provider contract mismatch")
        sequence(contract["evidence"], "provider evidence")
        require(all(isinstance(e, str) and e in evidence for e in contract["evidence"]), "unbound provider evidence reference")
        sequence(contract["limits"], "provider limitations")
        for limit in contract["limits"]:
            nonempty(limit, "provider limitation")
        sequence(provider["apis"], "provider APIs")
        provider_symbols = set()
        for api in provider["apis"]:
            fields(api, ("name", "symbol", "ordinal", "calling_convention", "stdcall_bytes", "status", "binding"), "API")
            nonempty(api["name"], "API name")
            nonempty(api["symbol"], "API symbol")
            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", api["symbol"]), "invalid API symbol")
            key = (module, api["name"])
            require(key not in api_keys, "duplicate API: " + api["name"])
            api_keys.add(key)
            require(api["ordinal"] is None, "invented ordinal: named/C API has no stable assigned ordinal")
            require(api["calling_convention"] == convention, "API calling convention mismatch")
            require(api["status"] == status, "API implementation status promotion/mismatch")
            require(isinstance(api["binding"], str) and api["binding"] in bindings and api["binding"] == binding_id,
                    "unknown or wrong API binding")
            binding = bindings[api["binding"]]
            declarations = public_symbols(read(binding["declaration"]), re.escape(api["symbol"]))
            require(api["symbol"] in declarations, "missing declaration for symbol " + api["symbol"])
            signature = definition(read(binding["implementation"]), api["symbol"])
            if convention == "stdcall":
                require("WINAPI" in signature, "stdcall source calling convention mismatch")
                require(type(api["stdcall_bytes"]) is int and exports.get(api["name"]) == (api["symbol"], api["stdcall_bytes"]),
                        "export binding mismatch: " + api["name"])
                wanted_names = provider_names if identifier == "ntw64-client" else routed_names
                require(api["name"] in wanted_names, "provider route/export binding mismatch")
                exported_names.add(api["name"])
            else:
                require(api["stdcall_bytes"] is None and "WINAPI" not in signature, "C source calling convention mismatch")
                require(api["name"] == api["symbol"], "C API name/symbol binding mismatch")
            provider_symbols.add(api["symbol"])
            expanded.append(dict(api, provider=identifier, module=module, families=provider["families"],
                                 **{k: v for k, v in contract.items() if k != "limits"}, limits=contract["limits"]))
        if binding_id in ("core", "software", "dib"):
            prefix = {"core": "ntw_", "software": "ntwg_", "dib": "ntwg98_"}[binding_id]
            declared = public_symbols(read(BINDINGS[binding_id][0]), prefix)
            if binding_id == "dib":
                declared.discard("ntwg98_selftest")  # Diagnostic in selftest.c, not a compatibility API.
            require(provider_symbols == declared, "public API declaration coverage mismatch: " + identifier)
        if binding_id == "vxd":
            require(provider_symbols == {"ntwv_dioc", "ntwv_dioc_ex"}, "VxD dispatch slice coverage mismatch")
    require(provider_ids == set(PROVIDERS), "provider coverage is incomplete")
    require(exported_names == set(exports), "export coverage is incomplete")

    sequence(manifest["backend_apis"], "backend APIs")
    backend_names = set()
    ntapi = c_text(read(SOURCE_CONTRACTS["ntddk_header"]))
    require(re.search(r"#define\s+NTAPI\s+__attribute__\(\(ms_abi\)\)", ntapi), "Microsoft x64 ABI attribute is missing")
    resolver_path = "shizukudos/kernel64/ntdrv_prov.c"
    resolver = read(resolver_path)
    definition(resolver, "ntdrv_resolve_export")
    tables = {}
    for module, table in (("ntoskrnl.exe", "ntdrv_ntoskrnl_exports"), ("hal.dll", "ntdrv_hal_exports")):
        found = re.search(r"const\s+ntdrv_export_t\s+" + table + r"\s*\[\]\s*=\s*\{([\s\S]*?)\};", c_text(resolver))
        require(found is not None, "missing backend export table " + table)
        tables[module] = set(re.findall(r"\bE\((\w+)\)", found.group(1)))
    for api in manifest["backend_apis"]:
        require(isinstance(api, dict), "backend API must be an object")
        name = api.get("name")
        require(isinstance(name, str) and name in BACKEND_SLICE, "unknown backend API symbol")
        extra_fields = ("source_dependencies", "source_semantics") if name in BACKEND_DEPENDENCIES else ()
        fields(api, ("name", "symbol", "families", "scope", "module", "ordinal", "calling_convention", "minimum_abi",
                     "status", "source", "declaration_source", "resolver_source", "irql", "ownership", "sync_semantics",
                     "test_status", "evidence", "limits") + extra_fields, "backend API")
        require(api["scope"] == "Kernel64_backend", "backend scope cannot claim Windows98 frontend acceptance")
        name = api["name"]
        require(isinstance(name, str) and name in BACKEND_SLICE and api["symbol"] == name, "unknown backend API symbol")
        require(name not in backend_names, "duplicate backend API")
        backend_names.add(name)
        require(api["ordinal"] is None, "backend imports are named; no stable ordinal is declared")
        require(api["calling_convention"] == "ms_x64", "backend calling convention mismatch")
        require(api["minimum_abi"] == "Kernel64-NTDRV:unversioned", "backend minimum ABI is an unversioned source contract")
        require(api["status"] == "PARTIAL" and api["test_status"] == "SOURCE_BOUND", "backend implementation status cannot be promoted")
        expected_source = "shizukudos/kernel64/" + BACKEND_SLICE[name]
        require(api["source"] == expected_source and api["declaration_source"] == expected_source and
                api["resolver_source"] == resolver_path, "backend source binding mismatch")
        signature = definition(read(api["source"]), name)
        require("NTAPI" in signature, "backend Microsoft x64 ABI calling attribute missing: " + name)
        if name in BACKEND_DEPENDENCIES:
            require(api["source_dependencies"] == BACKEND_DEPENDENCIES[name], "backend dependency binding mismatch")
            require(api["irql"] == BACKEND_IRQL[name], "backend IRQL contract mismatch")
            wanted = BACKEND_SOURCE_SEMANTICS[name]
            fields(api["source_semantics"], wanted, "backend source semantics")
            require(all(type(api["source_semantics"][key]) is type(value) and api["source_semantics"][key] == value
                        for key, value in wanted.items()), "backend source semantics mismatch")
            dependencies = []
            for ref in api["source_dependencies"]:
                dependency = read(ref["path"])
                for symbol in ref["symbols"]:
                    definition(dependency, symbol)
                dependencies.append(dependency)
            backend_source_contract(name, read(api["source"]), dependencies)
        module = "hal.dll" if name.startswith("Hal") else "ntoskrnl.exe"
        require(api["module"] == module and name in tables[module], "backend export binding mismatch: " + name)
        sequence(api["families"], "backend API families")
        require(all(isinstance(f, str) for f in api["families"]) and len(set(api["families"])) == len(api["families"]),
                "backend family references must be unique strings")
        for key, label in (("irql", "IRQL"), ("ownership", "ownership"), ("sync_semantics", "sync semantics")):
            nonempty(api[key], "backend " + label)
        expected_owner, expected_sync = BACKEND_CONTRACTS[name]
        require(api["ownership"] == expected_owner, "backend ownership contract mismatch")
        require(api["sync_semantics"] == expected_sync, "backend sync contract mismatch")
        require(api["irql"].startswith("UP CR8/dispatcher model; "), "backend IRQL model does not establish SMP operation")
        sequence(api["evidence"], "backend evidence")
        require(all(isinstance(e, str) and e in evidence for e in api["evidence"]), "unbound backend evidence")
        sequence(api["limits"], "backend limitations")
        for limit in api["limits"]:
            nonempty(limit, "backend limitation")
    require(backend_names == set(BACKEND_SLICE), "backend exemplar coverage is incomplete")

    # Source markers verify the conservative boundary, without pretending they
    # prove scheduling behavior or hypervisor execution. Their hashes bind the
    # receipt to exactly the inspected implementations.
    require("caller" in read(SOURCE_CONTRACTS["w64_header"]).lower() or
            "serialize them" in read(SOURCE_CONTRACTS["w64_header"]), "W64 serialization contract is missing")
    require("hypervisor_present" in c_text(read(SOURCE_CONTRACTS["vxd_native"])) and
            "ntwv_cpuid" in c_text(read(SOURCE_CONTRACTS["vxd_native"])), "VxD hypervisor gate source binding missing")
    require(re.search(r"\{\s*SHZ_DOM_KERNEL64\s*,\s*SHZ_DOM_WIN98\s*\}", c_text(read(SOURCE_CONTRACTS["channel_plan"]))),
            "existing channel 2 peer plan is missing")

    sequence(manifest["catalog"], "catalog")
    wanted_families = {f: category for category, names in FAMILY_GROUPS.items() for f in names.split()}
    families = set()
    for entry in manifest["catalog"]:
        fields(entry, ("family", "category", "frontend_status", "backend_source_status", "providers", "binary", "backend_refs",
                       "backend_apis", "boundary"), "catalog entry")
        family = entry["family"]
        require(isinstance(family, str) and family in wanted_families, "unknown architectural family")
        require(family not in families, "duplicate family")
        families.add(family)
        require(entry["category"] == wanted_families[family], "family category mismatch")
        require(entry["frontend_status"] in ("PARTIAL", "UNSUPPORTED"), "catalog status cannot claim a complete family")
        require(entry["binary"] is None, "catalog boundary does not install or generate wrapper binaries")
        expected_providers = {p["id"] for p in manifest["providers"] if family in p["families"]}
        require(isinstance(entry["providers"], list) and all(isinstance(p, str) for p in entry["providers"]) and
                len(set(entry["providers"])) == len(entry["providers"]) and set(entry["providers"]) == expected_providers,
                "catalog provider-backed reference mismatch")
        require(entry["frontend_status"] == ("PARTIAL" if expected_providers else "UNSUPPORTED"), "catalog must be provider-backed before promotion")
        require(isinstance(entry["backend_refs"], list), "catalog backend refs must be an array")
        for ref in entry["backend_refs"]:
            fields(ref, ("path", "symbol"), "backend source reference")
            source = read(ref["path"])
            if ref["symbol"] is not None:
                nonempty(ref["symbol"], "backend source symbol")
                require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ref["symbol"]), "invalid backend reference symbol")
                definition(source, ref["symbol"])
        expected_backend = {a["name"] for a in manifest["backend_apis"] if family in a["families"]}
        require(isinstance(entry["backend_apis"], list) and all(isinstance(n, str) for n in entry["backend_apis"]) and
                len(set(entry["backend_apis"])) == len(entry["backend_apis"]) and set(entry["backend_apis"]) == expected_backend,
                "catalog backend API references do not match source inventory")
        backend_status = "PARTIAL" if expected_backend else "SOURCE_PRESENT_UNINVENTORIED" if entry["backend_refs"] else "NOT_INVENTORIED"
        require(entry["backend_source_status"] == backend_status, "catalog backend source status must not imply unsupported/absent code")
        nonempty(entry["boundary"], "catalog boundary")
    require(families == set(wanted_families), "architectural family coverage is incomplete")
    require(all(set(a["families"]) <= families for a in manifest["backend_apis"]), "unknown backend family reference")
    return {
        "schema": "shizuku.wrapper-capabilities.receipt.v1", "manifest_schema": SCHEMA,
        "baseline_commit": manifest["baseline_commit"], "validation_scope": "source_inventory",
        "behavior_tests_run": False, "evidence_execution": "not_run", "win98_win64_positive": False,
        "win98_pma_positive": False, "windows98_dos_replacement_verified": False,
        "architecture": manifest["architecture"], "family_count": len(families), "api_count": len(expanded),
        "advertised_masks": masks, "apis": expanded, "catalog": manifest["catalog"],
        "backend_api_count": len(backend_names), "backend_apis": manifest["backend_apis"],
        "evidence": manifest["evidence"], "source_sha256": dict(sorted(hashes.items())),
    }


def load_manifest(path):
    def unique_pairs(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "duplicate JSON field: " + key)
            out[key] = value
        return out
    return json.loads(Path(path).read_text(), object_pairs_hook=unique_pairs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=HERE / "manifest.json")
    parser.add_argument("--out", type=Path, help="Explicitly write a fresh JSON receipt; otherwise read-only stdout")
    args = parser.parse_args(argv)
    try:
        report = validate_manifest(load_manifest(args.manifest))
        report["manifest_sha256"] = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
        report["validator_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.out is not None:
            require(args.out.resolve().is_relative_to((ROOT / "build").resolve()), "receipt output must be under project build/")
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(encoded)
            print("PASS: source capability inventory: %d families, %d frontend APIs, %d backend APIs; receipt %s; behavior/native tests not run" %
                  (report["family_count"], report["api_count"], report["backend_api_count"], args.out))
        else:
            print(encoded, end="")
        return 0
    except (ValidationError, OSError, ValueError) as error:
        print("FAIL: capability inventory: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
