// Genuine JavaScriptCore C API caller for the original Win98 SE target.
// Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
// No browser, document renderer, network, or replacement JS implementation.
#include "config.h"
#include <JavaScriptCore/JavaScript.h>
#include "wasm_cases.h"
#include <windows.h>
#include <cstdio>
#include <cstring>

static HANDLE logHandle = INVALID_HANDLE_VALUE;

static bool line(const char* name, const char* value)
{
    char buffer[1024];
    int length = std::snprintf(buffer, sizeof(buffer), "%s=%s\r\n", name, value);
    DWORD written = 0;
    return length > 0 && static_cast<size_t>(length) < sizeof(buffer)
        && WriteFile(logHandle, buffer, static_cast<DWORD>(length), &written, nullptr)
        && written == static_cast<DWORD>(length) && FlushFileBuffers(logHandle);
}

static bool flag(const char* name, bool value)
{
    return line(name, value ? "1" : "0");
}

static JSValueRef evaluate(JSGlobalContextRef context, const char* code, JSValueRef* exception)
{
    JSStringRef script = JSStringCreateWithUTF8CString(code);
    if (!script)
        return nullptr;
    JSValueRef result = JSEvaluateScript(context, script, nullptr, nullptr, 1, exception);
    JSStringRelease(script);
    return result;
}

int main(int argc, char** argv)
{
    if (argc != 3 || std::strcmp(argv[1], "C:\\GOPLAB\\WASM83BD.LOG")
        || !std::strlen(argv[2]) || std::strlen(argv[2]) > 80
        || std::strspn(argv[2], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::strlen(argv[2]))
        return 10;
    // A stale log must never be reused as fresh native execution evidence.
    logHandle = CreateFileA(argv[1], GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (logHandle == INVALID_HANDLE_VALUE)
        return 2;
    bool logs = line("scope", "actual-pinned-JavaScriptCore-Wasm-subset") && line("nonce", argv[2]);
    OSVERSIONINFOA version { };
    version.dwOSVersionInfoSize = sizeof(version);
    bool target = GetVersionExA(&version) && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS
        && version.dwMajorVersion == 4 && version.dwMinorVersion == 10
        && LOWORD(version.dwBuildNumber) == 2222;
    char text[64];
    std::snprintf(text, sizeof(text), "%lu.%lu.%lu", version.dwMajorVersion,
        version.dwMinorVersion, static_cast<unsigned long>(LOWORD(version.dwBuildNumber)));
    logs = line("os.version", text) && flag("os.exact-target", target) && logs;
    if (!target || !logs) {
        line("exit", "3");
        CloseHandle(logHandle);
        return 3;
    }
    // Persist the stage before entering real engine initialization, which may
    // abort if another actual Win9x portability dependency remains unresolved.
    logs = flag("build.c-loop", ENABLE_C_LOOP) && logs;
    logs = flag("build.jit", ENABLE_JIT) && logs;
    logs = flag("build.webassembly", ENABLE_WEBASSEMBLY) && logs;
    logs = flag("full-browser-pass", false) && logs;
    if (!logs || !line("stage", "before-JSContextGroupCreate")) {
        CloseHandle(logHandle);
        return 4;
    }
    JSContextGroupRef group = JSContextGroupCreate();
    logs = flag("jsc.group.created", group != nullptr) && logs;
    JSGlobalContextRef context = group ? JSGlobalContextCreateInGroup(group, nullptr) : nullptr;
    logs = flag("jsc.context.created", context != nullptr) && logs;
    if (!context) {
        if (group)
            JSContextGroupRelease(group);
        line("exit", "5");
        CloseHandle(logHandle);
        return 5;
    }
    JSValueRef exception = nullptr;
    JSValueRef value = evaluate(context,
        "(() => { const m=new Map([['a',40],['b',2]]); return [...m.values()].reduce((a,b)=>a+b,0); })()", &exception);
    bool arithmetic = value && !exception && JSValueIsNumber(context, value)
        && JSValueToNumber(context, value, &exception) == 42 && !exception;
    logs = flag("jsc.arithmetic-map-arrow", arithmetic) && logs;
    exception = nullptr;
    value = evaluate(context,
        "('e\\u0301').normalize('NFC')==='\\u00e9' && /\\p{Letter}+/u.test('\\u03b1')", &exception);
    bool unicode = value && !exception && JSValueIsBoolean(context, value) && JSValueToBoolean(context, value);
    logs = flag("jsc.unicode-normalization-regexp", unicode) && logs;
    exception = nullptr;
    value = evaluate(context, "((2n ** 70n)+1n).toString()==='1180591620717411303425'", &exception);
    bool bigInteger = value && !exception && JSValueIsBoolean(context, value) && JSValueToBoolean(context, value);
    logs = flag("jsc.bigint", bigInteger) && logs;
    exception = nullptr;
    value = evaluate(context, "new Intl.NumberFormat('en-US',{useGrouping:true}).format(1234567)==='1,234,567'", &exception);
    bool international = value && !exception && JSValueIsBoolean(context, value) && JSValueToBoolean(context, value);
    logs = flag("jsc.icu-intl-numberformat", international) && logs;
    exception = nullptr;
    value = evaluate(context, "throw new Error('83bd-native-exception-control')", &exception);
    bool exceptionControl = !value && exception && JSValueIsObject(context, exception);
    logs = flag("jsc.exception-control", exceptionControl) && logs;
    bool wasmSubset = ENABLE_WEBASSEMBLY;
    for (const auto& test : wasm83bdCases) {
        exception = nullptr;
        if (!line("stage", test.name)) {
            logs = false;
            wasmSubset = false;
            break;
        }
        value = evaluate(context, test.script, &exception);
        bool passed = value && !exception && JSValueIsBoolean(context, value)
            && JSValueToBoolean(context, value);
        logs = flag(test.name, passed) && logs;
        wasmSubset = passed && wasmSubset;
    }
    logs = flag("wasm.subset", wasmSubset) && logs;
    // Exercise genuine C API collection and release, without claiming that a
    // log before return proves subsequent CRT/TLS process teardown succeeded.
    JSGarbageCollect(context);
    logs = flag("jsc.gc.returned", true) && logs;
    JSGlobalContextRelease(context);
    logs = flag("jsc.context.released", true) && logs;
    JSContextGroupRelease(group);
    logs = flag("jsc.group.released", true) && logs;
    bool success = arithmetic && unicode && bigInteger && international && exceptionControl && wasmSubset && logs;
    if (!line("exit", success ? "0" : "6"))
        success = false;
    CloseHandle(logHandle);
    return success ? 0 : 6;
}
