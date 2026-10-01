// Bounded genuine WebAssembly C-API probe inputs; no replacement engine.
// Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
#pragma once

struct Wasm83bdCase {
    const char* name;
    const char* script;
};

// Each case must return a Boolean through actual JSEvaluateScript. State lives
// only in this newly created test context. No page, polyfill, network or GPU.
static const Wasm83bdCase wasm83bdCases[] = {
    { "wasm.api", R"JS((() => typeof WebAssembly === 'object' &&
        typeof WebAssembly.validate === 'function' &&
        typeof WebAssembly.Module === 'function' &&
        typeof WebAssembly.Instance === 'function')())JS" },
    { "wasm.validate-module", R"JS((() => {
        // Three real functions: i32 answer=42, i64 wide=42n, load8_u(address).
        const bytes = new Uint8Array([
            0,97,115,109,1,0,0,0,
            1,14,3,96,0,1,127,96,0,1,126,96,1,127,1,127,
            3,4,3,0,1,2,
            5,4,1,1,1,2,
            7,33,4,6,97,110,115,119,101,114,0,0,
                4,119,105,100,101,0,1,
                4,114,101,97,100,0,2,
                6,109,101,109,111,114,121,2,0,
            10,19,3,4,0,65,42,11,4,0,66,42,11,7,0,32,0,45,0,0,11
        ]);
        if (!WebAssembly.validate(bytes)) return false;
        const module = new WebAssembly.Module(bytes);
        const instance = new WebAssembly.Instance(module, {});
        globalThis.__wasm83bd = { bytes, module, instance };
        return WebAssembly.Module.imports(module).length === 0 &&
            WebAssembly.Module.exports(module).length === 4;
    })())JS" },
    { "wasm.execute-i32", R"JS((() =>
        __wasm83bd.instance.exports.answer() === 42)())JS" },
    { "wasm.i64-bigint", R"JS((() =>
        __wasm83bd.instance.exports.wide() === 42n)())JS" },
    { "wasm.memory-load-grow", R"JS((() => {
        const exports = __wasm83bd.instance.exports;
        const old = exports.memory.buffer;
        if (old.byteLength !== 65536) return false;
        new Uint8Array(old)[0] = 73;
        if (exports.read(0) !== 73 || exports.memory.grow(1) !== 1) return false;
        const grown = exports.memory.buffer;
        if (old.byteLength !== 0 || grown.byteLength !== 131072 ||
            new Uint8Array(grown)[0] !== 73 || exports.read(0) !== 73) return false;
        try { exports.memory.grow(1); return false; }
        catch (error) { return error instanceof RangeError; }
    })())JS" },
    { "wasm.bounds-trap", R"JS((() => {
        try { __wasm83bd.instance.exports.read(131072); return false; }
        catch (error) { return error instanceof WebAssembly.RuntimeError; }
    })())JS" },
    { "wasm.invalid-module-control", R"JS((() => {
        const malformed = new Uint8Array([0,97,115,109,1,0,0,0,255]);
        if (WebAssembly.validate(malformed)) return false;
        try { new WebAssembly.Module(malformed); return false; }
        catch (error) { return error instanceof WebAssembly.CompileError; }
    })())JS" },
    { "wasm.table-function", R"JS((() => {
        const table = new WebAssembly.Table({ element: 'anyfunc', initial: 1, maximum: 2 });
        table.set(0, __wasm83bd.instance.exports.answer);
        if (table.get(0)() !== 42 || table.grow(1) !== 1 || table.length !== 2 ||
            table.get(1) !== null) return false;
        try { table.grow(1); return false; }
        catch (error) { return error instanceof RangeError; }
    })())JS" }
};
