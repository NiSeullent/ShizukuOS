/* SPDX-License-Identifier: GPL-2.0-only
 * Original selected semantic checks, not a Test262/conformance certification.
 * Contracts: https://tc39.es/ecma262/2026/multipage/keyed-collections.html
 * https://tc39.es/ecma262/2026/multipage/control-abstraction-objects.html
 * https://tc39.es/ecma262/2026/multipage/indexed-collections.html
 * Run against the real embedded interpreter, without feature polyfills.
 */
(() => {
    "use strict";
    let checks = 0;
    const equal = (actual, expected, name) => {
        if (!Object.is(actual, expected)) throw new Error(name);
        ++checks;
    };
    const throws = (fn, kind, name) => {
        let exception;
        try { fn(); } catch (error) { exception = error; }
        if (!(exception instanceof kind)) throw new Error(name);
        ++checks;
    };
    const map = new Map([["present", undefined]]);
    equal(map.getOrInsert("present", 7), undefined, "existing undefined value");
    equal(map.getOrInsert("new", 8), 8, "inserted value");
    equal(map.get("new"), 8, "insertion persists");
    equal(map.getOrInsert(-0, "zero"), "zero", "minus zero insertion");
    equal(map.getOrInsert(0, "other"), "zero", "zero key canonicalization");
    let calls = 0;
    equal(map.getOrInsertComputed("new", () => { ++calls; return 99; }), 8,
          "existing computed value");
    equal(calls, 0, "existing key skips callback");
    equal(map.getOrInsertComputed("computed", key => {
        ++calls; equal(key, "computed", "callback receives key"); return 17;
    }), 17, "computed insertion");
    equal(calls, 1, "callback exactly once");
    throws(() => map.getOrInsertComputed("new", null), TypeError,
           "callability validated even for existing key");
    throws(() => Map.prototype.getOrInsert.call({}, "x", 1), TypeError,
           "Map internal slot required");
    const weak = new WeakMap(), key = {};
    equal(weak.getOrInsert(key, 3), 3, "weak insertion");
    equal(weak.getOrInsertComputed(key, () => 9), 3, "weak existing value");
    throws(() => weak.getOrInsert(1, 2), TypeError, "weak primitive rejection");
    equal(Array.from(Iterator.concat([1, 2], new Set([3, 4]))).join(","),
          "1,2,3,4", "iterator concatenation order");
    equal(Iterator.concat().next().done, true, "empty concatenation");
    throws(() => Iterator.concat(1), TypeError, "nonobject iterable rejection");
    let closed = 0;
    function* source() { try { yield 1; yield 2; } finally { ++closed; } }
    const joined = Iterator.concat(source(), [3]);
    equal(joined.next().value, 1, "first iterator opens lazily");
    joined.return();
    equal(closed, 1, "return closes active iterator");
    const bytes = new Uint8Array([0, 1, 254, 255]);
    equal(bytes.toBase64(), "AAH+/w==", "base64 encoding");
    equal(Uint8Array.fromBase64("AAH+/w==").join(","), "0,1,254,255",
          "base64 decoding");
    equal(bytes.toBase64({ alphabet: "base64url", omitPadding: true }),
          "AAH-_w", "base64url encoding");
    throws(() => Uint8Array.fromBase64(7), TypeError, "base64 string required");
    throws(() => Uint8Array.fromBase64("AA", { alphabet: "invalid" }), TypeError,
           "invalid alphabet rejection");
    throws(() => Uint8Array.fromBase64("***"), SyntaxError,
           "malformed base64 rejection");
    equal(bytes.toHex(), "0001feff", "hex encoding");
    equal(Uint8Array.fromHex("0001FEff").join(","), "0,1,254,255",
          "hex decoding case");
    throws(() => Uint8Array.fromHex("abc"), SyntaxError, "odd hex rejection");
    equal(null?.field ?? "fallback", "fallback", "optional/nullish syntax");
    class Counter { #value = 40n; get() { return this.#value + 2n; } }
    equal(new Counter().get().toString(), "42", "private field and BigInt");
    equal("\ud800".isWellFormed(), false, "lone surrogate detection");
    equal("\ud800".toWellFormed(), "\ufffd", "well-formed conversion");
    equal(new Set([1, 2]).union(new Set([2, 3])).size, 3, "Set union");
    return JSON.stringify({ scope: "selected ES2026 semantic checks", checks,
        full_conformance_verified: false, browser_dom_verified: false });
})();
