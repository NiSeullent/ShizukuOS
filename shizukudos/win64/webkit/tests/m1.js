// SPDX-License-Identifier: GPL-2.0-only
// W1 M1 probe for jsc.exe on Kernel64 (tests/run_k64_webkit.py). Every part computes a value, compares it with the
// expected literal and records it; the last line is printed from an async continuation (so it only appears if the
// microtask queue ran) and carries an FNV-1a hash of all recorded values, which the runner recomputes on the host from
// its own copy of the expected values. Any mismatch throws, so jsc exits non-zero and no marker line is printed.
"use strict";
const results = [];
function check(name, got, want) {
    const g = String(got);
    print("W1 " + name + " = " + g);
    if (g !== want)
        throw new Error("W1 mismatch in " + name + ": got " + JSON.stringify(g) + " want " + JSON.stringify(want));
    results.push(name + "=" + g);
}

// closures
function counter() { let n = 0; return () => ++n; }
const c = counter(); c(); c();
check("closure", c() * 10 + [1, 2, 3].map(x => (y => x * y)(x)).reduce((a, b) => a + b), "44");

// JSON round trip with nesting, escapes, reviver
const j = JSON.parse(JSON.stringify({ a: [1, 2, { b: "xé\n" }], n: null, t: true }), (k, v) => typeof v === "number" ? v * 3 : v);
check("json", JSON.stringify(j), '{"a":[3,6,{"b":"xé\\n"}],"n":null,"t":true}');

// RegExp: captures, named groups, unicode, sticky, lookbehind, global replace with a function
const m = /(\d+)-(\w+)/.exec("id 42-abc!");
check("regexp", m[1] * 2 + m[2].toUpperCase() + "|" +
      "2026-09-30".replace(/(?<y>\d{4})-(?<m>\d\d)-(?<d>\d\d)/u, "$<d>.$<m>.$<y>") + "|" +
      "a1b22c333".replace(/\d+/g, s => s.length) + "|" + /(?<=\$)\d+/.exec("cost $75")[0] + "|" +
      /\p{Script=Greek}+/u.exec("abc αβγ def")[0].length, "84ABC|30.09.2026|a1b2c3|75|3");

// Date (UTC only: the guest has no time zone database)
const d = new Date(Date.UTC(2000, 1, 29, 12, 34, 56, 789));
check("date", d.toISOString() + "|" + d.getUTCDay() + "|" + Date.parse("2001-02-03T04:05:06Z") + "|" +
      new Date(8.64e15 + 1).getTime(), "2000-02-29T12:34:56.789Z|2|981173106000|NaN");

// typed arrays, DataView, endianness
const f64 = new Float64Array([1.5, -2.25]);
const u8 = new Uint8Array(f64.buffer);
let h = 0;
for (const b of u8) h = (Math.imul(h, 31) + b) >>> 0;
const dv = new DataView(new ArrayBuffer(8));
dv.setUint32(0, 0xdeadbeef); dv.setInt16(4, -2, true);
check("typedarray", h + "|" + dv.getUint8(0).toString(16) + dv.getUint8(3).toString(16) + "|" + dv.getUint16(4) + "|" +
      Array.from(new Int8Array([127, -128, 5]).map(x => x + 1)).join(","), "603777093|deef|65279|-128,-127,6");

// numbers: shortest round-trip formatting, fixed/exponential/precision, parse
check("number", (0.1 + 0.2) + "|" + (123.456).toFixed(2) + "|" + (1e21) + "|" + (255).toString(16) + "|" +
      (0.000001234).toExponential(2) + "|" + Math.PI.toPrecision(10) + "|" + parseFloat("3.25e2x") + "|" +
      Number.MAX_SAFE_INTEGER + "|" + (2 ** -1074), "0.30000000000000004|123.46|1e+21|ff|1.23e-6|3.141592654|325|9007199254740991|5e-324");

// Math (results chosen to be exact or correctly rounded in any conforming libm)
check("math", Math.sqrt(2) + "|" + Math.floor(-0.5) + "|" + Math.hypot(3, 4) + "|" + Math.round(2.5) + "|" +
      Math.trunc(-4.7) + "|" + Math.sign(-3) + "|" + Math.clz32(1) + "|" + Math.fround(5.5), "1.4142135623730951|-1|5|3|-4|-1|31|5.5");

// language features: classes with private fields, generators, destructuring, spread, Map/Set, Symbol, Proxy, BigInt
class P { #x; constructor(x) { this.#x = x; } get twice() { return this.#x * 2; } static of(x) { return new P(x); } }
function* gen(n) { for (let i = 0; i < n; i++) yield i * i; }
const [first, , third, ...rest] = [...gen(6)];
const map = new Map([["k", 1]]); map.set("j", 2);
const set = new Set("mississippi");
const px = new Proxy({}, { get: (t, k) => typeof k === "string" ? k.length : 0 });
check("lang", P.of(21).twice + "|" + first + third + rest.join("") + "|" + [...map.keys()].join("") + "|" + [...set].join("") +
      "|" + px.hello + "|" + (2n ** 100n % 1000007n) + "|" + typeof Symbol.iterator + "|" + `${1 + 1}x`,
      "42|0491625|kj|misp|5|698635|symbol|2x");

// strings: Unicode, normalization, case mapping, padding, localeCompare fallback
check("string", "ǅ".toLowerCase() + "Straße".toUpperCase() + "|" + "é".normalize("NFC").length + "|" +
      "abc".padStart(6, "12") + "|" + [..."a😀b"].length + "|" + "x".codePointAt(0) + "|" + "  trim ".trim(),
      "ǆSTRASSE|1|121abc|3|120|trim");

// Intl (only when jsc was built with ICU data; the probe reports which)
const hasIntl = typeof Intl === "object";
if (hasIntl) {
    check("intl", new Intl.NumberFormat("en-US").format(1234567.891) + "|" + new Intl.NumberFormat("de-DE").format(1234567.891) + "|" +
          new Intl.DateTimeFormat("en-US", { timeZone: "UTC" }).format(d) + "|" + ["b", "a", "C"].sort(new Intl.Collator("en").compare).join("") +
          "|" + new Intl.PluralRules("en-US").select(1) + new Intl.PluralRules("en-US").select(2),
          "1,234,567.891|1.234.567,891|2/29/2000|abC|oneother");
}

// Promise / async: the order of synchronous code, promise jobs and async continuations
const order = [];
async function twice(x) { await null; order.push("await"); return x * 2; }
Promise.resolve().then(() => order.push("job"));
order.push("sync");
twice(21).then(v => {
    order.push("async" + v);
    return Promise.all([1, Promise.resolve(2), new Promise(r => r(3))]);
}).then(all => {
    check("promise", order.join(",") + "|" + all.join(""), "sync,job,await,async42|123");
    let hash = 0x811c9dc5;
    const text = results.join(";");
    for (let i = 0; i < text.length; i++) {
        hash ^= text.charCodeAt(i);
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    print("W1-JSC-M1 OK parts=" + results.length + " intl=" + (hasIntl ? 1 : 0) + " fnv=" + hash.toString(16).padStart(8, "0"));
});
