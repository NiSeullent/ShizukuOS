/* SPDX-License-Identifier: GPL-2.0-only
 * Original selected numeric semantics for the ported interpreter/math seam.
 * https://tc39.es/ecma262/2026/multipage/numbers-and-dates.html
 * Exact special values and binary rounding are tested, plus explicitly
 * tolerant near-zero checks. This is not complete mathematical conformance.
 */
(() => {
    "use strict";
    let checks = 0;
    const equal = (actual, expected, name) => {
        if (!Object.is(actual, expected)) throw new Error(name);
        ++checks;
    };
    const close = (actual, expected, tolerance, name) => {
        if (!Number.isFinite(actual) || Math.abs(actual - expected) > tolerance)
            throw new Error(name);
        ++checks;
    };
    equal(Math.expm1(-0), -0, "expm1 signed zero");
    equal(Math.expm1(-Infinity), -1, "expm1 negative infinity");
    equal(Math.log1p(-0), -0, "log1p signed zero");
    equal(Math.log1p(-1), -Infinity, "log1p boundary");
    equal(Math.log1p(-2), NaN, "log1p domain");
    close(Math.expm1(1e-16), 1e-16, 1e-30, "expm1 near zero");
    close(Math.log1p(1e-16), 1e-16, 1e-30, "log1p near zero");
    equal(Math.asinh(-0), -0, "asinh signed zero");
    equal(Math.acosh(1), 0, "acosh boundary");
    equal(Math.atanh(1), Infinity, "atanh boundary");
    equal(Math.hypot(NaN, Infinity), Infinity, "hypot infinity precedence");
    equal(Math.hypot(-0, -0), 0, "hypot positive zero");
    close(Math.hypot(1e308, 1e308) / 1e308, Math.SQRT2, 1e-14,
          "hypot avoids intermediate overflow");
    equal(Math.pow(-0, -3), -Infinity, "pow signed zero");
    equal(Math.trunc(-0.75), -0, "trunc signed zero");
    equal(Math.imul(0xffffffff, 5), -5, "imul signed overflow");
    equal(Math.sqrt(-1), NaN, "sqrt domain");
    equal(Math.fround(1.337), 1.3370000123977661, "binary32 rounding");
    equal(Math.f16round(1.00048828125000022204), 1.0009765625,
          "binary16 avoids double rounding");
    equal(Math.f16round(-0), -0, "binary16 signed zero");
    equal(Math.sumPrecise([1e16, 1, -1e16]), 1, "precise cancellation");
    equal(Date.UTC(2000, 1, 29), 951782400000, "UTC leap day");
    equal(new Date(951782400000).toISOString(), "2000-02-29T00:00:00.000Z",
          "ISO conversion");
    equal(new Date(8640000000000001).getTime(), NaN, "Date clipping boundary");
    return JSON.stringify({ scope: "selected numeric semantics", checks,
        full_conformance_verified: false, native_math_verified: false });
})();
