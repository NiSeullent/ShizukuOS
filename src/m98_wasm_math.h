/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_WASM_MATH_H
#define M98_WASM_MATH_H
#include <stdint.h>
int __ctzdi2(uint64_t);
double m98_wasm_ceil(double),m98_wasm_floor(double),m98_wasm_trunc(double),m98_wasm_rint(double),m98_wasm_sqrt(double);
float m98_wasm_ceilf(float),m98_wasm_floorf(float),m98_wasm_truncf(float),m98_wasm_rintf(float),m98_wasm_sqrtf(float);
int m98_wasm_isnan(double),m98_wasm_signbit(double);
/* Applied after <math.h> in the custom platform header/prepared upstream unit. */
#ifdef M98_WASM_MATH_MAP
#undef ceil
#undef floor
#undef trunc
#undef rint
#undef sqrt
#undef ceilf
#undef floorf
#undef truncf
#undef rintf
#undef sqrtf
#undef isnan
#undef signbit
#define ceil m98_wasm_ceil
#define floor m98_wasm_floor
#define trunc m98_wasm_trunc
#define rint m98_wasm_rint
#define sqrt m98_wasm_sqrt
#define ceilf m98_wasm_ceilf
#define floorf m98_wasm_floorf
#define truncf m98_wasm_truncf
#define rintf m98_wasm_rintf
#define sqrtf m98_wasm_sqrtf
#define isnan m98_wasm_isnan
#define signbit m98_wasm_signbit
#endif
#endif
