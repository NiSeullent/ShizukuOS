/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_TRIDENT_SCRIPT_PORT_H
#define M98_TRIDENT_SCRIPT_PORT_H
#include <stddef.h>
#include <stdarg.h>
int m98_qjs_snprintf(char *,size_t,const char *,...);
int m98_qjs_vsnprintf(char *,size_t,const char *,va_list);
int m98_script_legacy_vsnprintf(char *,size_t,const char *,va_list);
void *m98_script_scratch_alloc(size_t);
void m98_script_scratch_free(void *);
/* Declared after the system math header, so these are owned functions rather
 * than MinGW dllimport or a silently selected prebuilt modern helper. */
#define M98_UNARY(name) double m98_math_##name(double)
M98_UNARY(sin);M98_UNARY(cos);M98_UNARY(tan);M98_UNARY(acos);M98_UNARY(asin);
M98_UNARY(atan);M98_UNARY(exp);M98_UNARY(log);M98_UNARY(log10);M98_UNARY(sqrt);
M98_UNARY(floor);M98_UNARY(ceil);M98_UNARY(fabs);M98_UNARY(sinh);M98_UNARY(cosh);
M98_UNARY(tanh);M98_UNARY(acosh);M98_UNARY(asinh);M98_UNARY(atanh);M98_UNARY(expm1);
M98_UNARY(log1p);M98_UNARY(log2);M98_UNARY(cbrt);M98_UNARY(trunc);
#undef M98_UNARY
double m98_math_atan2(double,double);double m98_math_fmod(double,double);
double m98_math_pow(double,double);double m98_math_hypot(double,double);
double m98_math_fmin(double,double);double m98_math_fmax(double,double);
double m98_math_frexp(double,int *);double m98_math_ldexp(double,int);
long double m98_math_sqrtl(long double);
#ifdef M98_SCRIPT_MATH_MAP
#define sin m98_math_sin
#define cos m98_math_cos
#define tan m98_math_tan
#define acos m98_math_acos
#define asin m98_math_asin
#define atan m98_math_atan
#define atan2 m98_math_atan2
#define exp m98_math_exp
#define log m98_math_log
#define log10 m98_math_log10
#define sqrt m98_math_sqrt
#define sqrtl m98_math_sqrtl
#define floor m98_math_floor
#define ceil m98_math_ceil
#define fabs m98_math_fabs
#define fmod m98_math_fmod
#define frexp m98_math_frexp
#define ldexp m98_math_ldexp
#define sinh m98_math_sinh
#define cosh m98_math_cosh
#define tanh m98_math_tanh
#define acosh m98_math_acosh
#define asinh m98_math_asinh
#define atanh m98_math_atanh
#define expm1 m98_math_expm1
#define log1p m98_math_log1p
#define log2 m98_math_log2
#define cbrt m98_math_cbrt
#define trunc m98_math_trunc
#define pow m98_math_pow
#define hypot m98_math_hypot
#define fmin m98_math_fmin
#define fmax m98_math_fmax
#endif
#ifdef M98_SCRIPT_FORMAT_MAP
#define snprintf m98_qjs_snprintf
#define vsnprintf m98_qjs_vsnprintf
#endif
#endif
