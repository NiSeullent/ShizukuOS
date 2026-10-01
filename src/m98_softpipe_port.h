/* SPDX-License-Identifier: GPL-2.0-only
 * Reviewed preparation boundary for selected original Mesa C sources. */
#ifndef M98_SOFTPIPE_PORT_H
#define M98_SOFTPIPE_PORT_H
#include <stddef.h>
#include <math.h>
void *m98_sp_heap_alloc(size_t);
void *m98_sp_heap_calloc(size_t,size_t);
void *m98_sp_heap_realloc(void *,size_t);
void m98_sp_heap_free(void *);
void *m98_sp_heap_aligned(size_t,size_t);
float m98_sp_math_cosf(float); float m98_sp_math_sinf(float);
float m98_sp_math_logf(float); float m98_sp_math_powf(float,float);
float m98_sp_math_sqrtf(float); float m98_sp_math_floorf(float);
float m98_sp_math_ceilf(float); float m98_sp_math_ldexpf(float,int);
float m98_sp_math_truncf(float); float m98_sp_math_rintf(float);
float m98_sp_math_fabsf(float); float m98_sp_math_fmaxf(float,float);
float m98_sp_math_fminf(float,float);
long m98_sp_math_lrintf(float); int m98_sp_ffs(int);
double m98_sp_math_floor(double); double m98_sp_math_sqrt(double);
double m98_sp_math_ldexp(double,int); double m98_sp_math_rint(double);
double m98_sp_math_fmin(double,double); double m98_sp_math_fmax(double,double);
/* Math headers have already been read before aliases affect Mesa call sites. */
#define cosf m98_sp_math_cosf
#define sinf m98_sp_math_sinf
#define logf m98_sp_math_logf
#define powf m98_sp_math_powf
#define sqrtf m98_sp_math_sqrtf
#define floorf m98_sp_math_floorf
#define ceilf m98_sp_math_ceilf
#define ldexpf m98_sp_math_ldexpf
#define truncf m98_sp_math_truncf
#define rintf m98_sp_math_rintf
#define fabsf m98_sp_math_fabsf
#define fmaxf m98_sp_math_fmaxf
#define fminf m98_sp_math_fminf
#define lrintf m98_sp_math_lrintf
#define ffs m98_sp_ffs
#define floor m98_sp_math_floor
#define sqrt m98_sp_math_sqrt
#define ldexp m98_sp_math_ldexp
#define rint m98_sp_math_rint
#define fmin m98_sp_math_fmin
#define fmax m98_sp_math_fmax
#endif
