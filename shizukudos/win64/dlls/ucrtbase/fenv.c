/* SPDX-License-Identifier: GPL-2.0-only
 * Floating-point environment: _controlfp / _control87 / _controlfp_s / _clearfp / _statusfp / _fpreset and the C99
 * <fenv.h> functions, over the SSE control/status register (MXCSR) and, for consistency with the Microsoft CRT on x64,
 * the x87 control/status words as well. The "abstract" control word uses Microsoft's <float.h> encoding:
 *   _EM_INEXACT 0x1 _EM_UNDERFLOW 0x2 _EM_OVERFLOW 0x4 _EM_ZERODIVIDE 0x8 _EM_INVALID 0x10 _EM_DENORMAL 0x80000,
 *   _RC_DOWN 0x100 _RC_UP 0x200 _RC_CHOP 0x300, _DN_FLUSH 0x01000000 (flush-to-zero + denormals-are-zero);
 * status words: _SW_INEXACT 0x1 _SW_UNDERFLOW 0x2 _SW_OVERFLOW 0x4 _SW_ZERODIVIDE 0x8 _SW_INVALID 0x10 _SW_DENORMAL 0x80000.
 * <fenv.h>: FE_TONEAREST 0, FE_DOWNWARD 0x100, FE_UPWARD 0x200, FE_TOWARDZERO 0x300; the exception bits are the _SW_ ones.
 */
#include "crtint.h"

#define EM_INEXACT 0x1u
#define EM_UNDERFLOW 0x2u
#define EM_OVERFLOW 0x4u
#define EM_ZERODIVIDE 0x8u
#define EM_INVALID 0x10u
#define EM_DENORMAL 0x80000u
#define MCW_EM 0x8001fu
#define MCW_RC 0x300u
#define MCW_DN 0x03000000u
#define DN_FLUSH 0x01000000u
#define MCW_PC 0x30000u
#define MCW_IC 0x40000u

static unsigned get_mxcsr(void) { unsigned v; __asm__ volatile("stmxcsr %0" : "=m"(v)); return v; }
static void set_mxcsr(unsigned v) { __asm__ volatile("ldmxcsr %0" : : "m"(v)); }
static unsigned short get_x87cw(void) { unsigned short v; __asm__ volatile("fnstcw %0" : "=m"(v)); return v; }
static void set_x87cw(unsigned short v) { __asm__ volatile("fldcw %0" : : "m"(v)); }
static unsigned short get_x87sw(void) { unsigned short v; __asm__ volatile("fnstsw %0" : "=m"(v)); return v; }

/* MXCSR -> abstract control word */
static unsigned cw_from_mxcsr(unsigned m)
{
    unsigned cw = 0;
    if (m & 0x0080) cw |= EM_INVALID;
    if (m & 0x0100) cw |= EM_DENORMAL;
    if (m & 0x0200) cw |= EM_ZERODIVIDE;
    if (m & 0x0400) cw |= EM_OVERFLOW;
    if (m & 0x0800) cw |= EM_UNDERFLOW;
    if (m & 0x1000) cw |= EM_INEXACT;
    switch ((m >> 13) & 3) {
    case 1: cw |= 0x100; break;                               /* toward -inf: _RC_DOWN */
    case 2: cw |= 0x200; break;                               /* toward +inf: _RC_UP */
    case 3: cw |= 0x300; break;                               /* toward zero: _RC_CHOP */
    default: break;
    }
    if ((m & 0x8040) == 0x8040) cw |= DN_FLUSH;
    else if (m & 0x8000) cw |= 0x03000000u;                   /* _DN_SAVE_OPERANDS_FLUSH_RESULTS */
    else if (m & 0x0040) cw |= 0x02000000u;                   /* _DN_FLUSH_OPERANDS_SAVE_RESULTS */
    return cw;
}
static unsigned mxcsr_from_cw(unsigned cw, unsigned m)
{
    m &= ~(0x1f80u | 0x6000u | 0x8040u);
    if (cw & EM_INVALID) m |= 0x0080;
    if (cw & EM_DENORMAL) m |= 0x0100;
    if (cw & EM_ZERODIVIDE) m |= 0x0200;
    if (cw & EM_OVERFLOW) m |= 0x0400;
    if (cw & EM_UNDERFLOW) m |= 0x0800;
    if (cw & EM_INEXACT) m |= 0x1000;
    switch (cw & MCW_RC) {
    case 0x100: m |= 1u << 13; break;
    case 0x200: m |= 2u << 13; break;
    case 0x300: m |= 3u << 13; break;
    default: break;
    }
    switch (cw & MCW_DN) {
    case DN_FLUSH: m |= 0x8040; break;
    case 0x02000000u: m |= 0x0040; break;
    case 0x03000000u: m |= 0x8000; break;
    default: break;
    }
    return m;
}
static unsigned short x87cw_from_cw(unsigned cw, unsigned short x)
{
    x &= (unsigned short)~0x0c3fu;
    if (cw & EM_INVALID) x |= 0x01;
    if (cw & EM_DENORMAL) x |= 0x02;
    if (cw & EM_ZERODIVIDE) x |= 0x04;
    if (cw & EM_OVERFLOW) x |= 0x08;
    if (cw & EM_UNDERFLOW) x |= 0x10;
    if (cw & EM_INEXACT) x |= 0x20;
    switch (cw & MCW_RC) {
    case 0x100: x |= 0x0400; break;
    case 0x200: x |= 0x0800; break;
    case 0x300: x |= 0x0c00; break;
    default: break;
    }
    return x;
}
static unsigned status_from(unsigned m, unsigned short x)
{
    unsigned s = 0;
    const unsigned f = (m & 0x3f) | (x & 0x3f);
    if (f & 0x01) s |= 0x10;                                   /* invalid */
    if (f & 0x02) s |= 0x80000;                                /* denormal */
    if (f & 0x04) s |= 0x08;                                   /* zero divide */
    if (f & 0x08) s |= 0x04;                                   /* overflow */
    if (f & 0x10) s |= 0x02;                                   /* underflow */
    if (f & 0x20) s |= 0x01;                                   /* inexact */
    return s;
}
static unsigned flags_from_status(unsigned s)                 /* _SW_ bits -> MXCSR / x87 flag bits */
{
    unsigned f = 0;
    if (s & 0x10) f |= 0x01;
    if (s & 0x80000) f |= 0x02;
    if (s & 0x08) f |= 0x04;
    if (s & 0x04) f |= 0x08;
    if (s & 0x02) f |= 0x10;
    if (s & 0x01) f |= 0x20;
    return f;
}

static unsigned control_common(unsigned newv, unsigned mask)
{
    const unsigned m = get_mxcsr();
    unsigned cw = cw_from_mxcsr(m);
    mask &= MCW_EM | MCW_RC | MCW_DN;                          /* precision / infinity control do not exist on x64 */
    if (mask) {
        cw = (cw & ~mask) | (newv & mask);
        set_mxcsr(mxcsr_from_cw(cw, m));
        set_x87cw(x87cw_from_cw(cw, get_x87cw()));
    }
    return cw;
}
DLLAPI unsigned CRTAPI _controlfp(unsigned newv, unsigned mask) { return control_common(newv, mask & ~EM_DENORMAL); }
DLLAPI unsigned CRTAPI _control87(unsigned newv, unsigned mask) { return control_common(newv, mask); }
DLLAPI void CRTAPI _set_controlfp(unsigned newv, unsigned mask) { control_common(newv, mask & ~EM_DENORMAL); }
DLLAPI crt_errno_t CRTAPI _controlfp_s(unsigned *cur, unsigned newv, unsigned mask)
{
    const unsigned valid = MCW_EM | MCW_RC | MCW_DN | MCW_PC | MCW_IC;
    unsigned r;
    if (mask & ~valid) {
        if (cur) *cur = control_common(0, 0);
        crt_set_errno(CRT_EINVAL);
        crt_invalid_parameter();
        return CRT_EINVAL;
    }
    r = control_common(newv, mask & ~EM_DENORMAL);
    if (cur) *cur = r;
    return 0;
}
DLLAPI unsigned CRTAPI _statusfp(void) { return status_from(get_mxcsr(), get_x87sw()); }
DLLAPI unsigned CRTAPI _clearfp(void)
{
    const unsigned s = _statusfp();
    set_mxcsr(get_mxcsr() & ~0x3fu);
    __asm__ volatile("fnclex");
    return s;
}
DLLAPI void CRTAPI _fpreset(void)
{
    set_mxcsr(0x1f80);
    __asm__ volatile("fninit");
    set_x87cw(0x027f);                                         /* the Windows x64 default: 53-bit precision, all masked */
}
DLLAPI int CRTAPI __fpe_flt_rounds(void)
{
    switch ((get_mxcsr() >> 13) & 3) {
    case 0: return 1;
    case 1: return 3;
    case 2: return 2;
    default: return 0;
    }
}
DLLAPI int CRTAPI _set_FMA3_enable(int flag) { (void)flag; return 0; }   /* no FMA3 code paths in this CRT */
DLLAPI int CRTAPI _get_FMA3_enable(void) { return 0; }

/* ---------------------------------------------------------------- <fenv.h> */
typedef struct { unsigned long ctl, stat; } crt_fenv;
DLLAPI int CRTAPI fegetround(void) { return (int)(cw_from_mxcsr(get_mxcsr()) & MCW_RC); }
DLLAPI int CRTAPI fesetround(int mode)
{
    if ((unsigned)mode & ~MCW_RC) return 1;
    control_common((unsigned)mode, MCW_RC);
    return 0;
}
DLLAPI int CRTAPI feclearexcept(int ex)
{
    const unsigned f = flags_from_status((unsigned)ex & 0x1f);
    if ((unsigned)ex & ~0x1fu) return 1;
    set_mxcsr(get_mxcsr() & ~f);
    if (f) {
        struct { unsigned short cw, r0, sw, r1, tw, r2; unsigned ip, cs, op, os; } env;
        __asm__ volatile("fnstenv %0" : "=m"(env));
        env.sw &= (unsigned short)~f;
        __asm__ volatile("fldenv %0" : : "m"(env));
    }
    return 0;
}
DLLAPI int CRTAPI fetestexcept(int ex) { return (int)(_statusfp() & (unsigned)ex & 0x1f); }
DLLAPI int CRTAPI fegetexceptflag(unsigned long *flag, int ex)
{
    if (!flag) return 1;
    *flag = _statusfp() & (unsigned)ex & 0x1f;
    return 0;
}
DLLAPI int CRTAPI fesetexceptflag(const unsigned long *flag, int ex)
{
    unsigned f;
    if (!flag) return 1;
    ex &= 0x1f;
    f = flags_from_status((unsigned)(*flag & (unsigned long)ex));
    set_mxcsr((get_mxcsr() & ~flags_from_status((unsigned)ex)) | f);
    return 0;
}
DLLAPI int CRTAPI fegetenv(crt_fenv *env)
{
    if (!env) return 1;
    env->ctl = cw_from_mxcsr(get_mxcsr());
    env->stat = _statusfp();
    return 0;
}
DLLAPI int CRTAPI fesetenv(const crt_fenv *env)
{
    unsigned m;
    if (!env) return 1;
    m = mxcsr_from_cw((unsigned)env->ctl, get_mxcsr());
    m = (m & ~0x3fu) | flags_from_status((unsigned)env->stat);
    set_mxcsr(m);
    set_x87cw(x87cw_from_cw((unsigned)env->ctl, get_x87cw()));
    return 0;
}
DLLAPI int CRTAPI feholdexcept(crt_fenv *env)
{
    if (fegetenv(env)) return 1;
    _clearfp();
    control_common(MCW_EM, MCW_EM);                            /* non-stop mode: every exception masked */
    return 0;
}
