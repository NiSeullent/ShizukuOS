/* SPDX-License-Identifier: GPL-2.0-only
 * AMD64 port scopes actual x87 and MXCSR state. Full register clobbers prevent
 * compiler temporaries from being silently overwritten by FXRSTOR64.
 */
#ifndef NTG_FP64_H
#define NTG_FP64_H
typedef struct { unsigned char state[512] __attribute__((aligned(16))); } ntg_fp_scope;
#define NTG_FP_CLOBBERS "memory","st","st(1)","st(2)","st(3)","st(4)","st(5)","st(6)","st(7)","xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7","xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"
static void ntg_fp_enter(ntg_fp_scope *s){unsigned short cw=0x037f;unsigned mxcsr=0x1f80;
 __asm__ volatile("fxsave64 %0\n\tfninit\n\tfldcw %1\n\tldmxcsr %2":"=m"(s->state):"m"(cw),"m"(mxcsr):NTG_FP_CLOBBERS);
}
static void ntg_fp_leave(ntg_fp_scope *s){__asm__ volatile("fxrstor64 %0"::"m"(s->state):NTG_FP_CLOBBERS);}
#endif
