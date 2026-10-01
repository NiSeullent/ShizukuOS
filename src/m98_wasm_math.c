/* SPDX-License-Identifier: GPL-2.0-only
 * Original IEEE binary rounding by integer bits; x87 square roots use explicit
 * PC24/PC53 and store their result before restoring the previous control word.
 * This alone is not proof of all floating point Wasm instructions. */
#include <stdint.h>
#include <string.h>
#include "m98_wasm_math.h"
static uint64_t bits(double x){uint64_t b;memcpy(&b,&x,8);return b;}
static double number(uint64_t b){double x;memcpy(&x,&b,8);return x;}
int m98_wasm_isnan(double x){return (bits(x)&UINT64_C(0x7fffffffffffffff))>UINT64_C(0x7ff0000000000000);}
int m98_wasm_signbit(double x){return (int)(bits(x)>>63);}
static double integral(double x,int mode){
 uint64_t b=bits(x),sign=b>>63,mag=b&UINT64_C(0x7fffffffffffffff),mask,rem,unit;int e=(int)(mag>>52)-1023;
 if(e>=52){if(e==1024&&mag>UINT64_C(0x7ff0000000000000))b|=UINT64_C(0x0008000000000000);return number(b);}
 if(e<0){
  if(!mag)return x;
  if(mode==1&&!sign)return 1.0;if(mode==2&&sign)return -1.0;
  if(mode==3&&mag>UINT64_C(0x3fe0000000000000))return sign?-1.0:1.0;
  return number(sign<<63);
 }
 unit=UINT64_C(1)<<(52-e);mask=unit-1;rem=mag&mask;
 if(!rem)return x;
 mag&=~mask;
 if((mode==1&&!sign)||(mode==2&&sign)||(mode==3&&(rem>unit/2||(rem==unit/2&&(mag&unit)))))mag+=unit;
 return number((sign<<63)|mag);
}
double m98_wasm_ceil(double x){return integral(x,1);}
double m98_wasm_floor(double x){return integral(x,2);}
double m98_wasm_trunc(double x){return integral(x,0);}
double m98_wasm_rint(double x){return integral(x,3);}
float m98_wasm_ceilf(float x){return (float)integral(x,1);}
float m98_wasm_floorf(float x){return (float)integral(x,2);}
float m98_wasm_truncf(float x){return (float)integral(x,0);}
float m98_wasm_rintf(float x){return (float)integral(x,3);}
double m98_wasm_sqrt(double x){unsigned short old,cw=0x027f;volatile double result;
 __asm__ volatile("fnstcw %0\n\tfldcw %1":"=m"(old):"m"(cw):"memory");
 __asm__ volatile("fldl %1\n\tfsqrt\n\tfstpl %0":"=m"(result):"m"(x):"memory");
 __asm__ volatile("fldcw %0"::"m"(old):"memory");return result;
}
float m98_wasm_sqrtf(float x){unsigned short old,cw=0x007f;volatile float result;
 __asm__ volatile("fnstcw %0\n\tfldcw %1":"=m"(old):"m"(cw):"memory");
 __asm__ volatile("flds %1\n\tfsqrt\n\tfstps %0":"=m"(result):"m"(x):"memory");
 __asm__ volatile("fldcw %0"::"m"(old):"memory");return result;
}

/* Original i486 helper prevents pulling a post-i486 prebuilt libgcc ctz. */
int __ctzdi2(uint64_t x){uint32_t word=(uint32_t)x;int n=0;
 if(!x)return 64;if(!word){word=(uint32_t)(x>>32);n=32;}
 while(!(word&1u)){word>>=1;n++;}return n;
}
