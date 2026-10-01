/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_SOFTPIPE_SHADER_H
#define M98_SOFTPIPE_SHADER_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Private typed IR -> genuine Mesa26.2.3 TGSI fragment interpreter.
 * No GLSL/GLES/WebGL/rasterization/texture/loop/compute/browser API is claimed.
 * Instructions are copied at open. IO/results are borrowed only during run.
 * Every operation is serialized; callback reentry/concurrent calls return BUSY.
 * Alloc/free/math callbacks and user storage must remain live through close.
 * Allocations are real, bounded to4MiB/context, aligned internally, never shared.
 * Source/result pointers are unchanged on failure. Cookies cannot be reused;
 * close clears the caller cookie, NULL-cookie close is idempotent.
 */
enum { M98_SP_OK=0,M98_SP_INVALID=1,M98_SP_LIMIT=2,M98_SP_NOMEM=3,
 M98_SP_UNSUPPORTED=4,M98_SP_STALE=5,M98_SP_BUSY=6,M98_SP_BACKEND=7 };
enum { M98_SP_INPUT=1,M98_SP_CONSTANT=2,M98_SP_TEMP=3,M98_SP_OUTPUT=4 };
enum { M98_SP_MOV=1,M98_SP_ADD,M98_SP_MUL,M98_SP_MAD,M98_SP_MIN,M98_SP_MAX,
 M98_SP_DP3,M98_SP_DP4,M98_SP_DDX,M98_SP_DDY,M98_SP_SLT,M98_SP_IF,
 M98_SP_ELSE,M98_SP_ENDIF,M98_SP_KILL_IF,M98_SP_END,M98_SP_SIN,M98_SP_COS,
 M98_SP_SQRT,M98_SP_FLOOR,M98_SP_CEIL,M98_SP_TRUNC,M98_SP_ROUND_EVEN,
 M98_SP_POW,M98_SP_LOOP=100,M98_SP_TEXTURE,M98_SP_COMPUTE,M98_SP_FMA };
enum { M98_SP_MATH_COS=1,M98_SP_MATH_SIN,M98_SP_MATH_LOG,M98_SP_MATH_POW,
 M98_SP_MATH_SQRT,M98_SP_MATH_FLOOR,M98_SP_MATH_CEIL,M98_SP_MATH_LDEXP };
enum { M98_SP_MAX_INPUTS=4,M98_SP_MAX_CONSTANTS=8,M98_SP_MAX_TEMPS=16,
 M98_SP_MAX_OUTPUTS=2,M98_SP_MAX_INSTRUCTIONS=128,M98_SP_MAX_DEPTH=16,
 M98_SP_MAX_CONTEXTS=16,M98_SP_MEMORY_LIMIT=4194304 };
typedef struct { uint32_t file,index,swizzle[4],negate,absolute; } m98_sp_source;
typedef struct {
 uint32_t opcode,dst_file,dst_index,source_count,saturate,reserved;
 m98_sp_source source[3];
} m98_sp_instruction;
typedef struct {
 uint32_t abi,instruction_count,input_count,constant_count,temp_count,output_count;
 uint32_t reserved[2]; const m98_sp_instruction *instructions;
} m98_sp_program;
typedef struct {
 uint32_t abi,reserved; void *user;
 void *(*allocate)(void *,size_t); void (*deallocate)(void *,void *);
 /* Actual provider returns0 and a computed double, including IEEE NaN/Inf.
  * Nonzero fails the complete run. Only listed operations may be requested.
  * Callback double->float conversion is a bounded profile, not correctly
  * rounded GLSL ES/libm conformance. MAD is ordinary multiply-add, not FMA. */
 int (*math)(void *,uint32_t,double,double,double *);
} m98_sp_callbacks;
typedef struct { float a0[4],dx[4],dy[4]; } m98_sp_plane;
typedef struct {
 uint32_t abi,live_mask,reserved[2]; float quad_x,quad_y;
 m98_sp_plane input[M98_SP_MAX_INPUTS];
 float constant[M98_SP_MAX_CONSTANTS][4];
} m98_sp_io;
typedef struct {
 uint32_t live_mask,output_count; float output[M98_SP_MAX_OUTPUTS][4][4];
} m98_sp_result;
int m98_sp_open(const m98_sp_program *,const m98_sp_callbacks *,uint32_t *cookie);
int m98_sp_run(uint32_t cookie,const m98_sp_io *,m98_sp_result *);
int m98_sp_close(uint32_t *cookie);
uint32_t m98_sp_abi(void);
#ifdef __cplusplus
}
#endif
#endif
