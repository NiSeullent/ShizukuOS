/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku vcruntime140 / vcruntime140_1: data layouts of the Microsoft x64 C++ exception ABI, the per-thread state both
 * DLLs share, and the catch records of the exception engine (ehengine.h).
 *
 * Layouts follow the documented x64 ABI as emitted by MSVC and by clang (-target x86_64-pc-windows-msvc): every pointer
 * inside the exception tables is a 32-bit offset from the image base of the module that owns the table (the throwing
 * module for ThrowInfo / CatchableType, the catching function's module for FuncInfo / HandlerType).
 */
#ifndef SHZ_VCRINT_H
#define SHZ_VCRINT_H

/* mingw-w64's headers declare these as dllimport CRT functions; this runtime defines them. */
#define __C_specific_handler vcr_hdr_C_specific_handler
#define _local_unwind vcr_hdr_local_unwind
#define longjmp vcr_hdr_longjmp
#define _setjmp vcr_hdr_setjmp
#define _set_purecall_handler vcr_hdr_set_purecall_handler
#define _get_purecall_handler vcr_hdr_get_purecall_handler
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#undef __C_specific_handler
#undef _local_unwind
#undef longjmp
#undef _setjmp
#undef _set_purecall_handler
#undef _get_purecall_handler

#define DLLAPI
#define VCR_NORETURN __attribute__((noreturn))

#define EH_EXCEPTION_CODE 0xE06D7363u               /* 'msc' | 0xE0000000 */
#define EH_MAGIC_1 0x19930520u                       /* FuncInfo / exception magic numbers */
#define EH_MAGIC_2 0x19930521u                       /* + pESTypeList */
#define EH_MAGIC_3 0x19930522u                       /* + EHFlags */
#define EH_PURE_MAGIC 0x01994000u                    /* /clr:pure throw */
#define STATUS_LONGJUMP_ 0x80000026u
#define STATUS_UNWIND_ 0xC0000027u

/* HandlerType.adjectives */
#define HT_CONST 0x01u
#define HT_VOLATILE 0x02u
#define HT_UNALIGNED 0x04u
#define HT_REFERENCE 0x08u
#define HT_RESUMABLE 0x10u
#define HT_STDDOTDOT 0x40u                          /* catch(...) that must not catch SEH exceptions under /EHa */
/* CatchableType.properties */
#define CT_SIMPLE 0x01u
#define CT_BYREF_ONLY 0x02u
#define CT_VIRTUAL_BASE 0x04u
/* ThrowInfo.attributes */
#define TI_CONST 0x01u
#define TI_VOLATILE 0x02u
#define TI_UNALIGNED 0x04u
#define TI_PURE 0x08u
/* FuncInfo.EHFlags (magic >= 0x19930522) */
#define FI_EHS 0x01u                                 /* /EHs: synchronous, catch(...) ignores SEH exceptions */
#define FI_DYNSTKALIGN 0x02u
#define FI_NOEXCEPT 0x04u

typedef struct { int32_t mdisp, pdisp, vdisp; } eh_pmd;
typedef struct { uint32_t properties; int32_t type; eh_pmd this_disp; int32_t size; int32_t copy_ctor; } eh_catchable;
typedef struct { int32_t count; int32_t types[1]; } eh_catchable_array;
typedef struct { uint32_t attributes; int32_t destructor; int32_t forward_compat; int32_t catchables; } eh_throwinfo;
typedef struct { const void *vftable; void *spare; char name[1]; } eh_typedesc;

/* FH3 (__CxxFrameHandler3) FuncInfo and its tables */
typedef struct {
    uint32_t magic;                                  /* magic in bits 0..28, BBT flags in 29..31 */
    int32_t max_state;
    int32_t unwind_map;                              /* -> { int32 to_state; int32 action; }[max_state] */
    uint32_t ntry;
    int32_t try_map;                                 /* -> fh3_try[ntry], innermost first */
    uint32_t nip;
    int32_t ip_map;                                  /* -> { int32 ip; int32 state; }[nip], sorted by ip */
    int32_t unwind_help;
    int32_t es_types;
    int32_t flags;
} fh3_funcinfo;
typedef struct { int32_t low, high, catch_high; int32_t ncatch; int32_t handlers; } fh3_try;
typedef struct { uint32_t adjectives; int32_t type; int32_t catch_obj; int32_t handler; int32_t frame; } fh3_handler;

/* Decoded forms both frame handlers present to the engine. */
typedef struct { int32_t low, high, catch_high; uint32_t ncatch; const uint8_t *catches; } eh_try;
typedef struct {
    uint32_t adjectives;
    int32_t type;                                    /* RVA of the TypeDescriptor, 0 for catch(...) */
    int32_t catch_obj;                               /* offset of the catch object in the function frame, 0: none */
    int32_t handler;                                 /* RVA of the catch funclet */
    int32_t frame;                                   /* FH3: offset of the parent-frame slot in the funclet frame */
    uint32_t ncont;                                  /* FH4: continuation addresses the funclet may return by index */
    uint64_t cont[2];
} eh_catch;

typedef struct eh_func eh_func;
typedef struct {
    int (*state)(const eh_func *f, uint64_t pc);
    int (*to_state)(const eh_func *f, int state);
    void (*unwind)(const eh_func *f, uint64_t frame, int from, int to);
    unsigned (*ntry)(const eh_func *f);
    void (*get_try)(const eh_func *f, unsigned i, eh_try *t);
    void (*get_catch)(const eh_func *f, const eh_try *t, unsigned j, eh_catch *c);
    int (*is_cleanup)(const eh_func *f, uint32_t rva);       /* rva starts an unwind (destructor) funclet */
} eh_ops;

struct eh_func {
    const eh_ops *ops;
    const void *info;                                /* FuncInfo (FH3) or the FuncInfo4 bytes (FH4) */
    uint64_t base;                                   /* image base of the function */
    uint64_t func_start;                             /* start of the function (or funclet) being examined */
    uint32_t flags;                                  /* FI_* */
    /* FH4 decoded header */
    int fh4;
    int is_catch;
    uint32_t frame_disp;
    const uint8_t *unwind_map, *try_map, *ip_map;
};

/* One executing catch handler. Records live on the heap (a thread may abandon a catch through an unwinder that does not
 * know them; the stale record is then pruned by address, which must stay readable). */
typedef struct vcr_catchrec vcr_catchrec;
struct vcr_catchrec {
    vcr_catchrec *next;                              /* enclosing (older) catch */
    uint64_t invoker_est;                            /* offset 8: written by vcr_call_catch (establisher of its frame) */
    uint64_t target_est;                             /* establisher frame of the frame that resumes after the catch */
    uint64_t target_rsp;                             /* its stack pointer: (invoker_est, target_rsp) is the dead zone */
    const void *info;                                /* function tables the try belongs to */
    uint64_t base;
    int32_t handler_rva;
    int try_index;
    int base_state;                                  /* state below the try: where the resume frame unwinds from */
    int done;                                        /* catch left by an unwind: object already released */
    int is_cxx;
    void *prev_exception, *prev_context;
    EXCEPTION_RECORD rec;                            /* the exception being handled (std::current_exception) */
    CONTEXT ctx;                                     /* context of the resume frame, Rip at its call site */
};

/* Per-thread state. __current_exception() returns its address (field 0), which is how vcruntime140_1 reaches it. */
#define VCR_SEEN 16
typedef struct {
    void *cur_exception;                             /* EXCEPTION_RECORD * of the exception being handled */
    void *cur_context;                               /* its CONTEXT * */
    int processing_throw;                            /* exceptions thrown and not yet caught (std::uncaught_exceptions) */
    int pad0;
    vcr_catchrec *catches;                           /* executing catch handlers, innermost first */
    void *se_translator;
    void *unexpected;
    struct { const EXCEPTION_RECORD *rec; CONTEXT *ctx; } seen[VCR_SEEN];   /* origin contexts, via the vectored handler */
    unsigned seen_next;
    uint32_t magic;
} vcr_ptd;
#define VCR_PTD_MAGIC 0x56435254u                    /* 'VCRT' */

/* setjmp / longjmp buffer (Microsoft x64 _JUMP_BUFFER) */
typedef struct {
    uint64_t Frame, Rbx, Rsp, Rbp, Rsi, Rdi, R12, R13, R14, R15, Rip;
    uint32_t MxCsr;
    uint16_t FpCsr, Spare;
    uint64_t Xmm[20];                                /* Xmm6..Xmm15, 16 bytes each */
} vcr_jmpbuf;

/* ucrtbase imports */
__declspec(dllimport) void *malloc(size_t n);
__declspec(dllimport) void free(void *p);
__declspec(dllimport) VCR_NORETURN void terminate(void);
__declspec(dllimport) VCR_NORETURN void abort(void);

#endif
