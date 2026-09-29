/* SPDX-License-Identifier: GPL-2.0-only
 * Software RaiseException dispatcher. Vectored handlers run before the SEH
 * chain. Compared with ReactOS RtlDispatchException ordering at
 * cae3ca87209fd8ebabd96c8ea95d439c13e7fdf8 (sdk/lib/rtl/i386/except.c).
 * No function body from that tree is copied.
 */
#ifndef NTW_RAISE_H
#define NTW_RAISE_H
#include <stdint.h>
#define NTW_EX_CONTINUE_SEARCH 0
#define NTW_EX_CONTINUE_EXECUTION (-1)
#define NTW_EX_EXECUTE_HANDLER 1
#define NTW_DISP_CONTINUE 0
#define NTW_DISP_SEARCH 1
#define NTW_DISP_NESTED 2
#define NTW_DISP_COLLIDED 3
#define NTW_EX_NONCONTINUABLE 0x1u
#define NTW_EX_UNWINDING 0x2u
#define NTW_EX_EXIT_UNWIND 0x4u
#define NTW_EX_STACK_INVALID 0x8u
#define NTW_EX_MAXIMUM_PARAMETERS 15u
#define NTW_EX_CHAIN_END 0xffffffffu
#define NTW_STATUS_NONCONTINUABLE 0xC0000025u
#define NTW_RAISE_RESUME 0
#define NTW_RAISE_TERMINATE 1
#define NTW_VEH_LIMIT 32u
typedef struct ntw_ex_record {
    uint32_t code, flags, next, address, count;
    uint32_t info[NTW_EX_MAXIMUM_PARAMETERS];
} ntw_ex_record;
typedef struct ntw_context {
    uint32_t ContextFlags;
    uint32_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    uint8_t FloatSave[112];
    uint32_t SegGs, SegFs, SegEs, SegDs;
    uint32_t Edi, Esi, Ebx, Edx, Ecx, Eax;
    uint32_t Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    uint8_t ExtendedRegisters[512];
} ntw_context;
typedef struct ntw_ex_pointers { ntw_ex_record *record; ntw_context *context; } ntw_ex_pointers;
#if defined(__i386__)
#define NTW_VEH_CALL __attribute__((stdcall))
#else
#define NTW_VEH_CALL
#endif
typedef int32_t (NTW_VEH_CALL *ntw_veh_routine)(ntw_ex_pointers *pointers);
typedef int32_t (*ntw_seh_routine)(ntw_ex_record *record, void *frame, ntw_context *context, void *dispatch);
typedef int (*ntw_frame_ok)(uint32_t frame, void *user);
typedef int32_t (*ntw_unhandled_routine)(ntw_ex_pointers *pointers, void *user);
int ntw_veh_add(uint32_t first, ntw_veh_routine routine, uint32_t *handle, uint32_t *error);
int ntw_veh_remove(uint32_t handle, uint32_t *error);
void ntw_veh_reset(void);
int ntw_raise_software(ntw_ex_record *record, ntw_context *context, uint32_t seh_head,
                       ntw_frame_ok frame_ok, void *frame_user, ntw_unhandled_routine unhandled,
                       void *unhandled_user, uint32_t *final_code);
int ntw_unwind_chain(uint32_t *seh_head, uint32_t target_frame, ntw_ex_record *record,
                     ntw_context *context, ntw_frame_ok frame_ok, void *frame_user, uint32_t *error);
#endif
