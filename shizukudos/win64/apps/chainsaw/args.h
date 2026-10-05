/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_CHAINSAW_ARGS_H
#define SHZ_CHAINSAW_ARGS_H
#include <stdint.h>
#define CS_NAME_BYTES 32u
enum cs_action { CS_DETECT, CS_LIST, CS_SAW, CS_NUKE, CS_CHARBOMBA, CS_HELP };
typedef struct {
    enum cs_action action;
    unsigned verbose, numeric, acknowledged;
    uint32_t pid, ack_pid;
    uint64_t ack_generation;
    char name[CS_NAME_BYTES];
} cs_args;
/* No operation is performed by this parser. It rejects unknown/duplicate
 * options and requires a target-bound acknowledgement for CHARBOMBA. */
int cs_parse(int argc, char *const argv[], cs_args *out, const char **error);
int cs_name_equal(const char *a, const char *b);
int cs_ack_matches(const cs_args *a, uint32_t pid, uint64_t generation);
#endif
