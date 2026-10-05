/* SPDX-License-Identifier: GPL-2.0-only */
#include "args.h"
#include <stddef.h>
#include <string.h>

static unsigned fold(unsigned c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; }
int cs_name_equal(const char *a, const char *b)
{
    unsigned n;
    for (n = 0; n < CS_NAME_BYTES; ++n) {
        unsigned x = (unsigned char)a[n], y = (unsigned char)b[n];
        if (fold(x) != fold(y)) return 0;
        if (!x) return 1;
    }
    return 0; /* unterminated name is never a valid match */
}
static int word(const char *a, const char *b) { return cs_name_equal(a, b); }
static int prefix(const char *s, const char *p)
{
    while (*p) if (*s++ != *p++) return 0;
    return 1;
}
static int decimal(const char **p, uint64_t max, uint64_t *out)
{
    const char *s = *p;
    uint64_t n = 0;
    if (*s < '0' || *s > '9') return 0;
    do {
        unsigned d = (unsigned)(*s++ - '0');
        if (n > (max - d) / 10u) return 0;
        n = n * 10u + d;
    } while (*s >= '0' && *s <= '9');
    if (!n) return 0;
    *p = s; *out = n;
    return 1;
}
static int target(const char *s, cs_args *a)
{
    size_t n;
    if (*s >= '0' && *s <= '9') {
        const char *end = s; uint64_t pid;
        if (!decimal(&end, 2147483647u, &pid) || *end) return 0;
        a->numeric = 1; a->pid = (uint32_t)pid; return 1;
    }
    for (n = 0; s[n]; ++n) {
        unsigned c = (unsigned char)s[n];
        if (n + 1 >= sizeof a->name ||
            !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return 0;
        a->name[n] = (char)c;
    }
    return n != 0;
}
int cs_ack_matches(const cs_args *a, uint32_t pid, uint64_t generation)
{
    return a->action == CS_CHARBOMBA && a->acknowledged && pid && generation &&
           a->ack_pid == pid && a->ack_generation == generation;
}
int cs_parse(int argc, char *const argv[], cs_args *a, const char **error)
{
    int i = 1, have_target = 0, special = 0, listing = 0;
    memset(a, 0, sizeof *a); a->action = CS_DETECT;
    *error = "invalid command";
    if (argc < 1 || argc > 10) { *error = "too many arguments"; return 0; }
    if (argc == 2 && (word(argv[1], "/help") || word(argv[1], "--help") || word(argv[1], "/?"))) {
        a->action = CS_HELP; return 1;
    }
    if (i < argc && word(argv[i], "SAW")) { a->action = CS_SAW; ++i; }
    for (; i < argc; ++i) {
        const char *s = argv[i];
        if (word(s, "/verbose") || word(s, "/debug") || word(s, "--verbose")) {
            if (a->verbose) { *error = "duplicate verbose option"; return 0; }
            a->verbose = 1;
        } else if (word(s, "/list") || word(s, "/zombies") || word(s, "/detect")) {
            if (listing || have_target || a->action == CS_SAW) { *error = "detector mode cannot target a process"; return 0; }
            listing = 1; a->action = word(s, "/list") ? CS_LIST : CS_DETECT;
        } else if (word(s, "/nuke") || word(s, "/charbomba")) {
            if (special || listing) { *error = "choose only one teardown mode"; return 0; }
            special = 1; a->action = word(s, "/nuke") ? CS_NUKE : CS_CHARBOMBA;
        } else if (prefix(s, "--ack-destructive=")) {
            const char *p = s + 18; uint64_t pid, gen;
            if (a->acknowledged || !decimal(&p, 2147483647u, &pid) || *p++ != ':' ||
                !decimal(&p, UINT64_MAX, &gen) || *p) { *error = "acknowledgement must be PID:GENERATION"; return 0; }
            a->acknowledged = 1; a->ack_pid = (uint32_t)pid; a->ack_generation = gen;
        } else {
            if (*s == '/' || *s == '-') { *error = "unknown option"; return 0; }
            if (listing || have_target || !target(s, a)) { *error = "one valid PID or exact process name is required"; return 0; }
            have_target = 1; if (!special) a->action = CS_SAW;
        }
    }
    if ((a->action == CS_SAW || a->action == CS_NUKE || a->action == CS_CHARBOMBA) && !have_target) {
        *error = "teardown requires a target"; return 0;
    }
    if (a->acknowledged && a->action != CS_CHARBOMBA) { *error = "destructive acknowledgement is only for /charbomba"; return 0; }
    if (a->action == CS_CHARBOMBA && !a->acknowledged) {
        *error = "CHARBOMBA requires explicit --ack-destructive=PID:GENERATION"; return 0;
    }
    *error = 0; return 1;
}
