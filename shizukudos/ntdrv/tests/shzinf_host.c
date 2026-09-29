/* SPDX-License-Identifier: GPL-2.0-only
 * Host harness for shizukudos/win64/apps/shzpnp/shzinf.c: prints the canonical dump that test_shzpnp.py also produces
 * from shizukudos/ntdrv/inf.py, so both implementations can be compared line by line.
 *   shzinf_host dump <inf> <legacy 0|1> <build>
 *   shzinf_host match <legacy 0|1> <build> <device-spec> <inf> [<inf> ...]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shzinf.h"

static unsigned char *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long n;
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    b = malloc((size_t)n + 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(b); return 0; }
    fclose(f);
    *len = (size_t)n;
    return b;
}

static void esc(const char *s)
{
    for (; s && *s; ++s) {
        if (*s == '\n') fputs("\\n", stdout);
        else if (*s == '\t') fputs("\\t", stdout);
        else if (*s == '|') fputs("\\|", stdout);
        else if (*s == '\\') fputs("\\\\", stdout);
        else putchar(*s);
    }
}

static void reg(const char *tag, const shzinf_reg_t *r)
{
    int i;
    printf("%s ", tag);
    esc(r->root); putchar('|'); esc(r->subkey); putchar('|'); esc(r->name);
    printf("|%u|%u|", r->flags, r->type);
    if (!r->has_data) fputs("-", stdout);
    else if (r->type == SHZ_REG_DWORD || r->type == SHZ_REG_QWORD) printf("n:%llu", (unsigned long long)r->num);
    else if (r->type == SHZ_REG_BINARY || r->type == SHZ_REG_NONE || (r->flags & SHZ_FLG_BINVALUETYPE)) {
        fputs("b:", stdout);
        for (i = 0; i < r->binlen; ++i) printf("%02x", r->bin[i]);
    } else if (r->type == SHZ_REG_MULTI_SZ) { printf("m%d:", r->nmulti); esc(r->str); }
    else { fputs("s:", stdout); esc(r->str); }
    putchar('\n');
}

static void num(int v) { if (v < 0) fputs("-", stdout); else printf("%d", v); }

int main(int argc, char **argv)
{
    static shzinf_model_t models[4096];
    shzinf_target_t t = { "amd64", 10, 0, 22631, 1, 0, 0 };
    if (argc >= 5 && !strcmp(argv[1], "dump")) {
        size_t len;
        unsigned char *d = slurp(argv[2], &len);
        shzinf_t *inf;
        int n, i, j, k;
        if (!d) return 2;
        t.legacy = atoi(argv[3]);
        t.build = atoi(argv[4]);
        inf = shzinf_parse(d, len, "0409");
        printf("VERSION class=");
        esc(shzinf_version(inf, "Class", &t)); printf(" provider="); esc(shzinf_version(inf, "Provider", &t));
        printf(" driverver="); esc(shzinf_version(inf, "DriverVer", &t)); printf(" catalog="); esc(shzinf_version(inf, "CatalogFile", &t));
        putchar('\n');
        n = shzinf_models(inf, &t, models, 4096);
        if (n > 4096) n = 4096;
        for (i = 0; i < n; ++i) {
            const shzinf_model_t *m = &models[i];
            shzinf_install_t *r = shzinf_install(inf, m->install, &t);
            printf("MODEL %d ", m->lineno); esc(m->section); putchar('|'); esc(m->install); putchar('|'); esc(m->hwid); putchar('|');
            for (j = 0; j < m->ncompat; ++j) { if (j) putchar(';'); esc(m->compat[j]); }
            putchar('|'); esc(m->description); putchar('\n');
            printf("INSTALL "); esc(r->section ? r->section : "-"); printf(" feature="); num(r->feature_score);
            printf(" driverver="); esc(r->driverver ? r->driverver : "-"); printf(" kmdf="); esc(r->kmdf ? r->kmdf : "-");
            printf(" rank=%08x\n", shzinf_rank(r, 0));
            for (j = 0; j < r->ncopy; ++j) {
                const shzinf_copy_t *c = &r->copy[j];
                printf("COPY "); esc(c->dest); putchar('|'); esc(c->source); printf("|%d|", c->dirid); esc(c->subdir);
                printf("|%u|", c->flags); esc(c->section ? c->section : "-"); putchar('\n');
            }
            for (j = 0; j < r->nreg; ++j) reg("REG", &r->reg[j]);
            for (j = 0; j < r->nhwreg; ++j) reg("HWREG", &r->hwreg[j]);
            for (j = 0; j < r->nsvc; ++j) {
                const shzinf_service_t *s = &r->svc[j];
                printf("SVC "); esc(s->name);
                if (s->is_delete) { printf("|delete\n"); continue; }
                printf("|%u|", s->flags); esc(s->section); putchar('|'); num(s->service_type); putchar('|'); num(s->start_type);
                putchar('|'); num(s->error_control); putchar('|'); esc(s->binary ? s->binary : "-"); putchar('|');
                esc(s->group ? s->group : "-"); putchar('|'); esc(s->display ? s->display : "-"); putchar('|');
                for (k = 0; k < s->ndeps; ++k) { if (k) putchar(';'); esc(s->deps[k]); }
                putchar('\n');
                for (k = 0; k < s->nreg; ++k) reg("SVCREG", &s->reg[k]);
            }
            shzinf_install_free(r);
        }
        shzinf_free(inf);
        free(d);
        return 0;
    }
    if (argc >= 6 && !strcmp(argv[1], "match")) {
        shzinf_device_t dev;
        int a, i;
        t.legacy = atoi(argv[2]);
        t.build = atoi(argv[3]);
        if (!shzinf_parse_device(&dev, argv[4])) { printf("BADDEVICE\n"); return 0; }
        for (i = 0; i < dev.nhw; ++i) printf("HW %s\n", dev.hw[i]);
        for (i = 0; i < dev.ncp; ++i) printf("CP %s\n", dev.cp[i]);
        for (a = 5; a < argc; ++a) {
            size_t len;
            unsigned char *d = slurp(argv[a], &len);
            shzinf_t *inf;
            int n;
            if (!d) continue;
            inf = shzinf_parse(d, len, "0409");
            n = shzinf_models(inf, &t, models, 4096);
            if (n > 4096) n = 4096;
            for (i = 0; i < n; ++i) {
                shzinf_score_t sc;
                if (shzinf_score(&dev, &models[i], &sc)) {
                    shzinf_install_t *r = shzinf_install(inf, models[i].install, &t);
                    printf("HIT %d %d ", a - 5, models[i].lineno); esc(models[i].install);
                    printf(" %08x %04x %04x ", shzinf_rank(r, (int)sc.identifier), sc.identifier, sc.kind); esc(sc.inf_id);
                    putchar('\n');
                    shzinf_install_free(r);
                }
            }
            shzinf_free(inf);
            free(d);
        }
        return 0;
    }
    fprintf(stderr, "usage: shzinf_host dump <inf> <legacy> <build> | match <legacy> <build> <device> <inf>...\n");
    return 2;
}
