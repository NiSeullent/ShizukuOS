/* SPDX-License-Identifier: GPL-2.0-only */
#include "../args.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static cs_args parse(int valid, int argc, char **argv)
{
    cs_args a; const char *error;
    int ok = cs_parse(argc, argv, &a, &error);
    assert(ok == valid); assert(ok ? error == 0 : error != 0); return a;
}
#define CASE(valid, ...) do { char *v[] = { "CHAINSAW.exe", __VA_ARGS__ }; parse(valid, (int)(sizeof v / sizeof v[0]), v); } while (0)
int main(void)
{
    cs_args a; char *noargs[] = { "CHAINSAW.exe" };
    a = parse(1, 1, noargs); assert(a.action == CS_DETECT);
    CASE(1, "/list", "/verbose"); CASE(1, "SAW", "1842");
    CASE(1, "muzik.exe", "/nuke"); CASE(1, "/NUKE", "1842", "/debug");
    CASE(0, "SAW"); CASE(0, "0"); CASE(0, "-1"); CASE(0, "2147483648");
    CASE(0, "1842x"); CASE(0, "1842", "1843"); CASE(0, "/list", "1842");
    CASE(0, "1842", "/nuke", "/charbomba"); CASE(0, "1842", "/unknown");
    CASE(0, "1842", "/charbomba"); CASE(0, "1842", "/charbomba", "/force");
    CASE(0, "1842", "--ack-destructive=1842:42");
    CASE(0, "1842", "/charbomba", "--ack-destructive=1842:0");
    CASE(0, "1842", "/charbomba", "--ack-destructive=1842:18446744073709551616");
    CASE(0, "1842", "/charbomba", "--ack-destructive=1842:42garbage");
    CASE(0, "1842", "/charbomba", "--ack-destructive=1842:42", "--ack-destructive=1842:42");
    CASE(0, "C:\\HAL.exe"); CASE(0, "this_process_name_is_far_too_long.exe");
    { char *v[] = { "CHAINSAW.exe", "1842", "/CHARBOMBA", "--ack-destructive=1842:18446744073709551615" };
      a = parse(1, 4, v); assert(cs_ack_matches(&a, 1842, UINT64_MAX));
      assert(!cs_ack_matches(&a, 1843, UINT64_MAX)); assert(!cs_ack_matches(&a, 1842, 42)); }
    assert(cs_name_equal("MUZIK.EXE", "muzik.exe")); assert(!cs_name_equal("muzik", "muzik.exe"));
    puts("CHAINSAW parser: target, mutually exclusive modes, acknowledgement overflow/binding, names PASS");
    return 0;
}
