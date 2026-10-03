/* SPDX-License-Identifier: GPL-2.0-only -- actual mapped PE32 clock calls.
 * Every callback return/protection below is a model, never native evidence. */
static uint64_t clock_load(const unsigned char *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8u);
    return value;
}
static void clock_reset(void)
{
    CHECK(!clock_owned);
    clock_testing = 1;
    clock_open_calls = clock_io_calls = clock_close_calls = clock_vq_calls = 0;
    clock_open_error = clock_io_error = clock_close_error = clock_reply_mode = clock_mbi_mode = 0;
    clock_post_protect = 0;
    clock_handle = 0;
    for (unsigned i = 0; i < 3; ++i) clock_protect[i] = 4;
    for (unsigned i = 0; i < sizeof clock_storage; ++i) clock_storage[i] = 0xab;
}
static uint32_t clock_call(uint32_t rva, const void *counter, const void *frequency)
{
    return call2(rva, (uintptr_t)counter, (uintptr_t)frequency).low;
}
static void clock_unchanged(const unsigned char *counter, const unsigned char *frequency)
{
    CHECK(clock_load(counter) == UINT64_C(0xabababababababab));
    if (frequency) CHECK(clock_load(frequency) == UINT64_C(0xabababababababab));
}
static void core_clock_contracts(void)
{
    unsigned char *counter = clock_storage + 64, *frequency = clock_storage + 128;
    static const uint32_t allowed[] = {4, 8, 0x40, 0x80, 0x204};
    static const uint32_t refused[] = {1, 2, 0x10, 0x20, 0x104, 0x180};
    uint32_t opens, closes, vq;
    clock_reset();
    last_error = 0x4242;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 1 && last_error == 0x4242);
    CHECK(clock_load(counter) == clock_sample && clock_load(frequency) == SHZ_CLOCK_FREQUENCY);
    CHECK(clock_sample > UINT32_MAX && clock_open_calls == 1 && clock_io_calls == 1 && clock_close_calls == 1);
    CHECK(clock_vq_calls == 4 && !clock_owned);
    for (unsigned i = 0; i < sizeof allowed / sizeof allowed[0]; ++i) {
        clock_reset(); clock_protect[0] = allowed[i];
        last_error = 0x4646;
        CHECK(clock_call(RVA_NtwQueryCoreClock, counter + 4, NULL) == 1 && last_error == 0x4646);
        CHECK(clock_load(counter + 4) == clock_sample && clock_vq_calls == 2 && !clock_owned);
    }
    for (unsigned i = 0; i < sizeof refused / sizeof refused[0]; ++i) {
        clock_reset(); clock_protect[0] = refused[i];
        CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == NTWV_ERROR_NOACCESS);
        CHECK(!clock_open_calls && !clock_io_calls && !clock_close_calls);
        clock_unchanged(counter, frequency);
    }
    for (clock_mbi_mode = 1; clock_mbi_mode <= 7; ) {
        const uint32_t mode = clock_mbi_mode;
        clock_reset(); clock_mbi_mode = mode;
        CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == NTWV_ERROR_NOACCESS);
        CHECK(!clock_open_calls && !clock_io_calls && !clock_close_calls);
        clock_unchanged(counter, frequency);
        clock_mbi_mode = mode + 1;
    }
    clock_reset();
    CHECK(clock_call(RVA_NtwQueryCoreClock, NULL, frequency) == 0 && last_error == NTWV_ERROR_INVALID_PARAMETER);
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter + 1, frequency) == 0 && last_error == NTWV_ERROR_INVALID_PARAMETER);
    CHECK(clock_call(RVA_NtwQueryCoreClock, (void *)(uintptr_t)UINT32_C(0xfffffffc), NULL) == 0 && last_error == NTWV_ERROR_INVALID_PARAMETER);
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, counter + 4) == 0 && last_error == NTWV_ERROR_INVALID_PARAMETER);
    CHECK(!clock_vq_calls && !clock_open_calls);
    CHECK(clock_call(RVA_NtwQueryCoreClock, (void *)(uintptr_t)0x1000, NULL) == 0 && last_error == NTWV_ERROR_NOACCESS);
    CHECK(!clock_open_calls);
    clock_unchanged(counter, frequency);

    clock_reset(); counter = clock_storage + 4092;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, NULL) == 1);
    CHECK(clock_load(counter) == clock_sample && clock_vq_calls == 4);
    clock_reset(); clock_protect[1] = 2;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, NULL) == 0 && last_error == NTWV_ERROR_NOACCESS);
    CHECK(clock_vq_calls == 2 && !clock_open_calls); clock_unchanged(counter, NULL);
    counter = clock_storage + 64;
    clock_reset(); clock_post_protect = 2;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == NTWV_ERROR_NOACCESS);
    CHECK(clock_open_calls == 1 && clock_io_calls == 1 && clock_close_calls == 1 && clock_vq_calls == 3);
    clock_unchanged(counter, frequency);

    for (uint32_t mode = 1; mode <= 7; ++mode) {
        clock_reset(); clock_reply_mode = mode;
        CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == NTWV_ERROR_REVISION_MISMATCH);
        CHECK(clock_open_calls == 1 && clock_io_calls == 1 && clock_close_calls == 1 && !clock_owned);
        clock_unchanged(counter, frequency);
    }
    clock_reset(); clock_open_error = NTWV_ERROR_NOT_SUPPORTED;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == NTWV_ERROR_NOT_SUPPORTED);
    CHECK(clock_open_calls == 1 && !clock_io_calls && !clock_close_calls);
    clock_unchanged(counter, frequency);
    clock_reset(); clock_io_error = NTWV_ERROR_DEV_NOT_EXIST;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == NTWV_ERROR_DEV_NOT_EXIST);
    CHECK(clock_open_calls == 1 && clock_io_calls == 1 && clock_close_calls == 1 && !clock_owned);
    clock_unchanged(counter, frequency);

    /* Failed cleanup stays owned. A subsequent query must drain that exact
     * zero handle before opening another device; transport's first error wins. */
    clock_reset(); clock_io_error = NTWV_ERROR_NOT_SUPPORTED; clock_close_error = 5;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == NTWV_ERROR_NOT_SUPPORTED);
    CHECK(clock_owned && clock_open_calls == 1 && clock_io_calls == 1 && clock_close_calls == 1);
    clock_unchanged(counter, frequency);
    clock_io_error = 0;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == 5);
    CHECK(clock_owned && clock_open_calls == 1 && clock_io_calls == 1 && clock_close_calls == 2);
    clock_close_error = 0; last_error = 0x4848;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 1 && last_error == 0x4848);
    CHECK(!clock_owned && clock_open_calls == 2 && clock_io_calls == 2 && clock_close_calls == 4);
    CHECK(clock_load(counter) == clock_sample && clock_load(frequency) == SHZ_CLOCK_FREQUENCY);

    clock_reset(); last_error = 0x7878;
    CHECK(clock_call(RVA_NtQueryPerformanceCounter, counter, counter) == 0 && last_error == 0x7878);
    CHECK(clock_load(counter) == SHZ_CLOCK_FREQUENCY);
    clock_reset(); last_error = 0x7979;
    CHECK(clock_call(RVA_NtQueryPerformanceCounter, counter, counter + 4) == 0 && last_error == 0x7979);
    CHECK(clock_load(counter + 4) == SHZ_CLOCK_FREQUENCY);
    CHECK(counter[0] == 0x40 && counter[1] == 0 && counter[2] == 0 && counter[3] == 0);
    clock_reset(); clock_protect[0] = 2; last_error = 0x7a7a;
    CHECK(clock_call(RVA_NtQueryPerformanceCounter, counter, frequency) == UINT32_C(0xc0000005) && last_error == 0x7a7a);
    clock_unchanged(counter, frequency);
    last_error = 0x7b7b;
    CHECK(clock_call(RVA_NtQueryPerformanceCounter, NULL, frequency) == UINT32_C(0xc000000d) && last_error == 0x7b7b);

    /* Detach stops admission without closing under the loader lock. Explicit
     * shutdown outside DllMain retains/retries an actual failed close. */
    clock_reset(); clock_close_error = 5;
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == 5 && clock_owned);
    opens = clock_open_calls; closes = clock_close_calls; vq = clock_vq_calls;
    CHECK(call3(PE_ENTRY, PE_BASE, 0, 0).low == 1);
    CHECK(clock_close_calls == closes && clock_owned);
    CHECK(clock_call(RVA_NtwQueryCoreClock, counter, frequency) == 0 && last_error == NTWV_ERROR_NOT_READY);
    CHECK(clock_open_calls == opens && clock_close_calls == closes && clock_vq_calls == vq);
    CHECK(call0(RVA_NtwShutdownCoreClock).low == 0 && last_error == 5 && clock_owned);
    clock_close_error = 0; last_error = 0x4545;
    CHECK(call0(RVA_NtwShutdownCoreClock).low == 1 && last_error == 0x4545 && !clock_owned);
    closes = clock_close_calls;
    CHECK(call0(RVA_NtwShutdownCoreClock).low == 1 && last_error == 0x4545 && clock_close_calls == closes);
    CHECK(clock_call(RVA_NtQueryPerformanceCounter, counter, frequency) == UINT32_C(0xc00000a3) && last_error == 0x4545);
}
