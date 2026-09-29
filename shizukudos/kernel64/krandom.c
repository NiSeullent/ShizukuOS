/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 random number generator: an entropy pool plus a ChaCha20 CSPRNG, the source behind NtShzRandom (0xa0) and
 * therefore behind every user-mode random API (bcryptprimitives!ProcessPrng, BCryptGenRandom, RtlGenRandom via Wine's
 * cryptbase, UuidCreate). The design follows the Linux random driver in outline:
 *
 *   pool     BLAKE2s-256 over everything collected (hashing makes the order and form of inputs irrelevant)
 *   inputs   at boot: RDSEED and RDRAND when the CPU has them, the TSC, the wall clock, boot information, and a CPU
 *            execution-jitter sample (4096 timed runs of a data-dependent memory walk); afterwards: the TSC and
 *            instruction pointer of every hardware interrupt (a cheap per-interrupt mix, folded into the pool every
 *            64 interrupts)
 *   output   ChaCha20 keyed from the pool; the key is replaced after every request (fast key erasure) and reseeded from
 *            the pool at least every second of interrupts
 *
 * Without RDRAND/RDSEED (Intel before Ivy Bridge, many VMs) the generator still works: the boot jitter sample and the
 * interrupt timings are the entropy. That is what Windows and Linux do on such CPUs; the previous user-mode source
 * (RDRAND only) failed outright there, and with it every caller of ProcessPrng (Chromium's base included).
 */
#include "proc_internal.h"

/* ---------------------------------------------------------------- BLAKE2s-256 (RFC 7693) */
typedef struct { uint32_t h[8], t[2], f[2]; uint8_t buf[64]; size_t n; } b2s_t;
static const uint32_t b2s_iv[8] = { 0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                                    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u };
static const uint8_t b2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 }, { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 }, { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 }, { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 }, { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 } };

static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static uint32_t rotl32(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
static uint32_t le32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static void b2s_compress(b2s_t *s, int last)
{
    uint32_t v[16], m[16];
    unsigned i, r;
    for (i = 0; i < 16; ++i) m[i] = le32(s->buf + 4 * i);
    for (i = 0; i < 8; ++i) { v[i] = s->h[i]; v[i + 8] = b2s_iv[i]; }
    v[12] ^= s->t[0]; v[13] ^= s->t[1];
    if (last) v[14] = ~v[14];
#define G(a, b, c, d, x, y) do { v[a] += v[b] + (x); v[d] = rotr32(v[d] ^ v[a], 16); v[c] += v[d]; v[b] = rotr32(v[b] ^ v[c], 12); \
                                 v[a] += v[b] + (y); v[d] = rotr32(v[d] ^ v[a], 8); v[c] += v[d]; v[b] = rotr32(v[b] ^ v[c], 7); } while (0)
    for (r = 0; r < 10; ++r) {
        const uint8_t *z = b2s_sigma[r];
        G(0, 4, 8, 12, m[z[0]], m[z[1]]); G(1, 5, 9, 13, m[z[2]], m[z[3]]);
        G(2, 6, 10, 14, m[z[4]], m[z[5]]); G(3, 7, 11, 15, m[z[6]], m[z[7]]);
        G(0, 5, 10, 15, m[z[8]], m[z[9]]); G(1, 6, 11, 12, m[z[10]], m[z[11]]);
        G(2, 7, 8, 13, m[z[12]], m[z[13]]); G(3, 4, 9, 14, m[z[14]], m[z[15]]);
    }
#undef G
    for (i = 0; i < 8; ++i) s->h[i] ^= v[i] ^ v[i + 8];
}

static void b2s_init(b2s_t *s)
{
    unsigned i;
    memset(s, 0, sizeof *s);
    for (i = 0; i < 8; ++i) s->h[i] = b2s_iv[i];
    s->h[0] ^= 0x01010000u ^ 32u;                    /* digest length 32, no key, fanout/depth 1 */
}

static void b2s_update(b2s_t *s, const void *data, size_t len)
{
    const uint8_t *p = data;
    while (len) {
        size_t k;
        if (s->n == 64) {                            /* a full block is compressed only once more input follows */
            s->t[0] += 64;
            if (s->t[0] < 64) ++s->t[1];
            b2s_compress(s, 0);
            s->n = 0;
        }
        k = 64 - s->n < len ? 64 - s->n : len;
        memcpy(s->buf + s->n, p, k);
        s->n += k; p += k; len -= k;
    }
}

static void b2s_final(b2s_t *s, uint8_t out[32])
{
    unsigned i;
    s->t[0] += (uint32_t)s->n;
    if (s->t[0] < s->n) ++s->t[1];
    memset(s->buf + s->n, 0, 64 - s->n);
    b2s_compress(s, 1);
    for (i = 0; i < 8; ++i) { out[4 * i] = (uint8_t)s->h[i]; out[4 * i + 1] = (uint8_t)(s->h[i] >> 8);
                              out[4 * i + 2] = (uint8_t)(s->h[i] >> 16); out[4 * i + 3] = (uint8_t)(s->h[i] >> 24); }
}

/* ---------------------------------------------------------------- ChaCha20 block (RFC 8439) */
static void chacha20_block(const uint32_t key[8], uint64_t counter, uint8_t out[64])
{
    uint32_t x[16], s[16];
    unsigned i;
    s[0] = 0x61707865u; s[1] = 0x3320646eu; s[2] = 0x79622d32u; s[3] = 0x6b206574u;
    for (i = 0; i < 8; ++i) s[4 + i] = key[i];
    s[12] = (uint32_t)counter; s[13] = (uint32_t)(counter >> 32); s[14] = 0; s[15] = 0;
    memcpy(x, s, sizeof x);
#define QR(a, b, c, d) do { x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
                            x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7); } while (0)
    for (i = 0; i < 10; ++i) {
        QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);
        QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);
    }
#undef QR
    for (i = 0; i < 16; ++i) {
        const uint32_t v = x[i] + s[i];
        out[4 * i] = (uint8_t)v; out[4 * i + 1] = (uint8_t)(v >> 8); out[4 * i + 2] = (uint8_t)(v >> 16); out[4 * i + 3] = (uint8_t)(v >> 24);
    }
}

/* ---------------------------------------------------------------- state */
static b2s_t pool;                                   /* everything collected so far (never output directly) */
static uint32_t crng_key[8];
static uint64_t crng_counter, crng_reseed_irqs;
static uint64_t fast[4];                             /* per-interrupt mixing, folded into the pool every 64 interrupts */
static unsigned fast_count;
static uint64_t irqs_total, jitter_bits;
static int ready, hw_rdrand, hw_rdseed;

static inline uint64_t rdtsc(void) { uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); return (uint64_t)hi << 32 | lo; }

static int rdrand64(uint64_t *v)
{
    unsigned i;
    for (i = 0; i < 10; ++i) {                       /* Intel DRNG guide: retry up to 10 times */
        unsigned char ok;
        __asm__ volatile("rdrand %0; setc %1" : "=r"(*v), "=qm"(ok) : : "cc");
        if (ok) return 1;
    }
    return 0;
}

static int rdseed64(uint64_t *v)
{
    unsigned i;
    for (i = 0; i < 100; ++i) {                      /* RDSEED underflows more often than RDRAND: retry with a pause */
        unsigned char ok;
        __asm__ volatile("rdseed %0; setc %1" : "=r"(*v), "=qm"(ok) : : "cc");
        if (ok) return 1;
        __asm__ volatile("pause");
    }
    return 0;
}

/* pool -> new ChaCha20 key (the pool itself continues: its digest is taken from a copy) */
static void crng_reseed(void)
{
    b2s_t copy = pool;
    uint8_t k[32];
    unsigned i;
    uint64_t v;
    if (hw_rdrand && rdrand64(&v)) b2s_update(&copy, &v, sizeof v);
    b2s_update(&copy, crng_key, sizeof crng_key);    /* chain the previous key */
    b2s_final(&copy, k);
    for (i = 0; i < 8; ++i) crng_key[i] = le32(k + 4 * i);
    b2s_update(&pool, k, 1);                         /* the pool moves on, so two reseeds never give the same key */
    memset(k, 0, sizeof k);
    memset(&copy, 0, sizeof copy);
    crng_counter = 0;
    crng_reseed_irqs = irqs_total;
}

/* CPU execution jitter: the time a data-dependent memory walk takes varies with cache, TLB, pipeline and (in a VM) host
 * scheduling state. Each sample's low bits go into the pool; one bit of entropy per sample is credited only when the
 * delta changed from the previous one (a stuck timer credits nothing). */
static void collect_jitter(unsigned samples)
{
    static volatile uint8_t mem[4096];
    uint64_t prev = 0, acc = 0x9e3779b97f4a7c15ull;
    unsigned i, j, credited = 0;
    for (i = 0; i < samples; ++i) {
        const uint64_t t0 = rdtsc();
        for (j = 0; j < 64; ++j) {
            const unsigned idx = (unsigned)((acc >> 17) ^ j * 131u) & 4095u;
            mem[idx] = (uint8_t)(mem[idx] + (uint8_t)acc);
            acc = acc * 6364136223846793005ull + mem[(idx * 7u) & 4095u];
        }
        {
            const uint64_t d = rdtsc() - t0;
            b2s_update(&pool, &d, sizeof d);
            if (d != prev) ++credited;
            prev = d;
        }
    }
    b2s_update(&pool, &acc, sizeof acc);
    jitter_bits += credited;
}

/* Known-answer tests of the two primitives: BLAKE2s-256("abc") from RFC 7693 appendix B, and the ChaCha20 block for
 * the all-zero key, nonce and counter (the first test vector of draft-agl-tls-chacha20poly1305 / RFC 8439 A.1 #1). */
static int krandom_selftest(void)
{
    static const uint8_t b2s_abc[32] = {
        0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2, 0xE1, 0xA7, 0x2B, 0xA3, 0x4E, 0xEB, 0x45, 0x2F,
        0x37, 0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A, 0x29, 0x4D, 0x99, 0x9B, 0x4C, 0x86, 0x67, 0x59, 0x82 };
    static const uint8_t chacha_zero[16] = {
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28 };
    static const uint8_t chacha_zero_tail[4] = { 0xb2, 0xee, 0x65, 0x86 };
    static const uint32_t zero_key[8];
    b2s_t s;
    uint8_t out[64];
    b2s_init(&s);
    b2s_update(&s, "abc", 3);
    b2s_final(&s, out);
    if (memcmp(out, b2s_abc, 32)) return 0;
    chacha20_block(zero_key, 0, out);
    return !memcmp(out, chacha_zero, 16) && !memcmp(out + 60, chacha_zero_tail, 4);
}

void krandom_init(const void *boot_data, size_t boot_len)
{
    uint32_t a = 1, b = 0, c = 0, d = 0;
    uint64_t v, t;
    unsigned i, hw_words = 0;
    b2s_init(&pool);
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    hw_rdrand = (int)((c >> 30) & 1u);
    a = 7; b = 0; c = 0; d = 0;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    hw_rdseed = (int)((b >> 18) & 1u);
    for (i = 0; i < 8; ++i) {                        /* 512 bits from the hardware when present */
        if ((hw_rdseed && rdseed64(&v)) || (hw_rdrand && rdrand64(&v))) { b2s_update(&pool, &v, sizeof v); ++hw_words; }
    }
    t = rdtsc();
    b2s_update(&pool, &t, sizeof t);
    t = shz_time_ns();                               /* wall clock (RTC / hypervisor time) */
    b2s_update(&pool, &t, sizeof t);
    if (boot_data && boot_len) b2s_update(&pool, boot_data, boot_len);
    collect_jitter(4096);
    crng_reseed();
    ready = 1;
    kprintf("K64 test %s: random: BLAKE2s-256 and ChaCha20 known-answer tests\n", krandom_selftest() ? "PASS" : "FAIL");
    kprintf("K64 random: pool seeded (%u hardware words%s%s, %llu jitter bits credited); ChaCha20 CSPRNG ready\n",
            hw_words, hw_rdseed ? ", RDSEED" : "", hw_rdrand ? ", RDRAND" : ", no RDRAND", jitter_bits);
}

/* Every hardware interrupt: the arrival time is the entropy (cheap: no hashing here). */
void krandom_irq(uint64_t vector, uint64_t rip)
{
    const uint64_t t = rdtsc();
    fast[0] += t; fast[1] ^= rip; fast[2] = (fast[2] << 13 | fast[2] >> 51) ^ fast[0] ^ vector; fast[3] += fast[2] * 0x9e3779b97f4a7c15ull;
    ++irqs_total;
    if (++fast_count >= 64) {                        /* fold into the pool */
        b2s_update(&pool, fast, sizeof fast);
        fast_count = 0;
    }
}

/* Fill buf with n bytes. Always succeeds once krandom_init ran. */
void krandom_get(void *buf, size_t n)
{
    uint8_t block[64];
    uint8_t *p = buf;
    uint64_t f = irq_save();
    unsigned i;
    if (!ready) krandom_init(0, 0);                  /* never output from an unseeded generator */
    if (irqs_total - crng_reseed_irqs >= 1000)       /* about once a second of timer interrupts */
        crng_reseed();
    while (n) {
        const size_t k = n < 64 ? n : 64;
        chacha20_block(crng_key, ++crng_counter, block);
        memcpy(p, block, k);
        p += k; n -= k;
    }
    chacha20_block(crng_key, ++crng_counter, block); /* fast key erasure: the next key is keystream nobody saw */
    for (i = 0; i < 8; ++i) crng_key[i] = le32(block + 4 * i);
    memset(block, 0, sizeof block);
    irq_restore(f);
}

/* 0xa0 NtShzRandom(PVOID buffer, SIZE_T length): the system RNG for user mode (at most 1 MiB per call). */
int32_t sys_ext_misc(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)r; (void)a3; (void)a4;
    if (num == SYS_NtShzRandom) {
        uint8_t tmp[256];
        uint64_t done = 0;
        if (a2 > (1u << 20)) return STATUS_INVALID_PARAMETER;
        while (done < a2) {
            const uint64_t k = a2 - done < sizeof tmp ? a2 - done : sizeof tmp;
            krandom_get(tmp, k);
            if (copy_to_user(cur, a1 + done, tmp, k)) { memset(tmp, 0, sizeof tmp); return STATUS_ACCESS_VIOLATION; }
            done += k;
        }
        memset(tmp, 0, sizeof tmp);
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_SYSTEM_SERVICE;
}
