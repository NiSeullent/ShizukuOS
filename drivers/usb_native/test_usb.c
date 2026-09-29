/* SPDX-License-Identifier: GPL-2.0-only
 * Original hosted USB descriptor tests. No controller, OS or USB I/O.
 * The success oracle walks caller bytes independently of parser internals.
 */
#include "ntwu_usb.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t assertions, calls, device_ok, config_ok, rejected;
static uint64_t mutations, random_cases, truncations;
static const char *phase = "initialization";

#define CHECK(x) do { ++assertions; if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d %s phase=%s calls=%" PRIu64 \
            " mutations=%" PRIu64 " random=%" PRIu64 "\n", \
            __FILE__, __LINE__, #x, phase, calls, mutations, random_cases); \
    exit(1); } } while (0)

enum expectation { ANY_RESULT = 100, MUST_REJECT = 101 };
struct blob { uint8_t bytes[NTWU_MAX_BLOB + 1u]; size_t length; };

static uint16_t word(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static void put_word(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}
static int decimal_bcd(uint16_t value)
{
    unsigned shift;
    for (shift = 0; shift < 16; shift += 4)
        if (((value >> shift) & 15u) > 9u) return 0;
    return 1;
}
static unsigned address_index(uint8_t address)
{
    return (address & 15u) + ((address & 128u) ? 16u : 0u);
}
static void expected_result(struct ntwu_result r, size_t length, int expected)
{
    CHECK(r.status <= NTWU_OK && r.status >= NTWU_INCONSISTENT);
    CHECK((size_t)r.offset <= length);
    if (expected == MUST_REJECT) CHECK(r.status != NTWU_OK);
    else if (expected != ANY_RESULT) CHECK(r.status == expected);
}
static void device_oracle(const uint8_t *p, size_t n, enum ntwu_speed speed,
                          const struct ntwu_device *d)
{
    CHECK(n == 18 && p[0] == 18 && p[1] == 1);
    CHECK(speed >= NTWU_LOW_SPEED && speed <= NTWU_HIGH_SPEED);
    CHECK(word(p + 2) == 0x0100 || word(p + 2) == 0x0110 || word(p + 2) == 0x0200);
    CHECK(speed != NTWU_HIGH_SPEED || word(p + 2) == 0x0200);
    CHECK(decimal_bcd(word(p + 2)) && decimal_bcd(word(p + 12)));
    CHECK(p[17] != 0 && (p[4] != 0 || (p[5] == 0 && p[6] == 0)));
    if (speed == NTWU_LOW_SPEED) CHECK(p[7] == 8);
    if (speed == NTWU_HIGH_SPEED) CHECK(p[7] == 64);
    if (speed == NTWU_FULL_SPEED)
        CHECK(p[7] == 8 || p[7] == 16 || p[7] == 32 || p[7] == 64);
    CHECK(d->struct_size == sizeof(*d) && d->abi_version == NTWU_ABI_VERSION);
    CHECK(d->usb_bcd == word(p + 2) && d->vendor_id == word(p + 8));
    CHECK(d->product_id == word(p + 10) && d->device_bcd == word(p + 12));
    CHECK(d->device_class == p[4] && d->subclass == p[5] && d->protocol == p[6]);
    CHECK(d->control_packet_bytes == p[7] && d->manufacturer_string == p[14]);
    CHECK(d->product_string == p[15] && d->serial_string == p[16]);
    CHECK(d->configuration_count == p[17] && d->speed == (uint8_t)speed);
}
static void config_oracle(const uint8_t *p, size_t n, enum ntwu_speed speed,
                          const struct ntwu_configuration *c)
{
    uint8_t seen_alt[NTWU_MAX_INTERFACES][256] = {{0}};
    uint8_t seen_address[NTWU_MAX_ALTERNATES][32] = {{0}};
    uint8_t seen_interface[NTWU_MAX_INTERFACES] = {0};
    unsigned max_active_endpoints[NTWU_MAX_INTERFACES] = {0};
    int owner[32];
    size_t at = 9;
    unsigned alts = 0, endpoints = 0, opaque = 0, interfaces = 0, i;
    uint16_t current = NTWU_NO_INDEX, preceding_ep = NTWU_NO_INDEX;
    for (i = 0; i < 32; ++i) owner[i] = -1;
    CHECK(n >= 9 && n <= NTWU_MAX_BLOB && p[0] == 9 && p[1] == 2);
    CHECK(word(p + 2) == n && p[4] <= NTWU_MAX_INTERFACES);
    CHECK(p[5] != 0 && (p[7] & 128u) && !(p[7] & 31u) && p[8] <= 250);
    CHECK(c->struct_size == sizeof(*c) && c->abi_version == NTWU_ABI_VERSION);
    CHECK(c->total_length == n && c->configuration_value == p[5]);
    CHECK(c->interface_count == p[4] && c->attributes == p[7]);
    CHECK(c->string_index == p[6] && c->max_power_ma == (uint16_t)(p[8] * 2u));
    CHECK(c->speed == (uint8_t)speed && speed >= NTWU_LOW_SPEED && speed <= NTWU_HIGH_SPEED);
    CHECK(c->alternate_count <= NTWU_MAX_ALTERNATES);
    CHECK(c->endpoint_count <= NTWU_MAX_ENDPOINTS && c->opaque_count <= NTWU_MAX_OPAQUE);
    while (at < n) {
        unsigned length, type;
        CHECK(n - at >= 2);
        length = p[at]; type = p[at + 1];
        CHECK(length >= 2 && length <= n - at);
        if (type == 4) {
            const struct ntwu_interface *a;
            unsigned number, alternate;
            CHECK(length == 9 && alts < c->alternate_count);
            number = p[at + 2]; alternate = p[at + 3];
            CHECK(number < p[4] && number < NTWU_MAX_INTERFACES);
            CHECK(!seen_alt[number][alternate]);
            seen_alt[number][alternate] = 1;
            if (!seen_interface[number]) { seen_interface[number] = 1; ++interfaces; }
            current = (uint16_t)alts; preceding_ep = NTWU_NO_INDEX;
            a = &c->alternates[alts++];
            CHECK(a->offset == at && a->number == number && a->alternate == alternate);
            CHECK(a->first_endpoint == endpoints && a->declared_endpoints == p[at + 4]);
            CHECK(a->class_code == p[at + 5] && a->class_code != 0);
            CHECK(a->subclass == p[at + 6] && a->protocol == p[at + 7]);
            CHECK(a->string_index == p[at + 8]);
        } else if (type == 5) {
            const struct ntwu_endpoint *ep;
            const struct ntwu_interface *a;
            unsigned addr, index, kind, packet, interval;
            CHECK(length == 7 && current != NTWU_NO_INDEX && endpoints < c->endpoint_count);
            a = &c->alternates[current];
            addr = p[at + 2]; index = address_index((uint8_t)addr);
            kind = p[at + 3]; packet = word(p + at + 4); interval = p[at + 6];
            CHECK((addr & 15u) != 0 && (addr & 0x70u) == 0);
            CHECK(!seen_address[current][index]); seen_address[current][index] = 1;
            CHECK(owner[index] == -1 || owner[index] == a->number);
            owner[index] = a->number;
            CHECK(kind == 2 || kind == 3);
            CHECK((packet & 0xf800u) == 0);
            if (kind == 2) {
                CHECK(speed != NTWU_LOW_SPEED);
                if (speed == NTWU_HIGH_SPEED) CHECK(packet == 512);
                else CHECK(packet == 8 || packet == 16 || packet == 32 || packet == 64);
            } else {
                CHECK(interval != 0);
                if (speed == NTWU_LOW_SPEED) CHECK(packet <= 8);
                if (speed == NTWU_FULL_SPEED) CHECK(packet <= 64);
                if (speed == NTWU_HIGH_SPEED) {
                    CHECK(packet <= 1024 && interval <= 16);
                    CHECK(a->alternate != 0 || packet <= 64);
                }
            }
            ep = &c->endpoints[endpoints];
            CHECK(ep->offset == at && ep->alternate_index == current);
            CHECK(ep->address == addr && ep->transfer_type == kind);
            CHECK(ep->max_packet_bytes == packet && ep->interval == interval);
            CHECK(ep->transactions == 1);
            preceding_ep = (uint16_t)endpoints++;
        } else {
            const struct ntwu_opaque *o;
            CHECK(type == 11 || type >= 0x20);
            CHECK(type != 0x30 && type != 0x31 && opaque < c->opaque_count);
            o = &c->opaque[opaque++];
            CHECK(o->offset == at && o->length == length && o->type == type);
            CHECK(o->preceding_alternate == current && o->preceding_endpoint == preceding_ep);
        }
        at += length;
    }
    CHECK(at == n && alts == c->alternate_count && endpoints == c->endpoint_count);
    CHECK(opaque == c->opaque_count && interfaces == c->interface_count);
    for (i = 0; i < interfaces; ++i) CHECK(seen_interface[i] && seen_alt[i][0]);
    for (i = 0; i < alts; ++i) {
        const struct ntwu_interface *a = &c->alternates[i];
        unsigned j, count = 0;
        for (j = 0; j < endpoints; ++j) if (c->endpoints[j].alternate_index == i) ++count;
        CHECK(a->endpoint_count == count && a->declared_endpoints == count);
        CHECK((unsigned)a->first_endpoint + count <= endpoints);
        if (count > max_active_endpoints[a->number]) max_active_endpoints[a->number] = count;
    }
    if (speed == NTWU_LOW_SPEED) {
        unsigned active = 0;
        for (i = 0; i < interfaces; ++i) active += max_active_endpoints[i];
        CHECK(active <= 2);
    }
}

/* Every call gets an exactly sized heap object: ASan can catch a read even one
 * byte past the supplied length, rather than hiding it in a larger fixture. */
static void device_call(const uint8_t *source, size_t n, enum ntwu_speed speed, int expected)
{
    struct ntwu_device out, sentinel;
    struct ntwu_result r;
    uint8_t *input = malloc(n);
    CHECK(n == 0 || input != NULL);
    if (n) memcpy(input, source, n);
    memset(&out, 0xa5, sizeof(out)); memcpy(&sentinel, &out, sizeof(out));
    ++calls; r = ntwu_parse_device(input, n, speed, &out);
    expected_result(r, n, expected);
    if (n) CHECK(memcmp(input, source, n) == 0);
    if (r.status == NTWU_OK) { ++device_ok; device_oracle(input, n, speed, &out); }
    else { ++rejected; CHECK(memcmp(&out, &sentinel, sizeof(out)) == 0); }
    free(input);
}
static void config_call(const uint8_t *source, size_t n, enum ntwu_speed speed, int expected)
{
    struct ntwu_configuration out, sentinel;
    struct ntwu_result r;
    uint8_t *input = malloc(n);
    CHECK(n == 0 || input != NULL);
    if (n) memcpy(input, source, n);
    memset(&out, 0xa5, sizeof(out)); memcpy(&sentinel, &out, sizeof(out));
    ++calls; r = ntwu_parse_configuration(input, n, speed, &out);
    expected_result(r, n, expected);
    if (n) CHECK(memcmp(input, source, n) == 0);
    if (r.status == NTWU_OK) { ++config_ok; config_oracle(input, n, speed, &out); }
    else { ++rejected; CHECK(memcmp(&out, &sentinel, sizeof(out)) == 0); }
    free(input);
}
static struct blob configuration(uint8_t interfaces)
{
    struct blob b = {{9, 2, 9, 0, 0, 1, 7, 0x80, 50}, 9};
    b.bytes[4] = interfaces;
    return b;
}
static void append(struct blob *b, const uint8_t *p, size_t n)
{
    CHECK(n <= sizeof(b->bytes) - b->length);
    memcpy(b->bytes + b->length, p, n); b->length += n;
    put_word(b->bytes + 2, (uint16_t)b->length);
}
static void alternate(struct blob *b, uint8_t number, uint8_t alt, uint8_t endpoints)
{
    const uint8_t p[9] = {9, 4, number, alt, endpoints, 0xff, 6, 0x50, 9};
    append(b, p, sizeof(p));
}
static void endpoint(struct blob *b, uint8_t address, uint8_t type,
                     uint16_t packet, uint8_t interval)
{
    uint8_t p[7] = {7, 5, address, type, 0, 0, interval};
    put_word(p + 4, packet); append(b, p, sizeof(p));
}
static void opaque_record(struct blob *b, uint8_t type, uint8_t length)
{
    uint8_t p[255] = {0};
    CHECK(length >= 2); p[0] = length; p[1] = type;
    append(b, p, length);
}
static struct blob single(uint8_t type, uint16_t packet, uint8_t interval)
{
    struct blob b = configuration(1);
    alternate(&b, 0, 0, 1); endpoint(&b, 0x81, type, packet, interval);
    return b;
}
static void parse_blob(const struct blob *b, enum ntwu_speed speed, int expected)
{
    config_call(b->bytes, b->length, speed, expected);
}

static void device_cases(void)
{
    static const uint8_t good[19] = {18,1,0,2,0,0,0,64,0x34,0x12,0x78,0x56,0x21,1,1,2,3,1,0};
    uint8_t p[19]; unsigned i, v;
    phase = "device fixtures";
    for (i = 0; i < 18; ++i) { ++truncations; device_call(good,i,NTWU_FULL_SPEED,MUST_REJECT); }
    device_call(good,19,NTWU_FULL_SPEED,MUST_REJECT);
    device_call(good,18,NTWU_FULL_SPEED,NTWU_OK);
    device_call(good,18,NTWU_HIGH_SPEED,NTWU_OK);
    device_call(good,18,NTWU_SUPER_SPEED,NTWU_UNSUPPORTED);
    memcpy(p,good,sizeof(p)); p[6]=9;
    device_call(p,18,NTWU_FULL_SPEED,NTWU_UNSUPPORTED);
    memcpy(p,good,sizeof(p)); p[0]=19;
    device_call(p,19,NTWU_FULL_SPEED,NTWU_UNSUPPORTED);
    for (i = 0; i < 4; ++i) {
        memcpy(p,good,sizeof(p)); p[7]=(uint8_t)(8u << i);
        device_call(p,18,NTWU_FULL_SPEED,NTWU_OK);
    }
    memcpy(p,good,sizeof(p)); p[7]=8;
    device_call(p,18,NTWU_LOW_SPEED,NTWU_OK);
    p[2]=0x10; p[3]=1; device_call(p,18,NTWU_LOW_SPEED,NTWU_OK);
    p[2]=0; device_call(p,18,NTWU_LOW_SPEED,NTWU_OK);
    device_call(p,18,NTWU_HIGH_SPEED,MUST_REJECT);
    phase = "device exhaustive single-byte mutations";
    for (i = 0; i < 18; ++i) for (v = 0; v < 256; ++v) {
        memcpy(p,good,sizeof(p)); p[i]=(uint8_t)v; ++mutations;
        device_call(p,18,NTWU_FULL_SPEED,ANY_RESULT);
    }
}
static void topology_cases(void)
{
    struct blob b, changed; size_t n; unsigned i;
    phase = "configuration topology";
    b=single(2,64,0); parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    for (n=0;n<b.length;++n) { ++truncations; config_call(b.bytes,n,NTWU_FULL_SPEED,MUST_REJECT); }
    for (i=0;i<9;++i) {
        changed=b;
        switch(i) {
        case 0: changed.bytes[0]=8; break;
        case 1: changed.bytes[0]=10; break;
        case 2: changed.bytes[2]=0; break;
        case 3: changed.bytes[2]=(uint8_t)(b.length-1); break;
        case 4: changed.bytes[2]=(uint8_t)(b.length+1); break;
        case 5: changed.bytes[4]=2; break;
        case 6: changed.bytes[5]=0; break;
        case 7: changed.bytes[7]=0; break;
        default: changed.bytes[8]=251; break;
        }
        parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
    }
    changed=b; changed.bytes[changed.length++]=0; parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
    for (i=0;i<2;++i) {
        changed=b; changed.bytes[9]=(uint8_t)i; parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
        changed=b; changed.bytes[18]=(uint8_t)i; parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
    }
    changed=b; changed.bytes[9]=10; parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
    changed=b; changed.bytes[18]=8; parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
    /* Extended known records remain correctly framed, so rejection cannot
     * depend merely on damaging the following descriptor boundary. */
    changed=b; memmove(changed.bytes+10,changed.bytes+9,changed.length-9);
    changed.bytes[0]=10;changed.bytes[9]=0;++changed.length;
    put_word(changed.bytes+2,(uint16_t)changed.length);
    parse_blob(&changed,NTWU_FULL_SPEED,NTWU_UNSUPPORTED);
    changed=b;memmove(changed.bytes+19,changed.bytes+18,changed.length-18);
    changed.bytes[9]=10;changed.bytes[18]=0;++changed.length;
    put_word(changed.bytes+2,(uint16_t)changed.length);
    parse_blob(&changed,NTWU_FULL_SPEED,NTWU_UNSUPPORTED);
    changed=b;changed.bytes[18]=8;changed.bytes[changed.length++]=0;
    put_word(changed.bytes+2,(uint16_t)changed.length);
    parse_blob(&changed,NTWU_FULL_SPEED,NTWU_UNSUPPORTED);
    changed=b; changed.bytes[14]=0; parse_blob(&changed,NTWU_FULL_SPEED,NTWU_UNSUPPORTED);
    changed=b; changed.bytes[13]=0; parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
    changed=b; changed.bytes[13]=2; parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
    changed=b; changed.bytes[11]=1; parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
    changed=b; changed.bytes[12]=1; parse_blob(&changed,NTWU_FULL_SPEED,MUST_REJECT);
    b=configuration(1); endpoint(&b,0x81,2,64,0); alternate(&b,0,0,0);
    parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    b=configuration(1); alternate(&b,0,0,2); endpoint(&b,0x81,2,64,0); endpoint(&b,0x81,2,64,0);
    parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    b=configuration(1); alternate(&b,0,0,0); alternate(&b,0,0,0);
    parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    b=configuration(1); alternate(&b,0,0,1); endpoint(&b,0x81,2,64,0);
    alternate(&b,0,3,1); endpoint(&b,0x81,2,64,0);
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    b=configuration(1); alternate(&b,0,3,1); endpoint(&b,0x81,2,64,0);
    alternate(&b,0,0,1); endpoint(&b,0x81,2,64,0);
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    b=configuration(2); alternate(&b,0,0,1); endpoint(&b,0x81,2,64,0);
    alternate(&b,1,0,1); endpoint(&b,0x81,2,64,0);
    parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    b=configuration(2); alternate(&b,0,0,0); alternate(&b,0,1,1); endpoint(&b,0x81,2,64,0);
    alternate(&b,1,0,1); endpoint(&b,0x81,2,64,0);
    parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    b=configuration(1); alternate(&b,0,0,2); endpoint(&b,0x81,2,64,0); endpoint(&b,1,2,64,0);
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    b=configuration(2);alternate(&b,1,0,1);endpoint(&b,0x82,2,64,0);
    alternate(&b,0,0,1);endpoint(&b,0x81,2,64,0);
    b.bytes[7]=0xe0;b.bytes[8]=250;parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
}
static void endpoint_cases(void)
{
    struct blob b; unsigned i;
    static const uint8_t bad_addresses[]={0,0x80,0x10,0x91,0x7f,0xff};
    static const uint16_t bad_bulk[]={0,1,7,9,63,65,512,1024,0x0840,0x1040,0x8040};
    phase="endpoint speed and packet contracts";
    for(i=0;i<sizeof(bad_addresses);++i) {
        b=single(2,64,0);b.bytes[20]=bad_addresses[i];parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    }
    for(i=0;i<sizeof(bad_bulk)/sizeof(bad_bulk[0]);++i) {
        b=single(2,bad_bulk[i],0);parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    }
    for(i=0;i<4;++i) {
        b=single(2,(uint16_t)(8u<<i),0);parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    }
    b=single(2,512,0);parse_blob(&b,NTWU_HIGH_SPEED,NTWU_OK);
    parse_blob(&b,NTWU_LOW_SPEED,NTWU_UNSUPPORTED);
    b=single(2,64,0);parse_blob(&b,NTWU_HIGH_SPEED,MUST_REJECT);
    b=single(0,8,1);parse_blob(&b,NTWU_FULL_SPEED,NTWU_UNSUPPORTED);
    b=single(1,8,1);parse_blob(&b,NTWU_FULL_SPEED,NTWU_UNSUPPORTED);
    b=single(0x12,64,1);parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    b=single(3,8,1);parse_blob(&b,NTWU_LOW_SPEED,NTWU_OK);
    b=single(3,0,255);parse_blob(&b,NTWU_LOW_SPEED,NTWU_OK);
    b=single(3,9,1);parse_blob(&b,NTWU_LOW_SPEED,MUST_REJECT);
    b=single(3,64,255);parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    b=single(3,65,1);parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    b=single(3,1,0);parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    b=single(3,64,16);parse_blob(&b,NTWU_HIGH_SPEED,NTWU_OK);
    b=single(3,0,1);parse_blob(&b,NTWU_HIGH_SPEED,NTWU_OK);
    b=single(3,65,1);parse_blob(&b,NTWU_HIGH_SPEED,NTWU_UNSUPPORTED);
    b=single(3,64,17);parse_blob(&b,NTWU_HIGH_SPEED,MUST_REJECT);
    b=configuration(1);alternate(&b,0,0,0);alternate(&b,0,1,1);endpoint(&b,0x81,3,1024,16);
    parse_blob(&b,NTWU_HIGH_SPEED,NTWU_OK);
    put_word(b.bytes+b.length-3,1025);parse_blob(&b,NTWU_HIGH_SPEED,MUST_REJECT);
    put_word(b.bytes+b.length-3,0x0c00);parse_blob(&b,NTWU_HIGH_SPEED,NTWU_UNSUPPORTED);
    parse_blob(&b,NTWU_SUPER_SPEED,NTWU_UNSUPPORTED);
    phase="low-speed simultaneous endpoint limit";
    b=configuration(1);alternate(&b,0,0,3);
    endpoint(&b,0x81,3,8,1);endpoint(&b,0x82,3,8,1);endpoint(&b,3,3,8,1);
    parse_blob(&b,NTWU_LOW_SPEED,NTWU_INCONSISTENT);
    b=configuration(2);alternate(&b,0,0,0);alternate(&b,0,1,2);
    endpoint(&b,0x81,3,8,1);endpoint(&b,0x82,3,8,1);
    alternate(&b,1,0,1);endpoint(&b,0x83,3,8,1);
    parse_blob(&b,NTWU_LOW_SPEED,NTWU_INCONSISTENT);
    b=configuration(1);alternate(&b,0,0,2);
    endpoint(&b,0x81,3,8,1);endpoint(&b,1,3,8,1);alternate(&b,0,1,2);
    endpoint(&b,0x81,3,8,1);endpoint(&b,1,3,8,1);
    parse_blob(&b,NTWU_LOW_SPEED,NTWU_OK);
    b=configuration(2);alternate(&b,0,0,1);endpoint(&b,0x81,3,8,1);
    alternate(&b,1,0,1);endpoint(&b,0x82,3,8,1);
    parse_blob(&b,NTWU_LOW_SPEED,NTWU_OK);
}
static void opaque_and_limits(void)
{
    struct blob b; unsigned i, j; size_t remaining;
    static const uint8_t forbidden[]={0,1,2,3,6,7,8,9,10,0x30,0x31};
    phase="opaque contexts and exact capacity limits";
    b=configuration(1);opaque_record(&b,11,8);alternate(&b,0,0,1);
    opaque_record(&b,0x24,5);endpoint(&b,0x81,3,8,1);opaque_record(&b,0x25,4);
    alternate(&b,0,1,0);opaque_record(&b,0xff,2);
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    for(i=0;i<sizeof(forbidden);++i) {
        b=configuration(1);alternate(&b,0,0,0);opaque_record(&b,forbidden[i],8);
        parse_blob(&b,NTWU_FULL_SPEED,MUST_REJECT);
    }
    b=configuration(16);for(i=0;i<16;++i)alternate(&b,(uint8_t)i,0,0);
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    b.bytes[4]=17;alternate(&b,16,0,0);parse_blob(&b,NTWU_FULL_SPEED,NTWU_LIMIT);
    b=configuration(1);for(i=0;i<32;++i)alternate(&b,0,(uint8_t)i,0);
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    alternate(&b,0,32,0);parse_blob(&b,NTWU_FULL_SPEED,NTWU_LIMIT);
    b=configuration(1);
    for(i=0;i<3;++i) {
        unsigned count=i<2?30u:4u;alternate(&b,0,(uint8_t)i,(uint8_t)count);
        for(j=0;j<count;++j)endpoint(&b,(uint8_t)(1u+j%15u+(j>=15?128u:0u)),2,64,0);
    }
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    b.bytes[9u+2u*(9u+30u*7u)+4u]=5;endpoint(&b,5,2,64,0);
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_LIMIT);
    b=configuration(1);alternate(&b,0,0,0);
    for(i=0;i<64;++i)opaque_record(&b,0x24,2);
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    opaque_record(&b,0x24,2);parse_blob(&b,NTWU_FULL_SPEED,NTWU_LIMIT);
    b=configuration(1);alternate(&b,0,0,0);
    while(b.length<NTWU_MAX_BLOB) {
        remaining=NTWU_MAX_BLOB-b.length;
        opaque_record(&b,0x24,(uint8_t)(remaining>255?255:remaining));
    }
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    b.bytes[b.length++]=0;put_word(b.bytes+2,(uint16_t)b.length);
    parse_blob(&b,NTWU_FULL_SPEED,NTWU_LIMIT);
}
static void invalid_and_overlap(void)
{
    union { max_align_t alignment; uint8_t bytes[1800]; } storage;
    uint8_t saved[sizeof(storage.bytes)];
    struct ntwu_device device, original_device;
    struct ntwu_configuration config, original_config;
    struct ntwu_result r;
    struct blob b=single(2,64,0);
    static const uint8_t d[18]={18,1,0,2,0,0,0,64,1,0,2,0,0,1,0,0,0,1};
    unsigned i;
    phase="invalid arguments and overlapping input/output";
    memset(&device,0xa5,sizeof(device));memcpy(&original_device,&device,sizeof(device));
    memset(&config,0xa5,sizeof(config));memcpy(&original_config,&config,sizeof(config));
    ++calls;r=ntwu_parse_device(NULL,18,NTWU_FULL_SPEED,&device);
    expected_result(r,18,NTWU_INVALID);++rejected;CHECK(memcmp(&device,&original_device,sizeof(device))==0);
    ++calls;r=ntwu_parse_configuration(NULL,b.length,NTWU_FULL_SPEED,&config);
    expected_result(r,b.length,NTWU_INVALID);++rejected;CHECK(memcmp(&config,&original_config,sizeof(config))==0);
    ++calls;r=ntwu_parse_device(d,sizeof(d),NTWU_FULL_SPEED,NULL);
    expected_result(r,sizeof(d),NTWU_INVALID);++rejected;
    ++calls;r=ntwu_parse_configuration(b.bytes,b.length,NTWU_FULL_SPEED,NULL);
    expected_result(r,b.length,NTWU_INVALID);++rejected;
    device_call(d,sizeof(d),(enum ntwu_speed)0,NTWU_INVALID);
    config_call(b.bytes,b.length,(enum ntwu_speed)99,NTWU_INVALID);
    ++calls;r=ntwu_parse_configuration(b.bytes,SIZE_MAX,NTWU_FULL_SPEED,&config);
    CHECK(r.status!=NTWU_OK && r.offset==0);++rejected;
    CHECK(memcmp(&config,&original_config,sizeof(config))==0);
    for(i=0;i<3;++i) {
        size_t input_offset=i==1?4u:0u,output_offset=i==2?4u:0u;
        memset(storage.bytes,0x69,sizeof(storage.bytes));memcpy(storage.bytes+input_offset,d,sizeof(d));
        memcpy(saved,storage.bytes,sizeof(saved));++calls;
        r=ntwu_parse_device(storage.bytes+input_offset,sizeof(d),NTWU_FULL_SPEED,
            (struct ntwu_device *)(void *)(storage.bytes+output_offset));
        expected_result(r,sizeof(d),NTWU_INVALID);++rejected;
        CHECK(memcmp(saved,storage.bytes,sizeof(saved))==0);
        memset(storage.bytes,0x69,sizeof(storage.bytes));memcpy(storage.bytes+input_offset,b.bytes,b.length);
        memcpy(saved,storage.bytes,sizeof(saved));++calls;
        r=ntwu_parse_configuration(storage.bytes+input_offset,b.length,NTWU_FULL_SPEED,
            (struct ntwu_configuration *)(void *)(storage.bytes+output_offset));
        expected_result(r,b.length,NTWU_INVALID);++rejected;
        CHECK(memcmp(saved,storage.bytes,sizeof(saved))==0);
    }
}
static uint32_t random_word(uint32_t *state)
{
    uint32_t x=*state;x^=x<<13;x^=x>>17;x^=x<<5;*state=x;return x;
}
static void mutation_and_generation(void)
{
    struct blob seed=single(2,64,0),b;
    uint32_t state=UINT32_C(0x95c0ffee);
    unsigned iteration,i,value;
    phase="configuration exhaustive single-byte mutations";
    for(i=0;i<seed.length;++i)for(value=0;value<256;++value) {
        b=seed;b.bytes[i]=(uint8_t)value;++mutations;parse_blob(&b,NTWU_FULL_SPEED,ANY_RESULT);
    }
    phase="deterministic configuration mutation stream";
    for(iteration=0;iteration<20000;++iteration) {
        unsigned count=1u+random_word(&state)%8u;
        b=seed;
        for(i=0;i<count;++i) {
            size_t position=random_word(&state)%b.length;
            b.bytes[position]=(uint8_t)random_word(&state);
        }
        if((iteration&3u)==0)b.length=random_word(&state)%(seed.length+1u);
        ++random_cases;parse_blob(&b,(enum ntwu_speed)(1u+iteration%3u),ANY_RESULT);
    }
    phase="deterministic arbitrary bounded blobs";
    for(iteration=0;iteration<10000;++iteration) {
        b.length=random_word(&state)%512u;
        for(i=0;i<b.length;++i)b.bytes[i]=(uint8_t)random_word(&state);
        ++random_cases;parse_blob(&b,NTWU_FULL_SPEED,ANY_RESULT);
    }
    phase="generated valid multi-interface alternate configurations";
    for(iteration=0;iteration<1000;++iteration) {
        unsigned interfaces=1u+random_word(&state)%4u;
        b=configuration((uint8_t)interfaces);
        opaque_record(&b,11,8);
        for(i=0;i<interfaces;++i) {
            unsigned alt,alternates=1u+random_word(&state)%3u;
            for(alt=0;alt<alternates;++alt) {
                unsigned ep,count=random_word(&state)%3u;
                alternate(&b,(uint8_t)i,(uint8_t)alt,(uint8_t)count);
                opaque_record(&b,0x24,3);
                for(ep=0;ep<count;++ep) {
                    endpoint(&b,(uint8_t)(0x81u+i*2u+ep),2,64,0);
                    opaque_record(&b,0x25,2);
                }
            }
        }
        ++random_cases;parse_blob(&b,NTWU_FULL_SPEED,NTWU_OK);
    }
}
int main(void)
{
    device_cases();topology_cases();endpoint_cases();opaque_and_limits();
    invalid_and_overlap();mutation_and_generation();
    CHECK(calls==device_ok+config_ok+rejected);
    printf("{\"status\":\"PASS\",\"assertions\":%" PRIu64
           ",\"parse_calls\":%" PRIu64 ",\"device_successes\":%" PRIu64
           ",\"configuration_successes\":%" PRIu64 ",\"rejections\":%" PRIu64
           ",\"mutation_cases\":%" PRIu64 ",\"random_cases\":%" PRIu64
           ",\"truncation_cases\":%" PRIu64 "}\n",
           assertions,calls,device_ok,config_ok,rejected,mutations,random_cases,truncations);
    return 0;
}
