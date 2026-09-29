/* SPDX-License-Identifier: GPL-2.0-only */
/* Original bounded USB2 descriptor parser. No controller or transfer code. */
#include "ntwu_usb.h"

static struct ntwu_result result(int32_t status, size_t offset)
{
    struct ntwu_result value;
    value.status = status;
    value.offset = (uint32_t)offset;
    return value;
}

/* Volatile byte accesses keep compiler-generated libc calls out of this core. */
static void clear_bytes(void *destination, size_t count)
{
    volatile uint8_t *p = (volatile uint8_t *)destination;
    while (count != 0u) { *p++ = 0u; --count; }
}

static void publish_bytes(void *destination, const void *source, size_t count)
{
    volatile uint8_t *d = (volatile uint8_t *)destination;
    const volatile uint8_t *s = (const volatile uint8_t *)source;
    while (count != 0u) { *d++ = *s++; --count; }
}

static int valid_storage(const void *input, size_t length,
                         const void *output, size_t output_size)
{
    uintptr_t a, b;
    if (input == NULL || output == NULL) return 0;
    a = (uintptr_t)input;
    b = (uintptr_t)output;
    if (length > UINTPTR_MAX - a || output_size > UINTPTR_MAX - b) return 0;
    return !(a < b + output_size && b < a + length);
}

static int32_t speed_status(enum ntwu_speed speed)
{
    if (speed == NTWU_LOW_SPEED || speed == NTWU_FULL_SPEED ||
        speed == NTWU_HIGH_SPEED) return NTWU_OK;
    return speed == NTWU_SUPER_SPEED ? NTWU_UNSUPPORTED : NTWU_INVALID;
}

static uint16_t little16(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static int valid_bcd(uint16_t value)
{
    unsigned int i;
    for (i = 0u; i < 4u; ++i) {
        if ((value & 15u) > 9u) return 0;
        value = (uint16_t)(value >> 4);
    }
    return 1;
}

static int full_packet(uint16_t packet)
{
    return packet == 8u || packet == 16u || packet == 32u || packet == 64u;
}

struct ntwu_result ntwu_parse_device(const void *bytes, size_t length,
                                    enum ntwu_speed speed, struct ntwu_device *output)
{
    const uint8_t *data = (const uint8_t *)bytes;
    struct ntwu_device parsed;
    uint16_t version, release;
    uint8_t packet;
    if (length > NTWU_MAX_BLOB) return result(NTWU_LIMIT, 0u);
    if (!valid_storage(bytes, length, output, sizeof(*output)))
        return result(NTWU_INVALID, 0u);
    if (speed_status(speed) != NTWU_OK) return result(speed_status(speed), 0u);
    if (length < 2u) return result(NTWU_TRUNCATED, length);
    if (data[0] < 18u) return result(NTWU_MALFORMED, 0u);
    if (data[0] > length) return result(NTWU_TRUNCATED, length);
    if (data[0] != 18u) return result(NTWU_UNSUPPORTED, 0u);
    if (data[1] != 1u) return result(NTWU_MALFORMED, 1u);
    if (length != 18u) return result(NTWU_MALFORMED, 18u);
    version = little16(data + 2u);
    release = little16(data + 12u);
    if (!valid_bcd(version)) return result(NTWU_MALFORMED, 2u);
    if (!valid_bcd(release)) return result(NTWU_MALFORMED, 12u);
    if (version != 0x0100u && version != 0x0110u && version != 0x0200u)
        return result(NTWU_UNSUPPORTED, 2u);
    if (speed == NTWU_HIGH_SPEED && version != 0x0200u)
        return result(NTWU_INCONSISTENT, 2u);
    if (data[4] == 0u && data[5] != 0u) return result(NTWU_MALFORMED, 5u);
    if (data[4] == 0u && data[6] != 0u) return result(NTWU_UNSUPPORTED, 6u);
    packet = data[7];
    if ((speed == NTWU_LOW_SPEED && packet != 8u) ||
        (speed == NTWU_HIGH_SPEED && packet != 64u) ||
        (speed == NTWU_FULL_SPEED && !full_packet(packet)))
        return result(NTWU_MALFORMED, 7u);
    if (data[17] == 0u) return result(NTWU_MALFORMED, 17u);
    clear_bytes(&parsed, sizeof(parsed));
    parsed.struct_size = sizeof(parsed);
    parsed.abi_version = NTWU_ABI_VERSION;
    parsed.usb_bcd = version;
    parsed.vendor_id = little16(data + 8u);
    parsed.product_id = little16(data + 10u);
    parsed.device_bcd = release;
    parsed.device_class = data[4];
    parsed.subclass = data[5];
    parsed.protocol = data[6];
    parsed.control_packet_bytes = packet;
    parsed.manufacturer_string = data[14];
    parsed.product_string = data[15];
    parsed.serial_string = data[16];
    parsed.configuration_count = data[17];
    parsed.speed = (uint8_t)speed;
    publish_bytes(output, &parsed, sizeof(parsed));
    return result(NTWU_OK, 0u);
}

static int32_t endpoint_fields(const uint8_t *data, enum ntwu_speed speed,
                              uint8_t alternate)
{
    uint16_t packet = little16(data + 4u);
    uint8_t type = (uint8_t)(data[3] & 3u);
    if ((data[2] & 0x70u) != 0u || (data[2] & 15u) == 0u)
        return NTWU_MALFORMED;
    if ((data[3] & 0xfcu) != 0u || (packet & 0xf800u) != 0u)
        return NTWU_UNSUPPORTED;
    if (type == 2u) {
        if (speed == NTWU_LOW_SPEED) return NTWU_UNSUPPORTED;
        if ((speed == NTWU_FULL_SPEED && !full_packet(packet)) ||
            (speed == NTWU_HIGH_SPEED && packet != 512u)) return NTWU_MALFORMED;
    } else if (type == 3u) {
        /* USB2 5.7.3 permits zero payload; this is not an operational pipe. */
        uint16_t maximum = speed == NTWU_LOW_SPEED ? 8u :
                           speed == NTWU_FULL_SPEED ? 64u : 1024u;
        if (packet > maximum || data[6] == 0u) return NTWU_MALFORMED;
        if (speed == NTWU_HIGH_SPEED) {
            if (data[6] > 16u) return NTWU_MALFORMED;
            if (alternate == 0u && packet > 64u) return NTWU_UNSUPPORTED;
        }
    } else return NTWU_UNSUPPORTED;
    return NTWU_OK;
}

struct ntwu_result ntwu_parse_configuration(const void *bytes, size_t length,
                                           enum ntwu_speed speed,
                                           struct ntwu_configuration *output)
{
    const uint8_t *data = (const uint8_t *)bytes;
    struct ntwu_configuration parsed;
    uint8_t endpoint_owner[32];
    uint32_t seen_interfaces = 0u, default_interfaces = 0u, current_endpoints = 0u;
    uint16_t current = NTWU_NO_INDEX, preceding_endpoint = NTWU_NO_INDEX;
    uint16_t total;
    size_t offset;
    if (length > NTWU_MAX_BLOB) return result(NTWU_LIMIT, 0u);
    if (!valid_storage(bytes, length, output, sizeof(*output)))
        return result(NTWU_INVALID, 0u);
    if (speed_status(speed) != NTWU_OK) return result(speed_status(speed), 0u);
    if (length < 2u) return result(NTWU_TRUNCATED, length);
    if (data[0] < 9u) return result(NTWU_MALFORMED, 0u);
    if (data[0] > length) return result(NTWU_TRUNCATED, length);
    if (data[0] != 9u) return result(NTWU_UNSUPPORTED, 0u);
    if (data[1] != 2u) return result(NTWU_MALFORMED, 1u);
    total = little16(data + 2u);
    if (total < 9u) return result(NTWU_MALFORMED, 2u);
    if (total > length) return result(NTWU_TRUNCATED, length);
    if (total != length) return result(NTWU_MALFORMED, total);
    if (data[4] == 0u) return result(NTWU_MALFORMED, 4u);
    if (data[4] > NTWU_MAX_INTERFACES) return result(NTWU_LIMIT, 4u);
    if (data[5] == 0u) return result(NTWU_MALFORMED, 5u);
    if ((data[7] & 0x80u) == 0u) return result(NTWU_MALFORMED, 7u);
    if ((data[7] & 0x1fu) != 0u) return result(NTWU_UNSUPPORTED, 7u);
    if (data[8] > 250u) return result(NTWU_MALFORMED, 8u);
    clear_bytes(&parsed, sizeof(parsed));
    clear_bytes(endpoint_owner, sizeof(endpoint_owner));
    parsed.struct_size = sizeof(parsed);
    parsed.abi_version = NTWU_ABI_VERSION;
    parsed.total_length = total;
    parsed.configuration_value = data[5];
    parsed.interface_count = data[4];
    parsed.max_power_ma = (uint16_t)((uint16_t)data[8] * 2u);
    parsed.attributes = data[7];
    parsed.string_index = data[6];
    parsed.speed = (uint8_t)speed;
    offset = 9u;
    while (offset < length) {
        const uint8_t *record = data + offset;
        uint8_t amount, type;
        if (length - offset < 2u) return result(NTWU_TRUNCATED, offset);
        amount = record[0];
        type = record[1];
        if (amount < 2u) return result(NTWU_MALFORMED, offset);
        if ((size_t)amount > length - offset) return result(NTWU_TRUNCATED, offset);
        if (type == 4u) {
            struct ntwu_interface *interface;
            uint16_t i;
            if (amount < 9u) return result(NTWU_MALFORMED, offset);
            if (amount != 9u) return result(NTWU_UNSUPPORTED, offset);
            if (current != NTWU_NO_INDEX &&
                parsed.alternates[current].endpoint_count !=
                parsed.alternates[current].declared_endpoints)
                return result(NTWU_INCONSISTENT, offset);
            if (parsed.alternate_count == NTWU_MAX_ALTERNATES)
                return result(NTWU_LIMIT, offset);
            if (record[2] >= parsed.interface_count || record[4] > 30u)
                return result(NTWU_MALFORMED, offset);
            if (record[5] == 0u) return result(NTWU_UNSUPPORTED, offset);
            for (i = 0u; i < parsed.alternate_count; ++i)
                if (parsed.alternates[i].number == record[2] &&
                    parsed.alternates[i].alternate == record[3])
                    return result(NTWU_DUPLICATE, offset);
            current = parsed.alternate_count++;
            interface = &parsed.alternates[current];
            interface->offset = (uint16_t)offset;
            interface->first_endpoint = parsed.endpoint_count;
            interface->number = record[2];
            interface->alternate = record[3];
            interface->declared_endpoints = record[4];
            interface->class_code = record[5];
            interface->subclass = record[6];
            interface->protocol = record[7];
            interface->string_index = record[8];
            seen_interfaces |= UINT32_C(1) << record[2];
            if (record[3] == 0u) default_interfaces |= UINT32_C(1) << record[2];
            current_endpoints = 0u;
            preceding_endpoint = NTWU_NO_INDEX;
        } else if (type == 5u) {
            struct ntwu_interface *interface;
            struct ntwu_endpoint *endpoint;
            uint8_t key;
            uint32_t mask;
            int32_t status;
            if (amount < 7u) return result(NTWU_MALFORMED, offset);
            if (amount != 7u) return result(NTWU_UNSUPPORTED, offset);
            if (current == NTWU_NO_INDEX) return result(NTWU_INCONSISTENT, offset);
            if (parsed.endpoint_count == NTWU_MAX_ENDPOINTS)
                return result(NTWU_LIMIT, offset);
            interface = &parsed.alternates[current];
            status = endpoint_fields(record, speed, interface->alternate);
            if (status != NTWU_OK) return result(status, offset);
            key = (uint8_t)((record[2] & 15u) | ((record[2] & 0x80u) >> 3));
            mask = UINT32_C(1) << key;
            if ((current_endpoints & mask) != 0u ||
                (endpoint_owner[key] != 0u &&
                 endpoint_owner[key] != (uint8_t)(interface->number + 1u)))
                return result(NTWU_DUPLICATE, offset);
            if (interface->endpoint_count == interface->declared_endpoints)
                return result(NTWU_INCONSISTENT, offset);
            current_endpoints |= mask;
            endpoint_owner[key] = (uint8_t)(interface->number + 1u);
            preceding_endpoint = parsed.endpoint_count++;
            endpoint = &parsed.endpoints[preceding_endpoint];
            endpoint->offset = (uint16_t)offset;
            endpoint->max_packet_bytes = little16(record + 4u);
            endpoint->alternate_index = current;
            endpoint->address = record[2];
            endpoint->transfer_type = (uint8_t)(record[3] & 3u);
            endpoint->interval = record[6];
            endpoint->transactions = 1u;
            ++interface->endpoint_count;
        } else if (type == 11u || type >= 0x20u) {
            struct ntwu_opaque *opaque;
            if (type == 0x30u || type == 0x31u) return result(NTWU_UNSUPPORTED, offset);
            if (parsed.opaque_count == NTWU_MAX_OPAQUE) return result(NTWU_LIMIT, offset);
            opaque = &parsed.opaque[parsed.opaque_count++];
            opaque->offset = (uint16_t)offset;
            opaque->length = amount;
            opaque->type = type;
            opaque->preceding_alternate = current;
            opaque->preceding_endpoint = preceding_endpoint;
        } else return result(NTWU_UNSUPPORTED, offset);
        offset += amount;
    }
    if (current == NTWU_NO_INDEX ||
        parsed.alternates[current].endpoint_count != parsed.alternates[current].declared_endpoints ||
        seen_interfaces != (UINT32_C(1) << parsed.interface_count) - 1u ||
        default_interfaces != seen_interfaces)
        return result(NTWU_INCONSISTENT, length);
    if (speed == NTWU_LOW_SPEED) {
        uint16_t simultaneous = 0u;
        uint8_t number;
        /* Alternate selections of distinct interfaces can coexist. */
        for (number = 0u; number < parsed.interface_count; ++number) {
            uint8_t maximum = 0u;
            uint16_t i;
            for (i = 0u; i < parsed.alternate_count; ++i)
                if (parsed.alternates[i].number == number &&
                    parsed.alternates[i].endpoint_count > maximum)
                    maximum = parsed.alternates[i].endpoint_count;
            simultaneous = (uint16_t)(simultaneous + maximum);
        }
        if (simultaneous > 2u) return result(NTWU_INCONSISTENT, length);
    }
    publish_bytes(output, &parsed, sizeof(parsed));
    return result(NTWU_OK, 0u);
}
