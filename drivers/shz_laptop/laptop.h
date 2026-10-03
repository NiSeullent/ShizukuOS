/* SPDX-License-Identifier: GPL-2.0-only -- independently authored protocols */
#ifndef SHZ_LAPTOP_H
#define SHZ_LAPTOP_H
#include "../common/device.h"
#define SHZ_POLL_LIMIT 100000u
#define SHZ_TABLE_MAX 4096u
struct shz_gas { uint8_t space, bits, offset, access; uint64_t address; };
struct shz_fixed {
    struct shz_gas event_a,event_b,control_a,control_b,reset;
    uint32_t flags,smi_command; uint16_t sci;
    uint8_t enable,disable,reset_value;
};
struct shz_ec_table {
    struct shz_gas control,data; uint32_t uid; uint8_t gpe; char path[128];
};
/* Pure parsers; entire declared table must be present and checksummed. Output
 * remains unchanged on failure. HW-reduced ACPI and exotic GAS are unsupported. */
int shz_parse_fadt(const void *,size_t,struct shz_fixed *);
int shz_parse_ecdt(const void *,size_t,struct shz_ec_table *);
struct shz_register_ops {
    void *context;
    int (*validate)(void *,uint64_t owner,uint64_t generation,
                    const struct shz_gas *,unsigned bytes,int write);
    int (*read)(void *,const struct shz_gas *,unsigned bytes,uint32_t *);
    int (*write)(void *,const struct shz_gas *,unsigned bytes,uint32_t);
    uint64_t (*now_us)(void *);
    void (*relax)(void *);
};
struct shz_fixed_power {
    struct shz_fixed table; struct shz_register_ops ops;
    uint64_t owner,generation; uint32_t timeout_us;
};
int shz_fixed_events(struct shz_fixed_power *,uint16_t *active);
/* Masked W1C writes only. No sleep command is generated from guessed AML. */
int shz_fixed_ack(struct shz_fixed_power *,uint16_t events);
int shz_fixed_enable(struct shz_fixed_power *);
int shz_fixed_reset(struct shz_fixed_power *);
enum shz_ec_state { SHZ_EC_EMPTY,SHZ_EC_READY,SHZ_EC_BUSY,SHZ_EC_POISONED,SHZ_EC_CLOSED };
struct shz_ec {
    struct shz_ec_table table; struct shz_register_ops ops;
    uint64_t owner,generation; uint32_t timeout_us,state;
    int last_error;
};
/* Only exclusively owned EC interfaces are supported. Shared SMI/OS EC needs
 * a real ACPI Global Lock provider; exclusive=0 fails before any I/O. */
int shz_ec_open(struct shz_ec *,const struct shz_ec_table *,
                const struct shz_register_ops *,uint64_t owner,uint64_t generation,
                uint32_t timeout_us,int exclusive);
int shz_ec_read(struct shz_ec *,uint8_t address,uint8_t *value);
int shz_ec_write(struct shz_ec *,uint8_t address,uint8_t value);
int shz_ec_query(struct shz_ec *,uint8_t *event);
int shz_ec_close(struct shz_ec *);
/* Recovery is a TRUSTED provider that resynchronizes hardware and drains any
 * response. It is not a force flag. Failure leaves ownership quarantined. */
int shz_ec_recover(struct shz_ec *,int (*recover)(void *),void *);

#define SHZ_HID_REPORT_MAX 512u
#define SHZ_HID_DESCRIPTOR_MAX 2048u
#define SHZ_HID_FIELDS 128u
#define SHZ_HID_REPORTS 16u
#define SHZ_HID_CONTACTS 5u
struct shz_hid_descriptor {
    uint16_t report_bytes,report_register,input_register,input_bytes;
    uint16_t output_register,output_bytes,command_register,data_register;
    uint16_t vendor,product,version;
};
struct shz_hid_field {
    uint16_t bit,page,usage; uint8_t size,report,group,flags;
    int32_t minimum,maximum;
};
struct shz_hid_report { uint16_t bits; uint8_t id; };
struct shz_hid_layout {
    struct shz_hid_field fields[SHZ_HID_FIELDS];
    struct shz_hid_report reports[SHZ_HID_REPORTS];
    uint16_t count; uint8_t report_count,numbered,touchpad,pointer;
};
struct shz_hid_value { uint16_t page,usage; uint8_t group,flags; int32_t value; };
struct shz_contact { int32_t x,y; uint16_t id; uint8_t active,has_x,has_y; };
struct shz_pointer {
    struct shz_contact contacts[SHZ_HID_CONTACTS];
    uint8_t count,buttons,relative;
};
int shz_hid_parse_descriptor(const uint8_t *,size_t,struct shz_hid_descriptor *);
int shz_hid_parse_report(const uint8_t *,size_t,struct shz_hid_layout *);
/* Payload excludes transport length, includes report ID when numbered. */
int shz_hid_decode(const struct shz_hid_layout *,const uint8_t *,size_t,
                    struct shz_hid_value *,size_t,size_t *count);
int shz_hid_pointer(const struct shz_hid_layout *,const uint8_t *,size_t,
                    struct shz_pointer *);
/* Shared HID class adapter for Win98 input sinks and native NTDRV consumers.
 * Caller serializes PnP/input and supplies verified descriptor calibration.
 * Absolute single-contact frames establish a baseline on contact changes;
 * multitouch/extra buttons are rejected rather than guessed as gestures.
 * emit is atomic: on failure it must publish no movement/buttons. */
struct shz_pointer_sink {
    void *context;
    int (*validate)(void *,uint64_t owner,uint64_t generation);
    int (*emit)(void *,int32_t x,int32_t y,uint8_t buttons);
};
struct shz_pointer_adapter {
    struct shz_pointer_sink sink;
    uint64_t owner,generation;
    uint32_t units_x,units_y;
    int32_t previous_x,previous_y;
    int64_t remainder_x,remainder_y;
    uint16_t contact;
    uint8_t bound,tracking;
};
int shz_pointer_adapter_bind(struct shz_pointer_adapter *,const struct shz_pointer_sink *,
                            uint64_t owner,uint64_t generation,uint32_t units_x,uint32_t units_y);
int shz_pointer_adapter_input(struct shz_pointer_adapter *,const struct shz_pointer *);
int shz_pointer_adapter_report(struct shz_pointer_adapter *,const struct shz_hid_layout *,
                              const uint8_t *,size_t);
int shz_pointer_adapter_close(struct shz_pointer_adapter *);
struct shz_i2c_ops {
    void *context;
    int (*validate)(void *,uint64_t owner,uint64_t generation,uint16_t address);
    /* Atomic write/repeated-START/read, or direct read when tx_bytes=0.
     * timeout is an elapsed-time ceiling imposed by the real controller owner.
     * On error the write may have happened. No detached I/O can target buffers.
     * QUARANTINED retains transport DMA and requires drain before reuse. */
    int (*transfer)(void *,uint16_t address,const uint8_t *,size_t tx_bytes,
                    uint8_t *,size_t rx_bytes,uint32_t timeout_us);
    int (*interrupt)(void *,int *asserted); /* normalized active-low level */
    int (*drain)(void *,uint32_t timeout_us); /* real controller DMA drain */
    uint64_t (*now_us)(void *);
    void (*relax)(void *);
};
enum shz_i2c_state { SHZ_I2C_EMPTY,SHZ_I2C_STARTING,SHZ_I2C_READY,
                    SHZ_I2C_STOPPING,SHZ_I2C_SUSPENDED,SHZ_I2C_CLOSED,SHZ_I2C_QUARANTINED };
struct shz_hidi2c {
    struct shz_i2c_ops ops; struct shz_hid_descriptor descriptor;
    struct shz_hid_layout layout;
    uint64_t owner,generation; uint32_t timeout_us,state;
    uint16_t address,descriptor_register; uint32_t command_known; int last_error;
    uint8_t buffer[SHZ_HID_DESCRIPTOR_MAX]; /* retained on transport quarantine */
};
int shz_hidi2c_open(struct shz_hidi2c *,const struct shz_i2c_ops *,
                    uint64_t owner,uint64_t generation,uint16_t address,
                    uint16_t descriptor_register,uint32_t timeout_us);
int shz_hidi2c_input(struct shz_hidi2c *,uint8_t *,size_t,size_t *bytes);
int shz_hidi2c_stop(struct shz_hidi2c *,int suspend);
int shz_hidi2c_resume(struct shz_hidi2c *);

enum shz_acpi_kind { SHZ_ACPI_INTEGER,SHZ_ACPI_STRING };
struct shz_acpi_value { uint64_t integer; uint32_t kind; };
struct shz_acpi_provider {
    void *context;
    int (*validate)(void *,uint64_t owner,uint64_t generation,uint64_t node);
    /* Real AML evaluator or an equivalently verified firmware provider. Must
     * enforce elapsed timeout and return exact typed package length. No guessed
     * EC offsets or application-supplied values are hardware evidence.
     * An absent optional namespace method returns SHZ_NOT_FOUND, distinct
     * from an unsupported evaluator or method implementation. */
    int (*evaluate)(void *,uint64_t node,const char method[5],
                    struct shz_acpi_value *,size_t,size_t *,uint32_t timeout_us);
    uint64_t owner,generation; uint32_t timeout_us;
};
struct shz_battery {
    uint32_t state,rate,remaining,voltage,full,unit;
    uint8_t present,percent,percent_known;
};
int shz_acpi_battery(const struct shz_acpi_provider *,uint64_t node,struct shz_battery *);
int shz_acpi_temperature(const struct shz_acpi_provider *,uint64_t node,int32_t *millidegrees_c);
int shz_acpi_lid(const struct shz_acpi_provider *,uint64_t node,int *open);
int shz_acpi_ac_power(const struct shz_acpi_provider *,uint64_t node,int *online);
/* Verified vendor binding supplies EC offset and scaling. No default offsets. */
struct shz_ec_sensor { uint8_t address; int32_t scale_milli,offset_milli,minimum,maximum; };
int shz_ec_sensor_read(struct shz_ec *,const struct shz_ec_sensor *,int32_t *value);
#endif
