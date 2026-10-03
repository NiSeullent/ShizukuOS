/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_INSTALLER_CAPACITY_H
#define SHZ_NATIVE_INSTALLER_CAPACITY_H
/* Wire ceiling only: this does not allocate memory or grant source authority.
 * Private compiler limits must come from measured, independently admitted
 * producer inputs. Public profiles retain their original allocation limits. */
#define SHZ_NATIVE_SOURCE_DEFAULT_BYTES (256ull<<20)
#define SHZ_NATIVE_SOURCE_PROTOCOL_BYTES (512ull<<20)
#define SHZ_NATIVE_ARCHIVE_DEFAULT_BYTES (64ull<<20)
#define SHZ_NATIVE_RAM_DEFAULT_BYTES (256ull<<20)
#define SHZ_NATIVE_BOOT_MAPPING_BYTES (1024ull<<20)
#if defined(SHZ_PRIVATE_NATIVE_SOURCE_BYTES) || defined(SHZ_PRIVATE_NATIVE_ARCHIVE_BYTES) || defined(SHZ_PRIVATE_NATIVE_RAM_BYTES)
#if !defined(SHZ_PRIVATE_NATIVE_SOURCE_BYTES) || !defined(SHZ_PRIVATE_NATIVE_ARCHIVE_BYTES) || !defined(SHZ_PRIVATE_NATIVE_RAM_BYTES)
#error "All measured private compiler budget fields are required"
#endif
#if !defined(SHZ_PRIVATE_NATIVE_EFI_LOAD) && !(defined(SHZ_STANDALONE) && defined(SHZ_NATIVE_INSTALLER_RELEASE))
#error "Private budgets belong to the private installer loader/kernel only"
#endif
#if SHZ_PRIVATE_NATIVE_SOURCE_BYTES < SHZ_NATIVE_SOURCE_DEFAULT_BYTES || SHZ_PRIVATE_NATIVE_SOURCE_BYTES > SHZ_NATIVE_SOURCE_PROTOCOL_BYTES
#error "Private source budget exceeds the bounded wire protocol"
#endif
#if SHZ_PRIVATE_NATIVE_ARCHIVE_BYTES < SHZ_NATIVE_ARCHIVE_DEFAULT_BYTES || SHZ_PRIVATE_NATIVE_ARCHIVE_BYTES + (32ull<<20) > SHZ_PRIVATE_NATIVE_RAM_BYTES
#error "Private archive budget does not fit the measured RAM profile"
#endif
#if SHZ_PRIVATE_NATIVE_RAM_BYTES < SHZ_NATIVE_RAM_DEFAULT_BYTES || SHZ_PRIVATE_NATIVE_RAM_BYTES > SHZ_NATIVE_BOOT_MAPPING_BYTES || (SHZ_PRIVATE_NATIVE_RAM_BYTES & ((2ull<<20)-1))
#error "Private RAM must fit the actual 1GiB boot mapping and 2MiB pages"
#endif
#define SHZ_NATIVE_KERNEL_SOURCE_MAX SHZ_PRIVATE_NATIVE_SOURCE_BYTES
#define SHZ_NATIVE_INSTALLER_ARCHIVE_MAX SHZ_PRIVATE_NATIVE_ARCHIVE_BYTES
#define SHZ_NATIVE_INSTALLER_RAM_MAX SHZ_PRIVATE_NATIVE_RAM_BYTES
#else
#define SHZ_NATIVE_KERNEL_SOURCE_MAX SHZ_NATIVE_SOURCE_DEFAULT_BYTES
#define SHZ_NATIVE_INSTALLER_ARCHIVE_MAX SHZ_NATIVE_ARCHIVE_DEFAULT_BYTES
#define SHZ_NATIVE_INSTALLER_RAM_MAX SHZ_NATIVE_RAM_DEFAULT_BYTES
#endif
#endif
