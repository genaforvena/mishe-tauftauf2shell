/* Host shims for a native build of the verbatim MCUboot boot_serial.c.
 * No MCUboot source is edited here: each replacement is an OS/port backend
 * the Zephyr/Mynewt build supplies from its own tree. */
#ifndef M2SHELL_HOST_SHIMS_H
#define M2SHELL_HOST_SHIMS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* MCUboot's bootutil_log.h already supplies no-op macros without
 * MCUBOOT_HAVE_LOGGING; do not redefine them here. */

/* flash_map_backend.h declares the flash API and struct flash_area. */
#include <flash_map_backend/flash_map_backend.h>

uint16_t crc16_ccitt(uint16_t crc, const void *buf, size_t len);
int base64_decode(const char *src, char *dst);
int base64_encode(const char *src, int len, char *dst, int nullterm);

struct flash_sector;
int flash_area_open(uint8_t id, const struct flash_area **fa);
void flash_area_close(const struct flash_area *fa);
int flash_area_read(const struct flash_area *fa, uint32_t off, void *dst, uint32_t len);
int flash_area_write(const struct flash_area *fa, uint32_t off, const void *src, uint32_t len);
int flash_area_erase(const struct flash_area *fa, uint32_t off, uint32_t len);
int flash_area_get_sector(const struct flash_area *fa, uint32_t off, struct flash_sector *s);
int flash_area_get_sectors(int fa_id, uint32_t *count, struct flash_sector *sectors);
uint32_t flash_area_align(const struct flash_area *fa);
uint8_t flash_area_erased_val(const struct flash_area *fa);
int flash_area_id_from_multi_image_slot(int image_index, int slot);
int flash_area_id_from_direct_image(int image_id);
int boot_erase_region(const struct flash_area *fa, uint32_t off, uint32_t sz, bool backwards);
int boot_scramble_region(const struct flash_area *fa, uint32_t off, uint32_t sz, bool backwards);
uint32_t boot_status_off(const struct flash_area *fa);
uint32_t boot_swap_info_off(const struct flash_area *fa);
void *os_malloc(size_t size);
void os_free(void *p);
uint32_t os_uptime_get_ms_32(void);
uint32_t k_uptime_get_ms_32(void);
uint32_t k_uptime_get_32(void);
void mcuboot_watchdog_feed(void);
void os_cputime_delay_usecs(uint32_t usecs);
void hal_system_reset(void);

#define MCUBOOT_CPU_IDLE() do { } while (0)
#endif
