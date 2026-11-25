/* Port/backend stand-ins for the native MCUboot SMP build. All cryptographic
 * and protocol code is the verbatim pinned upstream source; this file only
 * supplies flash, OS, CRC and base64 the host does not have. */
#define GROOM_CT_SZ 8192u
#include "host-shims.h"
#include <bootutil/image.h>
#include <bootutil/bootutil.h>
#include <bootutil_priv.h>
#include <time.h>
#include <stdio.h>

extern uint8_t g_image[];
extern uint32_t g_idx;
extern uint32_t g_groom_len;
extern int g_groom;
extern uint8_t g_groom_ct[];
extern uint8_t *g_buf_base;

#define FLASH_SZ 32768u
#define SECT_SZ 4096u

static struct flash_area g_fa = { .fa_id = 0, .fa_off = 0, .fa_size = FLASH_SZ };

int flash_area_open(uint8_t id, const struct flash_area **fa)
{
    (void)id;
    printf("SHIM flash_area_open id=%u\n", id);
    if (fa) { *fa = &g_fa; }
    return 0;
}
void flash_area_close(const struct flash_area *fa) { (void)fa; }
int flash_area_read(const struct flash_area *fa, uint32_t off, void *dst, uint32_t len)
{
    (void)fa;
    if (off > FLASH_SZ || len > FLASH_SZ - off) { return -1; }
    memcpy(dst, &g_image[off], len);
    g_buf_base = (uint8_t *)dst;
    if (off == 0 && len >= 32) {
        g_idx = (uint32_t)((uint8_t *)dst)[8] |
                ((uint32_t)((uint8_t *)dst)[9] << 8);
    }
#if defined(M2S_NO_GROOM) || defined(M2S_FIXED_CONTROL)
    if (0) {
#elif defined(M2S_SOCKET_UART)
    if (g_groom && off == SECT_SZ && g_idx > SECT_SZ && len >= 512 && g_idx < GROOM_CT_SZ) {
#else
    if (g_groom && len >= 512 && g_idx < GROOM_CT_SZ) {
#endif
        uint32_t glen = g_groom_len;
        if (g_idx + glen > GROOM_CT_SZ) { glen = GROOM_CT_SZ - g_idx; }
        if (glen > len) { glen = len; }
        memcpy(g_buf_base + g_idx, g_groom_ct, glen);
    }
    return 0;
}
int flash_area_write(const struct flash_area *fa, uint32_t off, const void *src, uint32_t len)
{
    (void)fa;
    if (off > FLASH_SZ || len > FLASH_SZ - off) { return -1; }
    memcpy(&g_image[off], src, len);
    printf("SHIM flash_area_write off=%u len=%u first=%02x\n", off, len, len ? ((const uint8_t *)src)[0] : 0);
    return 0;
}
int flash_area_erase(const struct flash_area *fa, uint32_t off, uint32_t len)
{
    (void)fa;
    printf("SHIM flash_area_erase off=%u len=%u\n", off, len);
    if (off > FLASH_SZ || len > FLASH_SZ - off) { return -1; }
    memset(&g_image[off], 0xff, len);
    return 0;
}
int flash_area_get_sector(const struct flash_area *fa, uint32_t off, struct flash_sector *s)
{
    (void)fa;
    s->fs_off = off & ~(SECT_SZ - 1u);
    s->fs_size = SECT_SZ;
    return 0;
}
int flash_area_get_sectors(int fa_id, uint32_t *count, struct flash_sector *sectors)
{
    (void)fa_id;
    if (*count < 1) { return -1; }
    sectors[0].fs_off = 0;
    sectors[0].fs_size = SECT_SZ;
    *count = 1;
    return 0;
}
uint32_t flash_area_align(const struct flash_area *fa) { (void)fa; return 8; }
uint8_t flash_area_erased_val(const struct flash_area *fa) { (void)fa; return 0xff; }
int flash_area_id_from_multi_image_slot(int image_index, int slot)
{
    (void)image_index; (void)slot; return 0;
}
int flash_area_id_from_direct_image(int image_id) { return image_id; }
int boot_erase_region(const struct flash_area *fa, uint32_t off, uint32_t sz, bool backwards)
{
    (void)backwards; return flash_area_erase(fa, off, sz);
}
int boot_scramble_region(const struct flash_area *fa, uint32_t off, uint32_t sz, bool backwards)
{
    (void)backwards; return flash_area_erase(fa, off, sz);
}
uint32_t boot_status_off(const struct flash_area *fa) { (void)fa; return FLASH_SZ - 128; }
uint32_t boot_swap_info_off(const struct flash_area *fa) { (void)fa; return FLASH_SZ - 256; }
void *os_malloc(size_t size) { return malloc(size); }
void os_free(void *p) { free(p); }
uint32_t k_uptime_get_ms_32(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
    return (uint32_t)ts.tv_sec * 1000u + (uint32_t)ts.tv_nsec / 1000000u;
}
uint32_t os_uptime_get_ms_32(void) { return k_uptime_get_ms_32(); }
uint32_t k_uptime_get_32(void) { return k_uptime_get_ms_32(); }
void mcuboot_watchdog_feed(void) { }

uint16_t crc16_ccitt(uint16_t crc, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len--) {
        crc ^= (uint16_t)(*p++ << 8);
        for (int i = 0; i < 8; i++) {
            crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u) : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') { return c - 'A'; }
    if (c >= 'a' && c <= 'z') { return c - 'a' + 26; }
    if (c >= '0' && c <= '9') { return c - '0' + 52; }
    if (c == '+') { return 62; }
    if (c == '/') { return 63; }
    return -1;
}
int base64_encode(const char *src, int len, char *dst, int nullterm)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int out = 0;
    for (int i = 0; i < len; i += 3) {
        uint32_t v = ((uint32_t)(uint8_t)src[i] << 16);
        if (i + 1 < len) { v |= (uint32_t)(uint8_t)src[i + 1] << 8; }
        if (i + 2 < len) { v |= (uint32_t)(uint8_t)src[i + 2]; }
        dst[out++] = tbl[(v >> 18) & 63];
        dst[out++] = tbl[(v >> 12) & 63];
        dst[out++] = (i + 1 < len) ? tbl[(v >> 6) & 63] : '=';
        dst[out++] = (i + 2 < len) ? tbl[v & 63] : '=';
    }
    if (nullterm) { dst[out] = 0; }
    return out;
}
int base64_decode(const char *src, char *dst)
{
    int out = 0;
    size_t n = strlen(src);
    for (size_t i = 0; i < n; i += 4) {
        int a = b64val(src[i]);
        int b = (i + 1 < n) ? b64val(src[i + 1]) : -1;
        int c = (i + 2 < n && src[i + 2] != '=') ? b64val(src[i + 2]) : 0;
        int d = (i + 3 < n && src[i + 3] != '=') ? b64val(src[i + 3]) : 0;
        if (a < 0 || b < 0) { return -1; }
        uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        dst[out++] = (char)(v >> 16);
        if (i + 2 < n && src[i + 2] != '=') { dst[out++] = (char)(v >> 8); }
        if (i + 3 < n && src[i + 3] != '=') { dst[out++] = (char)v; }
    }
    return 0;
}

struct boot_loader_state *boot_get_loader_state(void)
{
    static struct boot_loader_state state;
    return &state;
}
int boot_open_all_flash_areas(struct boot_loader_state *state) { (void)state; return 0; }
void boot_close_all_flash_areas(struct boot_loader_state *state) { (void)state; }
int boot_read_sectors(struct boot_loader_state *state, struct boot_sector_buffer *sectors)
{
    (void)state; (void)sectors; return 0;
}
void os_cputime_delay_usecs(uint32_t usecs) { (void)usecs; }
void hal_system_reset(void) { }

/* Native host key loading: the real encrypted.c boot_enc_load() requires a
 * wrapped-key TLV in flash and a real KDF; this lab shim supplies the same
 * 16-byte AES key W1-W3 used in the pinned decryptor directly. The
 * vulnerable decrypt_region_inplace() body and real boot_enc_decrypt()
 * remain verbatim upstream code. */
extern uint8_t g_key[];
int boot_enc_load(struct boot_loader_state *state, int slot,
                  const struct image_header *hdr, const struct flash_area *fap,
                  struct boot_status *bs)
{
    (void)state; (void)hdr; (void)fap;
    memcpy(bs->enckey[slot], g_key, BOOT_ENC_KEY_SIZE);
    return 0;
}
