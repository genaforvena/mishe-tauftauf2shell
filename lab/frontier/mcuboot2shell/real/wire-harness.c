/*
 * mcuboot2shell W2: loopback wire-to-sink experiment.
 *
 * A live host process listens on 127.0.0.1 and accepts one 32-byte MCUboot
 * image header per connection. The real pinned decrypt_region_inplace() and
 * the real AES-CTR decryptor run on the wire-supplied header. This is NOT an
 * MCUboot serial/SMP parser and NOT a real encrypted image: Grooming and
 * flash contents are the same documented lab shims as real-harness.c.
 */
#define main harness_main
#include "real-harness.c"
#undef main

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static int read_exact(int fd, uint8_t *p, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t k = recv(fd, p + got, n - got, 0);
        if (k <= 0) { return -1; }
        got += (size_t)k;
    }
    return 0;
}

int main(void)
{
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    if (srv < 0) { return 2; }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(srv, 4) != 0) {
        return 2;
    }
    getsockname(srv, (struct sockaddr *)&addr, &alen);
    printf("PORT=%u\n", (unsigned)ntohs(addr.sin_port));
    fflush(stdout);
    for (int conn = 0; conn < 1; conn++) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) { break; }
        struct image_header hdr;
        struct flash_area fa;
        struct enc_key_data enc;
        static uint8_t ct[8192];
        static uint8_t zeros[8192];
        uint32_t off = SECT_SZ;
        uint32_t idx, dec_off, dec_len;

        if (read_exact(fd, (uint8_t *)&hdr, sizeof(hdr)) != 0) {
            printf("WIRE conn=%d REJECT short-header\n", conn);
            close(fd);

        }
        printf("WIRE conn=%d magic=%08x hdr_size=%u flags=%08x img_size=%u\n",
               conn, hdr.ih_magic, hdr.ih_hdr_size, hdr.ih_flags, hdr.ih_img_size);
        if (!IS_ENCRYPTED(&hdr)) {
            printf("WIRE conn=%d REJECT not-encrypted\n", conn);
            close(fd);
            continue;
        }
        if (hdr.ih_hdr_size >= off && hdr.ih_hdr_size < 2u * off) {
            idx = hdr.ih_hdr_size; dec_off = off; dec_len = 2u * off - idx;
        } else if (hdr.ih_hdr_size < off) {
            idx = 0; dec_off = off - hdr.ih_hdr_size; dec_len = off;
        } else {
            printf("WIRE conn=%d REJECT hdr_size-out-of-range\n", conn);
            close(fd);
            continue;
        }
        if (dec_len > sizeof(ct)) { dec_len = sizeof(ct); }

        memset(&fa, 0, sizeof(fa));
        memset(g_image, 0xcc, sizeof(g_image));
        for (uint32_t i = 0; i < sizeof(g_key); i++) { g_key[i] = (uint8_t)i; }
        fa.fa_id = 0; fa.fa_off = 0; fa.fa_size = FLASH_SZ;
        boot_enc_init(&enc);
        if (boot_enc_set_key(&enc, g_key) != 0) { printf("KEY FAIL\n"); close(fd); continue; }

        memset(g_groom_pt, 0, sizeof(g_groom_pt));
        memcpy(g_groom_pt, "MISHE-REAL-AES!!", 16);
        memset(zeros, 0, dec_len);
        memset(ct, 0, sizeof(ct));
        boot_enc_encrypt(&enc, dec_off, dec_len, 0, ct);
        for (uint32_t i = 0; i < dec_len; i++) { g_groom_ct[i] = ct[i] ^ g_groom_pt[i % 16]; }
        g_groom_len = dec_len;
        g_idx = idx;
        g_hsoc = hdr.ih_hdr_size;
        g_readback_len = 0;

        g_buf_base = NULL;
        /* No stack grooming here: writing past the 4096-byte VLA in this
         * server frame corrupts its own locals. The wire result is the
         * OOB destination logged by the wrapper, not chosen plaintext. */
        g_groom = 0;
        int rc = harness_decrypt_region(&enc, &fa, &hdr, off, SECT_SZ);
        printf("WIRE conn=%d RESULT rc=%d idx=%u dec_off=%u dec_len=%u readback=",
               conn, rc, idx, dec_off, dec_len);
        if (g_readback_len) { hex(g_readback, g_readback_len < 16 ? g_readback_len : 16); }
        else { printf("(none)"); }
        printf(" expected=MISHE-REAL-AES!!\n");
        fflush(stdout);
        boot_enc_drop(&enc);
        close(fd);
    }
    close(srv);
    return 0;
}
