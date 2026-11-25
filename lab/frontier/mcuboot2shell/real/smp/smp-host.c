/* Native host driver for the verbatim MCUboot boot_serial.c upload path.
 *
 * A loopback listener accepts one mcumgr SMP packet (raw framing):
 *   struct nmgr_hdr { op=WRITE, flags=0, len, group=1, seq=0, id=1 }
 *   followed by the CBOR upload map {"image":0,"data":<32-byte header>,"len":N,"off":0}.
 * The default build hands the packet verbatim to boot_serial_input(). The
 * M2S_SOCKET_UART build backs boot_uart_funcs with the socket and enters the
 * real boot_serial_start_inactivity() read/dispatch loop instead.
 *
 * This is a NATIVE host build, not Zephyr or a real MCU. All MCUboot protocol,
 * CBOR and encryption code is upstream source; flash, UART and OS are shims.
 */
#include "host-shims.h"
#include "../../../upstream-parent/boot/boot_serial/include/boot_serial/boot_serial.h"
#include "../../../upstream-parent/boot/boot_serial/src/boot_serial_priv.h"
#include "../../../upstream-parent/boot/bootutil/include/bootutil/image.h"
#include "../../../upstream-parent/boot/bootutil/include/bootutil/enc_key.h"
#include "../../../upstream-parent/boot/bootutil/src/bootutil_priv.h"
#include "../../../upstream-parent/boot/bootutil/include/bootutil/bootutil_log.h"
#include "../../../upstream-parent/boot/bootutil/include/bootutil/fault_injection_hardening.h"
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SECT_SZ 4096u
#define FLASH_SZ 32768u

fih_ret FIH_SUCCESS = 0;
fih_ret FIH_FAILURE = -1;
fih_ret FIH_NO_BOOTABLE_IMAGE = -2;
fih_ret FIH_BOOT_HOOK_REGULAR = -3;

uint8_t g_image[FLASH_SZ];
uint8_t g_key[BOOT_ENC_KEY_SIZE];
uint8_t g_groom_ct[8192];
uint8_t g_groom_pt[8192];
uint8_t g_readback[64];
uint32_t g_readback_len;
uint32_t g_hsoc;
uint32_t g_idx;
uint32_t g_groom_len;
int g_groom;
uint8_t *g_buf_base;
static struct enc_key_data g_enc;

void bootutil_wipe_memory(void *p, size_t n) { memset(p, 0, n); }
void boot_state_init(struct boot_loader_state *state) { (void)state; }
void boot_state_clear(struct boot_loader_state *state) { (void)state; }
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
    (void)fa; memcpy(hdr, &g_image[0], sizeof(*hdr)); return 0;
}
int boot_enc_retrieve_private_key(struct bootutil_key **k) { (void)k; return -1; }

int real_boot_enc_decrypt(struct enc_key_data *enc, uint32_t off, uint32_t sz,
                          uint32_t blk_off, uint8_t *buf);
int boot_enc_decrypt(struct enc_key_data *enc, uint32_t off, uint32_t sz,
                     uint32_t blk_off, uint8_t *buf)
{
    int delta = g_buf_base ? (int)(buf - g_buf_base) : -1;
    printf("REAL_DECRYPT off=%u len=%u blk_off=%u dst_delta=%d\n", off, sz, blk_off, delta);
    fflush(stdout);
    int rc = real_boot_enc_decrypt(enc, off, sz, blk_off, buf);
    if (g_groom && rc == 0 && delta >= 0) {
        g_readback_len = sz < sizeof(g_readback) ? sz : sizeof(g_readback);
        memcpy(g_readback, buf, g_readback_len);
        printf("READBACK delta=%d first16=", delta);
        for (uint32_t i = 0; i < 16 && i < g_readback_len; i++) { printf("%02x", g_readback[i]); }
        printf("\n");
        fflush(stdout);
    }
    return rc;
}

/* Verbatim pinned upstream function; build.sh selects parent or fixed pin. */
#ifndef M2S_ENC_INC
#define M2S_ENC_INC "encryption-host.inc"
#endif
#include M2S_ENC_INC

#ifdef M2S_SOCKET_UART
static int g_uart_fd = -1;
static unsigned g_uart_reads;
static unsigned g_uart_bytes;
static size_t g_uart_tx;

static int uart_read(char *str, int cnt, int *newline)
{
    ssize_t got = recv(g_uart_fd, str, (size_t)cnt, 0);
    *newline = 0;
    if (got <= 0) { return -1; }
    g_uart_reads++;
    g_uart_bytes += (unsigned)got;
    if (g_uart_reads <= 12) {
        printf("UART_READ requested=%d got=%zd\n", cnt, got);
        fflush(stdout);
    }
    return (int)got;
}

static void uart_write(const char *ptr, int cnt)
{
    size_t sent = 0;
    while (sent < (size_t)cnt) {
        ssize_t n = send(g_uart_fd, ptr + sent, (size_t)cnt - sent, MSG_NOSIGNAL);
        if (n <= 0) { break; }
        sent += (size_t)n;
    }
    g_uart_tx += sent;
    printf("UART_TX requested=%d sent=%zu\n", cnt, sent);
    fflush(stdout);
}
#else
static int uart_read(char *str, int cnt, int *newline) { (void)str; (void)cnt; (void)newline; return -1; }
static void uart_write(const char *ptr, int cnt) { (void)ptr; (void)cnt; }
#endif
 static const struct boot_uart_funcs uart = { uart_read, uart_write };

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
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(srv, 1) != 0) { return 2; }
    getsockname(srv, (struct sockaddr *)&addr, &alen);
    printf("PORT=%u\n", (unsigned)ntohs(addr.sin_port));
    fflush(stdout);
    int fd = accept(srv, NULL, NULL);
    if (fd < 0) { return 2; }

#ifdef M2S_SOCKET_UART
    /* Grooming plaintext is a separate lab condition, not SMP payload data. */
    if (read_exact(fd, g_groom_pt, 16) != 0) { return 2; }
    printf("SMP wire_plaintext=%.*s\n", 16, g_groom_pt);
    fflush(stdout);
    g_uart_fd = fd;
    struct timeval tv = { .tv_sec = 0, .tv_usec = 10000 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) { return 2; }
#else
    uint8_t pkt[8 + 16384];
     if (read_exact(fd, pkt, 8) != 0) { return 2; }
     size_t payload_len = ((size_t)pkt[2] << 8) | pkt[3];
     if (payload_len > 16384) { return 2; }
     if (read_exact(fd, pkt + 8, payload_len) != 0) { return 2; }
     printf("SMP op=%u len=%zu group=%u id=%u\n", pkt[0], payload_len,
            (pkt[4] << 8) | pkt[5], pkt[7]);
     fflush(stdout);
 
     if (read_exact(fd, g_groom_pt, 16) != 0) { return 2; }
     printf("SMP wire_plaintext=%.*s\n", 16, g_groom_pt);
     fflush(stdout);
#endif
    fflush(stdout);

    memset(g_image, 0xcc, sizeof(g_image));
    for (size_t i = 0; i < sizeof(g_key); i++) { g_key[i] = (uint8_t)i; }

    static uint8_t zeros[8192];
    static uint8_t ct[8192];
    boot_enc_init(&g_enc);
    if (boot_enc_set_key(&g_enc, g_key) != 0) { printf("KEY FAIL\n"); return 2; }
    memset(zeros, 0, sizeof(zeros));
    memset(ct, 0, sizeof(ct));
    boot_enc_encrypt(&g_enc, 4096, 2048, 0, ct);
    for (size_t i = 0; i < 2048; i++) { g_groom_ct[i] = ct[i] ^ g_groom_pt[i % 16]; }
    g_groom = 1;
    g_groom_len = 2048;

#ifdef M2S_SOCKET_UART
    bool command_seen = boot_serial_start_inactivity(&uart, 1000, 100);
    printf("SERIAL_DONE reads=%u bytes=%u tx=%zu command_seen=%d\n",
           g_uart_reads, g_uart_bytes, g_uart_tx, command_seen);
#else
    boot_uf = &uart;
    boot_serial_input((char *)pkt, (int)(8 + payload_len));
#endif
    printf("SMP image[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x ih_hdr_size=%u flags=%08x\n",
           g_image[0], g_image[1], g_image[2], g_image[3],
           g_image[4], g_image[5], g_image[6], g_image[7],
           (unsigned)(g_image[8] | (g_image[9] << 8)),
           (unsigned)(g_image[16] | (g_image[17] << 8) | ((uint32_t)g_image[18] << 16) | ((uint32_t)g_image[19] << 24)));
    fflush(stdout);
    printf("SMP_DONE readback_len=%u readback=", g_readback_len);
    for (uint32_t i = 0; i < g_readback_len && i < 16; i++) { printf("%02x", g_readback[i]); }
    printf("\n");
    fflush(stdout);
    close(fd);
    close(srv);
    return 0;
}
