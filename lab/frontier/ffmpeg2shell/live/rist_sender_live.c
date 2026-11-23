/* Throwaway loopback-only librist sender for the ffmpeg2shell live experiment.
 * Sends `count` RIST data blocks of `len` bytes to `url` over 127.0.0.1. */
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

int main(int argc, char **argv)
{
    const char *url = argc > 1 ? argv[1] : "rist://127.0.0.1:5004";
    int count = argc > 2 ? atoi(argv[2]) : 900;
    size_t len = argc > 3 ? (size_t)atoi(argv[3]) : 9972;

    struct rist_logging_settings ls = LOGGING_SETTINGS_INITIALIZER;
    struct rist_logging_settings *lsp = &ls;
    if (rist_logging_set(&lsp, RIST_LOG_INFO, logcb, NULL, NULL, NULL) < 0) {
        fprintf(stderr, "rist_logging_set failed\n");
        return 1;
    }

    struct rist_ctx *ctx = NULL;
    if (rist_sender_create(&ctx, RIST_PROFILE_MAIN, 0, lsp) < 0) {
        fprintf(stderr, "rist_sender_create failed\n");
        return 1;
    }

    struct rist_peer_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    rist_peer_config_defaults_set(&cfg);
    struct rist_peer_config *pc = &cfg;
    if (rist_parse_address2(url, &pc) < 0) {
        fprintf(stderr, "rist_parse_address2 failed\n");
        return 1;
    }

    struct rist_peer *peer = NULL;
    if (rist_peer_create(ctx, &peer, pc) < 0) {
        fprintf(stderr, "rist_peer_create failed\n");
        return 1;
    }
    if (rist_start(ctx) < 0) {
        fprintf(stderr, "rist_start failed\n");
        return 1;
    }
    usleep(600000); /* allow the main-profile handshake to complete */

    unsigned char *buf = malloc(len);
    if (!buf) return 1;
    memset(buf, 0x5a, len);
    const struct { size_t off; unsigned char val; } marks[] = {
        {4096, 0x41}, {4113, 0x7a}, {4120, 0x3c}, {4128, 0x7b},
        {5000, 0x42}, {9000, 0x63},
    };
    for (size_t i = 0; i < sizeof(marks)/sizeof(marks[0]); i++)
        if (marks[i].off < len) buf[marks[i].off] = marks[i].val;

    struct rist_data_block db;
    memset(&db, 0, sizeof(db));
    db.payload = buf;
    db.payload_len = len;
    int fails = 0;
    for (int i = 0; i < count; i++) {
        int r = rist_sender_data_write(ctx, &db);
        if (r < 0) { fails++; if (fails < 5) fprintf(stderr, "write %d: %d\n", i, r); }
        usleep(3000);
    }
    fprintf(stderr, "sent %d blocks of %zu bytes, %d failures\n", count, len, fails);
    usleep(600000);
    rist_destroy(ctx);
    free(buf);
    return 0;
}
