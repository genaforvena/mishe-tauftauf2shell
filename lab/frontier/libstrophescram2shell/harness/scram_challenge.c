/* Feed a server-first-message SCRAM challenge into libstrophe's real
 * sasl_scram() consumer. Only base64 encoding of the salt and argument
 * handling are lab-written; the challenge parser, SCRAM_ClientKey() and
 * SCRAM_Hi() are verbatim pinned library code. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "strophe.h"
#include "src/sasl.h"
#include "src/scram.h"

static void b64(const uint8_t *in, size_t len, char *out)
{
    static const char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i;
    for (i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= (uint32_t)in[i + 2];
        *out++ = t[(v >> 18) & 63];
        *out++ = t[(v >> 12) & 63];
        *out++ = i + 1 < len ? t[(v >> 6) & 63] : '=';
        *out++ = i + 2 < len ? t[v & 63] : '=';
    }
    *out = '\0';
}

int main(int argc, char **argv)
{
    size_t salt_len = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 125;
    unsigned char fill = argc > 2 ? (unsigned char)strtoul(argv[2], NULL, 0) : 0x42;
    uint8_t salt[4096];
    char encoded[8192];
    char challenge[9000];
    xmpp_ctx_t *ctx;
    const struct hash_alg *alg = NULL;
    char *response;
    size_t i;

    if (salt_len == 0 || salt_len > sizeof(salt)) {
        fprintf(stderr, "salt length out of range\n");
        return 2;
    }
    memset(salt, fill, salt_len);
    b64(salt, salt_len, encoded);
    snprintf(challenge, sizeof(challenge), "r=nonce,s=%s,i=1", encoded);

    ctx = xmpp_ctx_new(NULL, NULL);
    if (!ctx) {
        fprintf(stderr, "xmpp_ctx_new failed\n");
        return 2;
    }
    for (i = 0; i < scram_algs_num; i++) {
        if (strcmp(scram_algs[i]->scram_name, "SCRAM-SHA-1") == 0) {
            alg = scram_algs[i];
            break;
        }
    }
    if (!alg) {
        fprintf(stderr, "SCRAM-SHA-1 not found\n");
        return 2;
    }

    fprintf(stderr, "salt_len=%zu fill=0x%02x challenge_len=%zu\n",
            salt_len, fill, strlen(challenge));
    response = sasl_scram(ctx, alg, "biws", challenge, "n=user,r=nonce",
                          "user@example.org", "password");
    fprintf(stderr, "sasl_scram response=%s\n", response ? "non-NULL" : "NULL");
    xmpp_free(ctx, response);
    xmpp_ctx_free(ctx);
    return 0;
}
