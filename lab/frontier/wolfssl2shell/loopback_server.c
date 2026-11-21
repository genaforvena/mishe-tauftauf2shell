/*
 * Loopback-only wolfSSL DTLS 1.3 server for CVE-2026-6679 consumer-reality.
 *
 * Built against the verbatim pinned v5.9.0 library; no library source edits.
 * The only instrumentation is in this wrapper: it prints the real
 * ssl->dtls13Rtx.seenRecords list length after each wolfSSL_accept() pass.
 * The socket is bound to 127.0.0.1 and never routes elsewhere.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <wolfssl/options.h>
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

#ifndef WOLFSSL_DTLS13
#error "WOLFSSL_DTLS13 not configured"
#endif

static int ack_count(const WOLFSSL* ssl)
{
    const Dtls13RecordNumber* rn = ssl->dtls13Rtx.seenRecords;
    int n = 0;
    while (rn != NULL) {
        ++n;
        rn = rn->next;
    }
    return n;
}
static volatile int g_monitor_run = 1;

static void* ack_monitor(void* arg)
{
    WOLFSSL* s = (WOLFSSL*)arg;
    while (g_monitor_run) {
        printf("FACT MONITOR ack_count=%d state=%d done=%d\n",
               ack_count(s), s->options.serverState, s->options.handShakeDone);
        fflush(stdout);
        usleep(500000);
    }
    return NULL;
}

int main(int argc, char** argv)
{
    int port, fd, ret, n, last = -1, iter, err, have, shown = 0;
    struct sockaddr_in addr;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    char tree[1024];

    if (argc < 2 || argc > 5) {
        fprintf(stderr, "usage: loopback_server PORT [TIMEOUT_SEC] [early13] [unified_seen]\n");
        return 2;
    }
    port = atoi(argv[1]);
    if (port < 1024 || port > 65535)
        return 2;

    if (snprintf(tree, sizeof(tree), "%s", "./build/wolfssl-5.9.0-stable") < 0)
        return 2;

    if (wolfSSL_library_init() != WOLFSSL_SUCCESS)
        return 2;
    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());
    if (ctx == NULL)
        return 2;
    if (wolfSSL_CTX_use_certificate_file(ctx,
            "./build/wolfssl-5.9.0-stable/certs/server-cert.pem",
            SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(ctx,
            "./build/wolfssl-5.9.0-stable/certs/server-key.pem",
            SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "server cert/key load failed\n");
        return 2;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, 0);

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        return 2;

    /* Lab-side configuration: stateful from the first record, no HRR cookie,
     * and no opportunistic ACK flush while the sender fills seenRecords. */
    ssl->options.sendCookie = 0;
    wolfSSL_dtls13_set_send_more_acks(ssl, 0);
    /* Lab-only: enter TLS1.3 accept mode from the first call, modelling a
     * server after version negotiation. No pinned library source is edited. */
    if (argc >= 4 && atoi(argv[3])) {
        ssl->options.tls1_3 = 1;
        printf("FACT early13=1 tls1_3=%d\n", ssl->options.tls1_3);
        fflush(stdout);
    }
    if (argc == 5 && atoi(argv[4])) {
        ssl->options.seenUnifiedHdr = 1;
        printf("FACT unified_seen=1\n");
        fflush(stdout);
    }
    {
        int tmo = (argc >= 3) ? atoi(argv[2]) : 60;
        if (tmo < 1) tmo = 1;
        (void)wolfSSL_dtls_set_timeout_init(ssl, tmo);
        (void)wolfSSL_dtls_set_timeout_max(ssl, tmo * 2);
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 2;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((unsigned short)port);
    {
        int sz = 16 * 1024 * 1024;
        struct timeval tv;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
        tv.tv_sec = 0;
        tv.tv_usec = 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("bind 127.0.0.1");
        return 2;
    }
    if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
        return 2;
    {
        pthread_t mon;
        pthread_create(&mon, NULL, ack_monitor, ssl);
    }

    printf("FACT server=loopback version=%s port=%d\n",
           LIBWOLFSSL_VERSION_STRING, port);
    fflush(stdout);

    {
        char rbuf[64];
        for (iter = 0; iter < 20000; ++iter) {
            ret = wolfSSL_accept(ssl);
            if (ret == WOLFSSL_SUCCESS)
                (void)wolfSSL_read(ssl, rbuf, (int)sizeof(rbuf));
        err = wolfSSL_get_error(ssl, ret);
        have = (int)ssl->buffers.inputBuffer.length;
        if (iter < 40 || (have > 0 && shown < 60) || ret == WOLFSSL_SUCCESS) {
            ++shown;
            printf("FACT diag iter=%d ret=%d err=%d in_len=%d type=%d "
                   "dtls=%d stateful=%d cookie=%d ver=%02x%02x\n",
                   iter, ret, err, have, (int)ssl->curRL.type,
                   ssl->options.dtls, ssl->options.dtlsStateful,
                   ssl->options.sendCookie, ssl->version.major,
                   ssl->version.minor);
            fflush(stdout);
        }
        n = ack_count(ssl);
        if (n != last) {
            printf("FACT iter=%d accept_ret=%d ack_count=%d state=%d done=%d "
                   "unified=%d\n", iter, ret, n, ssl->options.serverState,
                   ssl->options.handShakeDone, ssl->options.seenUnifiedHdr);
            fflush(stdout);
            last = n;
        }
        if (n >= 4097)
            break;
        usleep(200);
        }
    }

    printf("FACT final_ack_count=%d accept_ret=%d state=%d done=%d\n",
           ack_count(ssl), ret, ssl->options.serverState,
           ssl->options.handShakeDone);
    printf("FACT pre_write_output_ptr=%p output_size=%u\n",
           (void*)ssl->buffers.outputBuffer.buffer,
           ssl->buffers.outputBuffer.bufferSize);
    fflush(stdout);

    /* Public API -> Dtls13RtxTimeout -> SendDtls13Ack -> the pinned sink,
     * driven by the real network-fed list. */
    ret = wolfSSL_dtls_got_timeout(ssl);
    printf("FACT got_timeout_ret=%d post_write_ack_count=%d "
           "output_ptr=%p output_size=%u\n",
           ret, ack_count(ssl), (void*)ssl->buffers.outputBuffer.buffer,
           ssl->buffers.outputBuffer.bufferSize);
    fflush(stdout);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return 0;
}
