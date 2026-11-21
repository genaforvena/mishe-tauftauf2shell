/* Loopback-only DTLS 1.3 client that performs a full handshake against the
 * companion loopback_server, to check the server path is genuinely live. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int main(int argc, char** argv)
{
    int port, fd, i, ret = -1, updates = 0, ur;
    struct sockaddr_in addr;
    struct timeval tv;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: loopback_real_client PORT [KEY_UPDATES]\n");
        return 2;
    }
    port = atoi(argv[1]);
    if (argc == 3)
        updates = atoi(argv[2]);
    if (wolfSSL_library_init() != WOLFSSL_SUCCESS)
        return 2;
    ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());
    if (ctx == NULL)
        return 2;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, 0);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
        return 2;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((unsigned short)port);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        return 2;
    tv.tv_sec = 0;
    tv.tv_usec = 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
        return 2;
    for (i = 0; i < 120; ++i) {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS)
            break;
        usleep(10000);
    }
    printf("FACT real_client_connect_ret=%d tries=%d\n", ret, i + 1);
    fflush(stdout);
    if (ret == WOLFSSL_SUCCESS) {
        char rbuf[64];
        for (i = 0; i < updates; ++i) {
            ur = wolfSSL_update_keys(ssl);
            { char one = 0; (void)wolfSSL_write(ssl, &one, 1); }
            if (i < 4 || i % 500 == 0)
                printf("FACT update_i=%d ret=%d\n", i, ur);
            if (ur != WOLFSSL_SUCCESS)
                break;
        }
        printf("FACT updates_sent=%d\n", i);
        fflush(stdout);
    }
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return ret == WOLFSSL_SUCCESS ? 0 : 1;
}
