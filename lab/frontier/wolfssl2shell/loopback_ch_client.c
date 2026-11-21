/* Loopback-only DTLS 1.3 client whose first ClientHello is captured by a
 * local UDP collector, to supply a real handshake datagram for the replay. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int main(int argc, char** argv)
{
    int port, fd, i, ret;
    struct sockaddr_in addr;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;

    if (argc != 2) {
        fprintf(stderr, "usage: loopback_ch_client PORT\n");
        return 2;
    }
    port = atoi(argv[1]);
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
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    if (wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS)
        return 2;

    for (i = 0; i < 400; ++i) {
        ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS)
            break;
        usleep(5000);
    }
    printf("FACT client_connect_ret=%d\n", ret);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    close(fd);
    return 0;
}
