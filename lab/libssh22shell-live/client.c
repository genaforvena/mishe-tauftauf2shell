/* Live client for CVE-2026-66035 stage-2 experiment. Loopback only. */
#include <libssh2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    int port, sock, rc;
    struct sockaddr_in addr;
    LIBSSH2_SESSION *session;
    const char *authlist;

    if(argc != 2) {
        fprintf(stderr, "usage: %s PORT\n", argv[0]);
        return 2;
    }
    port = atoi(argv[1]);
    alarm(12); /* controls must not hang forever */

    sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 2;
    }
    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2_init=%d\n", rc);
        return 2;
    }
    session = libssh2_session_init();
    if(!session) {
        fprintf(stderr, "session_init failed\n");
        return 2;
    }
    libssh2_session_set_blocking(session, 1);
    if(getenv("LAB_TRACE"))
        libssh2_trace(session, LIBSSH2_TRACE_TRANS | LIBSSH2_TRACE_KEX |
                      LIBSSH2_TRACE_ERROR | LIBSSH2_TRACE_SOCKET);

    rc = libssh2_session_handshake(session, sock);
    fprintf(stderr, "HANDSHAKE_RC=%d\n", rc);
    if(rc)
        goto done;

    /* Forces a transport read; the server's first encrypted packet is
     * processed here (the handshake itself stops at NEWKEYS). */
    authlist = libssh2_userauth_list(session, "lab", 3);
    fprintf(stderr, "AUTH_LIST=%s\n", authlist ? "received" : "NULL");

done:
    libssh2_session_free(session);
    close(sock);
    libssh2_exit();
    fprintf(stderr, "CLIENT_DONE\n");
    return 0;
}
