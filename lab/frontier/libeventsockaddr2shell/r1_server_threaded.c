#include <event2/event.h>
#include <event2/http.h>
#include <event2/listener.h>
#include <event2/thread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#define SERVER_PATH "/tmp/libevent_r1.sock"

static void handle_req(struct evhttp_request *req, void *arg) {
    (void)arg;
    evhttp_send_reply(req, 200, "OK", NULL);
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    unlink(SERVER_PATH);

    if (evthread_use_pthreads() != 0) {
        fprintf(stderr, "evthread_use_pthreads failed\n");
        return 1;
    }

    int tcp = argc > 1 && strcmp(argv[1], "tcp") == 0;
    int sfd;
    if (tcp) {
        sfd = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(18081);
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(sfd, (struct sockaddr*)&sin, sizeof(sin));
        listen(sfd, 16);
    } else {
        sfd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un sa;
        memset(&sa, 0, sizeof(sa));
        sa.sun_family = AF_UNIX;
        strncpy(sa.sun_path, SERVER_PATH, sizeof(sa.sun_path) - 1);
        bind(sfd, (struct sockaddr*)&sa, sizeof(sa));
        listen(sfd, 16);
    }

    struct event_base *base = event_base_new();
    struct evhttp *http = evhttp_new(base);
    evhttp_set_gencb(http, handle_req, NULL);
    evhttp_accept_socket(http, sfd);

    fprintf(stderr, "[server] listening on %s (pthreads ON)\n", tcp ? "127.0.0.1:18081" : SERVER_PATH);
    event_base_dispatch(base);
    return 0;
}
