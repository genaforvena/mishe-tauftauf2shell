/* Real pjmedia AVI consumer: create streams, pull one video frame.
 *
 * argv[1] = AVI path, argv[2] = "exact" (ASan redzone directly after the
 * logical frame) or "neighbor" (a live sentinel object after the frame).
 */
#include <pjlib.h>
#include <pjmedia.h>
#include <pjmedia/avi_stream.h>
#include <pjmedia/format.h>
#include <pjmedia/port.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(call, label) do {                                            \
    pj_status_t _s = (call);                                               \
    if (_s != PJ_SUCCESS) {                                                \
        char _err[PJ_ERR_MSG_SIZE];                                        \
        pj_strerror(_s, _err, sizeof(_err));                               \
        fprintf(stderr, "FAIL %s: %s\n", label, _err);                     \
        return 2;                                                          \
    }                                                                      \
} while (0)

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
    pjmedia_port *port;
    pjmedia_avi_stream *stream;
    const pjmedia_video_format_info *vfi;
    pjmedia_video_apply_fmt_param vafp;
    pjmedia_frame frame;
    unsigned char *buf;
    size_t framebytes;
    int neighbor;
    pj_status_t status;

    if (argc < 3) {
        fprintf(stderr, "usage: %s AVI exact|neighbor\n", argv[0]);
        return 2;
    }
    neighbor = (strcmp(argv[2], "neighbor") == 0);

    CHECK(pj_init(), "pj_init");
    pj_caching_pool_init(&cp, NULL, 0);
    pool = pj_pool_create(&cp.factory, "avi-real", 4096, 4096, NULL);
    if (!pool) {
        fprintf(stderr, "FAIL pool\n");
        return 2;
    }
    /* DIB video needs only the format manager; AV sync is disabled by flag. */
    if (!pjmedia_video_format_mgr_instance())
        CHECK(pjmedia_video_format_mgr_create(pool, 64, 0, NULL), "vfmgr");
    fprintf(stderr, "AVI=%s mode=%s\n", argv[1], neighbor ? "neighbor" : "exact");
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

    /* The real consumer allocates a frame buffer from declared dimensions. */
    buf = (unsigned char *)malloc(framebytes + (neighbor ? 64 : 0));
    if (!buf) {
        fprintf(stderr, "FAIL malloc\n");
        return 2;
    }
    memset(buf, 0x41, framebytes + (neighbor ? 64 : 0));
    if (neighbor)
        memcpy(buf + framebytes, "LIVE-ADJACENT-OBJ!", 18);

    pj_bzero(&frame, sizeof(frame));
    frame.buf = buf;
    frame.size = framebytes;
    if (neighbor)
        hexdump("NEIGHBOR_BEFORE", buf + framebytes, 18);
    fprintf(stderr, "PULL_START frame.size=%zu\n", framebytes);
    fflush(stderr);

    status = pjmedia_port_get_frame(port, &frame);
    fprintf(stderr, "PULL_DONE status=%d frame.size=%u frame.type=%d\n",
            (int)status, (unsigned)frame.size, (int)frame.type);
    hexdump("FRAME_TAIL", buf + (framebytes > 16 ? framebytes - 16 : 0), 16);
    if (neighbor)
        hexdump("NEIGHBOR_AFTER", buf + framebytes, 18);

    free(buf);
    pjmedia_port_destroy(port);
    pj_caching_pool_destroy(&cp);
    pj_shutdown();
    return 0;
}
