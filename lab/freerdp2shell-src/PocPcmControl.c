/* Benign control: identical flow to PocRdpsndOverflow.c but stage 2
 * re-injects benign PCM and SendSamples stays inside the 8820-byte buffer.
 * Expected: clean exit, no ASan report. */
#include "rdpsnd_main.h"
#include <freerdp/codec/audio.h>
#include <winpr/synch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static AUDIO_FORMAT fmt_pcm = { WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, 0, NULL };

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

    inject(ctx, &fmt_pcm);
    ctx->SelectFormat(ctx, 0);

    inject(ctx, &fmt_pcm);
    UINT rc = ctx->SelectFormat(ctx, 0);
    printf("PCM control rc=%u  out_frames=0x%016zx\n", rc, ctx->priv->out_frames);

    BYTE buf[8192]; memset(buf, 0x41, sizeof buf);
    ctx->SendSamples(ctx, buf, 2048, 0);
    printf("PCM control SendSamples done\n");
    return 0;
}
