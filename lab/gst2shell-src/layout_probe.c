/*
 * Source-faithful tail-layout probe for CVE-2026-111183 /
 * GHSA-62fg-53h6-6f68 (GStreamer rtpL16depay high-channel-count OOB write).
 *
 * This is NOT a live GStreamer build. It reproduces the exact field layout,
 * in the exact order, of the tail of the vulnerable element instance as read
 * from the pinned source at commit 0b70c356345335dacc0acdc45d07a8a33bdf5eab:
 *
 *   gst-plugins-base/gst-libs/gst/audio/audio-info.h:62-73
 *     struct _GstAudioInfo {
 *       const GstAudioFormatInfo *finfo;          offset  0  (8)
 *       GstAudioFlags             flags;          offset  8  (4)
 *       GstAudioLayout            layout;         offset 12  (4)
 *       gint                      rate;           offset 16  (4)
 *       gint                      channels;       offset 20  (4)
 *       gint                      bpf;            offset 24  (4)
 *       GstAudioChannelPosition   position[64];   offset 28  (256)  <- sink
 *       gpointer                  _gst_reserved[GST_PADDING];
 *                                                  offset 288 (4*8=32)
 *     };                                           sizeof = 320
 *
 *   gst-plugins-good/gst/rtp/gstrtpL16depay.h:47-53
 *     struct _GstRtpL16Depay {
 *       GstRTPBaseDepayload depayload;   (opaque parent, 8-aligned, omitted)
 *       GstAudioInfo info;               followed by
 *       const GstRTPChannelOrder *order; <- first named neighbour
 *     };
 *
 * The parent is an opaque, 8-aligned blob. All offsets BELOW ARE RELATIVE TO
 * `info` and therefore independent of the parent's size: the sink `position`
 * starts at info+28, reserved at info+288, `order` at info+320, and the
 * element allocation ends at info+328. So the vulnerable loop
 * `for (i=0;i<channels;i++) posn[i]=NONE;` first exceeds `position[64]` at
 * i=64 (info+284), stays inside the element through i=74 (info+324, the
 * second half of `order`), and escapes the allocation at i=75 (info+328).
 *
 * The written value is the compile-time constant GST_AUDIO_CHANNEL_POSITION_NONE
 * (0). The attacker controls the length, not the bytes. Rung 4 status is
 * decided by whether any in-allocation zeroing is controller-meaningful.
 *
 * Build:
 *   gcc -O0 -g -Wall -o layout_probe layout_probe.c
 *   gcc -O0 -g -fsanitize=address -o layout_probe_asan layout_probe.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define N_POSN 64
#define NONE 0
#define GST_PADDING 4
#define ELEM 4

typedef int gint;
typedef int GstAudioChannelPosition;
typedef void *gpointer;

struct audio_info_model {
  const void *finfo;                       /* 0 */
  gint flags, layout, rate, channels, bpf; /* 8..27 */
  GstAudioChannelPosition position[N_POSN];/* 28..283 */
  gpointer _gst_reserved[GST_PADDING];     /* 288..319 */
};                                          /* sizeof 320 */

struct element_tail {
  struct audio_info_model info;            /* 0..319 */
  const void *order;                       /* 320..327 */
};                                          /* sizeof 328 */

/* compile-time layout assertions against the source-derived offsets */
typedef char assert_pos[sizeof(((struct audio_info_model*)0)->position) == 256 ? 1 : -1];
typedef char assert_info[sizeof(struct audio_info_model) == 320 ? 1 : -1];
typedef char assert_order[__builtin_offsetof(struct element_tail, order) == 320 ? 1 : -1];

/* exact vulnerable loop from gstrtpchannels.c:301-310 at the pinned parent */
static void
vuln_create_default (gint channels, GstAudioChannelPosition * posn)
{
  gint i;
  if (channels <= 0)
    return;
  for (i = 0; i < channels; i++)
    posn[i] = NONE;
}
int
main (int argc, char **argv)
{
  gint channels = argc > 1 ? atoi (argv[1]) : 1000;
  int big = argc > 2 && strcmp (argv[2], "big") == 0;
  struct element_tail *e;
  unsigned char *backing = NULL;
  size_t zone_pad = 0, zone_reserved = 0, zone_order = 0, zone_escape = 0;
  gint i;

  /* Two modes. Exact: calloc(sizeof(element_tail)) so ASan faults at the
   * first write past info+328. Big: carve the element from a 64 KiB backing
   * prefilled with a marker so the non-ASan build can count every zone without
   * corrupting malloc's top chunk (a 936-int zero-fill does corrupt it). */
  if (big) {
    backing = (unsigned char *) malloc (65536);
    if (!backing)
      return 2;
    memset (backing, 0x5a, 65536);
    e = (struct element_tail *) backing;
  } else {
    e = (struct element_tail *) calloc (1, sizeof (*e));
    if (!e)
      return 2;
  }

  /* Set a non-NULL sentinel in `order` so a zeroing write is observable in
   * the non-ASan build. In the real vulnerable path this field is already
   * NULL (set at depay.c:204 before the overflow, because channels>8 has no
   * known order) -- hence zeroing it is a no-op there. The sentinel only
   * makes the layout effect visible; it is not a claim of real impact. */
  e->order = (const void *) (uintptr_t) 0x4141414141414141ULL;

  vuln_create_default (channels, e->info.position);

  /* Classify which zones were touched, by offset relative to info.
   * padding info+284..287; reserved info+288..319; order info+320..327;
   * escape (past the element allocation) info+328 and above. */
  for (i = N_POSN; i < channels; i++) {
    size_t off = 28u + (size_t) i * ELEM;
    if (off >= 284 && off < 288)
      zone_pad++;
    else if (off >= 288 && off < 320)
      zone_reserved++;
    else if (off >= 320 && off < 328)
      zone_order++;
    else if (off >= 328)
      zone_escape++;
  }

  printf ("channels=%d mode=%s info_size=%zu elem_tail_size=%zu position_off=28\n",
      channels, big ? "big" : "exact", sizeof (struct audio_info_model),
      sizeof (struct element_tail));
  printf ("oob_writes=%d pad_writes=%zu reserved_writes=%zu order_writes=%zu escape_writes=%zu\n",
      channels > N_POSN ? channels - N_POSN : 0, zone_pad, zone_reserved,
      zone_order, zone_escape);
  printf ("order_after=%p (sentinel 0x4141... => zeroed=%d)\n", e->order,
      e->order == NULL);
  printf ("first_oob_index=%d first_escape_index=%d\n",
      channels > N_POSN ? N_POSN : -1, 75);
  free (backing ? backing : (unsigned char *) e);
  return 0;
}
