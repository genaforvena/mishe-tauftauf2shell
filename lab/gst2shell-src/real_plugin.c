/* Drive the SHIPPING rtpL16depay plugin (not a recompiled harness).
 * caps carries encoding-params=(string)N; then one RTP buffer is pushed so
 * the real process() runs with whatever `order` set_caps left behind.
 */
#include <gst/gst.h>
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char **argv)
{
  gint channels = 74;
  GstElement *pipe, *dep, *sink_elem;
  GstPad *sink;
  GstCaps *caps;
  GstBuffer *buf;
  guint8 *data;
  gchar *capsstr;
  gboolean ok;
  GstFlowReturn fr;

  if (argc > 1)
    channels = atoi (argv[1]);
  gst_init (&argc, &argv);
  setvbuf (stdout, NULL, _IONBF, 0);

  pipe = gst_pipeline_new ("p");
  dep = gst_element_factory_make ("rtpL16depay", "dep");
  sink_elem = gst_element_factory_make ("fakesink", "sink");
  if (!dep || !sink_elem) {
    printf ("NO_ELEMENT\n");
    return 2;
  }
  gst_bin_add_many (GST_BIN (pipe), dep, sink_elem, NULL);
  gst_element_link (dep, sink_elem);
  gst_element_set_state (pipe, GST_STATE_PLAYING);
  sink = gst_element_get_static_pad (dep, "sink");

  capsstr = g_strdup_printf ("application/x-rtp, media=(string)audio, "
      "clock-rate=(int)44100, encoding-name=(string)L16, "
      "encoding-params=(string)%d, payload=(int)96", channels);
  caps = gst_caps_from_string (capsstr);
  printf ("caps=%s\n", capsstr);
  ok = gst_pad_set_caps (sink, caps);
  printf ("set_caps=%d\n", ok);
  /* 12-byte RTP header (PT=96) + one S16BE sample. */
  data = g_malloc0 (16);
  data[0] = 0x80;
  data[1] = 96 & 0x7f;
  data[12] = 0;
  data[13] = 1;
  data[14] = 0;
  data[15] = 2;
  buf = gst_buffer_new_wrapped (data, 16);
  printf ("pushing buffer\n");
  fr = gst_pad_chain (sink, buf);
  printf ("push=%d\n", fr);

  gst_caps_unref (caps);
  g_free (capsstr);
  gst_object_unref (sink);
  gst_element_set_state (pipe, GST_STATE_NULL);
  gst_object_unref (pipe);
  return 0;
}
