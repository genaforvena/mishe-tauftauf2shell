// W178: reencode_sequence.cc with a selectable decode chroma. The x265 sequence
// plugin calls heif_image_extend_padding_to_size() at encoder_x265.cc:1139 on
// the image handed to it, BEFORE any chroma conversion, so a 4:4:4 or
// monochrome decode should carry byte-exact JPEG samples into the OOB row.
// Usage: reencode_chroma INPUT.heif OUTPUT.heif [decode-only] [420|444|mono]
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libheif/heif.h>
#include <libheif/heif_sequences.h>

static void report(const char* what, heif_error err)
{
  if (err.code) {
    std::fprintf(stderr, "%s: rc=%d sub=%d %s\n", what, err.code, err.subcode,
                 err.message ? err.message : "(no message)");
  }
}

static heif_image* synth_first_image(int w, int h)
{
  heif_image* img = nullptr;
  heif_error e = heif_image_create(w, h, heif_colorspace_YCbCr, heif_chroma_420, &img);
  if (e.code) { report("synth create", e); return nullptr; }
  report("synth Y", heif_image_add_plane(img, heif_channel_Y, w, h, 8));
  report("synth Cb", heif_image_add_plane(img, heif_channel_Cb, (w+1)/2, (h+1)/2, 8));
  report("synth Cr", heif_image_add_plane(img, heif_channel_Cr, (w+1)/2, (h+1)/2, 8));
  int sy = 0, sc = 0;
  uint8_t* y = heif_image_get_plane(img, heif_channel_Y, &sy);
  uint8_t* cb = heif_image_get_plane(img, heif_channel_Cb, &sc);
  uint8_t* cr = heif_image_get_plane(img, heif_channel_Cr, &sc);
  for (int r = 0; r < h; ++r) for (int x = 0; x < w; ++x) y[r*sy+x] = 0x80;
  for (int r = 0; r < (h+1)/2; ++r) for (int x = 0; x < (w+1)/2; ++x) { cb[r*sc+x] = 0x80; cr[r*sc+x] = 0x80; }
  heif_image_set_duration(img, 1);
  return img;
}

int main(int argc, char** argv)
{
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s INPUT.heif OUTPUT.heif [decode-only] [420|444|mono]\n", argv[0]);
    return 64;
  }
  const bool decode_only = (argc > 3 && !std::strcmp(argv[3], "decode-only")) ||
                           (argc > 4 && !std::strcmp(argv[4], "decode-only"));
  const char* chroma_name = argc > 4 ? argv[4] : (argc > 3 && std::strcmp(argv[3], "decode-only") ? argv[3] : "420");
  heif_colorspace cs = heif_colorspace_YCbCr;
  heif_chroma chroma = heif_chroma_420;
  if (!std::strcmp(chroma_name, "444")) chroma = heif_chroma_444;
  else if (!std::strcmp(chroma_name, "native")) { cs = heif_colorspace_undefined; chroma = heif_chroma_undefined; }
  else if (!std::strcmp(chroma_name, "mono")) { cs = heif_colorspace_monochrome; chroma = heif_chroma_monochrome; }
  else if (std::strcmp(chroma_name, "420")) { std::fprintf(stderr, "bad chroma %s\n", chroma_name); return 64; }
  std::printf("decode request: colorspace=%d chroma=%s\n", int(cs), chroma_name);

  heif_context* in = heif_context_alloc();
  report("read", heif_context_read_from_file(in, argv[1], nullptr));
  if (!heif_context_has_sequence(in)) { std::fprintf(stderr, "input has no sequence\n"); return 1; }
  heif_track* in_track = heif_context_get_track(in, 0);
  uint16_t tw = 0, th = 0;
  report("track resolution", heif_track_get_image_resolution(in_track, &tw, &th));
  std::printf("track declared: %ux%u\n", tw, th);
  if (const char* s = std::getenv("TW")) tw = uint16_t(std::atoi(s));
  if (const char* s = std::getenv("TH")) th = uint16_t(std::atoi(s));
  std::printf("encoder declared: %ux%u\n", tw, th);
  heif_context* out = heif_context_alloc();
  heif_track* out_track = nullptr;
  heif_encoder* encoder = nullptr;
  if (!decode_only) {
    report("get x265 encoder", heif_context_get_encoder_for_format(out, heif_compression_HEVC, &encoder));
    if (!encoder) return 2;
    report("add track", heif_context_add_visual_sequence_track(out, tw, th,
                                                              heif_track_type_image_sequence,
                                                              nullptr, nullptr, &out_track));
    if (!out_track) return 3;
  }
  if (!decode_only && std::getenv("SYNTH_FIRST")) {
    heif_image* first = synth_first_image(tw, th);
    if (!first) return 5;
    report("synth first encode", heif_track_encode_sequence_image(out_track, first, encoder, nullptr));
    heif_image_release(first);
  }

  for (int frame = 0;; ++frame) {
    heif_image* img = nullptr;
    heif_error err = heif_track_decode_next_image(in_track, &img, cs, chroma, nullptr);
    if (err.code == heif_error_End_of_sequence) break;
    if (err.code) { report("decode", err); return 4; }
    const int w = heif_image_get_width(img, heif_channel_Y);
    const int h = heif_image_get_height(img, heif_channel_Y);
    int stride = 0;
    heif_image_get_plane_readonly(img, heif_channel_Y, &stride);
    std::printf("frame %d native colorspace=%d chroma=%d\n", frame, int(heif_image_get_colorspace(img)), int(heif_image_get_chroma_format(img)));
    if (h > 64 && stride > 0) {
      std::printf("frame %d Y row64:", frame);
      for (int x = 0; x < 64 && x < w; ++x)
        std::printf(" %02x", heif_image_get_plane_readonly(img, heif_channel_Y, &stride)[64*stride+x]);
      std::printf("\n");
    }
    std::fflush(stdout);
    if (!decode_only) {
      const heif_error enc_err = heif_track_encode_sequence_image(out_track, img, encoder, nullptr);
      report("encode", enc_err);
      std::printf("frame %d encode rc=%d\n", frame, enc_err.code);
      std::fflush(stdout);
    }
    heif_image_release(img);
  }

  if (!decode_only) {
    report("end sequence", heif_track_encode_end_of_sequence(out_track, encoder));
    report("write", heif_context_write_to_file(out, argv[2]));
    heif_encoder_release(encoder);
    heif_track_release(out_track);
    heif_context_free(out);
  }
  heif_track_release(in_track);
  heif_context_free(in);
  return 0;
}
