// W176 negative result: a lossless AV1 sequence cannot carry the mixed-size
// frames that the x265 padding path needs. The pinned build has AOM AV1 in,
// and libheif's public API accepts images of any size, but libaom latches the
// frame size from frame 0; frame 1 is refused with rc 8 sub 5002 "Image size
// must match encoder init configuration size". `heif-enc -A -L -S` likewise
// refuses mixed-size input before any encoder call.
//
// Build against the pinned W161 plain Release tree (see PROVENANCE-real.md):
//   SRC=lab/frontier/libheif2shell/src/libheif-v1.23.6
//   B=/tmp/libheif2shell-vuln-plain
//   LIBS=$(ninja -C "$B" -t commands examples/heif-enc | tail -1 \
//     | grep -o '/usr/lib[^ ]*' | tr '\n' ' ')
//   g++ -std=c++17 -g -O0 -U_GNU_SOURCE -I"$SRC/libheif/api" -I"$B" \
//     lab/frontier/libheif2shell/real/avif_lossless_probe.cc \
//     "$B/libheif/libheif.a" $LIBS -ldl -o /tmp/avif_lossless_probe
//   /tmp/avif_lossless_probe make /tmp/avif-mixed.avif
//   /tmp/avif_lossless_probe check /tmp/avif-mixed.avif
// The second frame's Y row 64 is a chosen 0x41..0x80 ramp; `check` prints
// whether it decoded byte-exact if libaom ever starts accepting the file.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libheif/heif.h>
#include <libheif/heif_sequences.h>

static void report(const char* what, heif_error e)
{
  if (e.code) std::fprintf(stderr, "%s: rc=%d sub=%d %s\n", what, e.code, e.subcode,
                           e.message ? e.message : "?");
}

static heif_image* make_image(int w, int h, bool second)
{
  heif_image* img = nullptr;
  report("create", heif_image_create(w, h, heif_colorspace_YCbCr, heif_chroma_420, &img));
  if (!img) return nullptr;
  report("Y plane", heif_image_add_plane(img, heif_channel_Y, w, h, 8));
  report("Cb plane", heif_image_add_plane(img, heif_channel_Cb, (w+1)/2, (h+1)/2, 8));
  report("Cr plane", heif_image_add_plane(img, heif_channel_Cr, (w+1)/2, (h+1)/2, 8));
  int sy = 0, sc = 0;
  uint8_t* y = heif_image_get_plane(img, heif_channel_Y, &sy);
  uint8_t* cb = heif_image_get_plane(img, heif_channel_Cb, &sc);
  uint8_t* cr = heif_image_get_plane(img, heif_channel_Cr, &sc);
  for (int r = 0; r < h; ++r)
    for (int x = 0; x < w; ++x)
      y[r*sy+x] = (second && r == 64) ? uint8_t(0x41 + (x & 63)) : 0x80;
  for (int r = 0; r < (h+1)/2; ++r)
    for (int x = 0; x < (w+1)/2; ++x) { cb[r*sc+x] = 0x80; cr[r*sc+x] = 0x80; }
  heif_image_set_duration(img, 1);
  return img;
}

static int make(const char* out)
{
  heif_context* ctx = heif_context_alloc();
  heif_encoder* enc = nullptr;
  report("AV1 encoder", heif_context_get_encoder_for_format(ctx, heif_compression_AV1, &enc));
  if (!enc) return 2;
  report("lossless", heif_encoder_set_parameter(enc, "lossless", "1"));
  report("chroma420", heif_encoder_set_parameter(enc, "chroma", "420"));
  report("speed", heif_encoder_set_parameter(enc, "speed", "8"));
  heif_context_set_sequence_timescale(ctx, 30);
  heif_track_options* opts = heif_track_options_alloc();
  heif_track_options_set_timescale(opts, 30);
  heif_track* track = nullptr;
  report("track", heif_context_add_visual_sequence_track(ctx, 512, 64,
         heif_track_type_image_sequence, opts, nullptr, &track));
  heif_track_options_release(opts);
  if (!track) return 3;
  heif_image* a = make_image(512, 64, false);
  report("frame0", heif_track_encode_sequence_image(track, a, enc, nullptr));
  heif_image_release(a);
  heif_image* b = make_image(64, 65, true);
  report("frame1", heif_track_encode_sequence_image(track, b, enc, nullptr));
  heif_image_release(b);
  report("end", heif_track_encode_end_of_sequence(track, enc));
  report("write", heif_context_write_to_file(ctx, out));
  heif_encoder_release(enc);
  heif_track_release(track);
  heif_context_free(ctx);
  return 0;
}

static int check(const char* in)
{
  heif_context* ctx = heif_context_alloc();
  report("read", heif_context_read_from_file(ctx, in, nullptr));
  if (!heif_context_has_sequence(ctx)) { std::fprintf(stderr, "no sequence\n"); return 4; }
  heif_track* track = heif_context_get_track(ctx, 0);
  for (int f = 0;; ++f) {
    heif_image* img = nullptr;
    heif_error e = heif_track_decode_next_image(track, &img, heif_colorspace_YCbCr,
                                                heif_chroma_420, nullptr);
    if (e.code == heif_error_End_of_sequence) break;
    if (e.code) { report("decode", e); return 5; }
    int stride = 0;
    const int w = heif_image_get_width(img, heif_channel_Y);
    const int h = heif_image_get_height(img, heif_channel_Y);
    const uint8_t* y = heif_image_get_plane_readonly(img, heif_channel_Y, &stride);
    std::printf("frame %d %dx%d stride=%d", f, w, h, stride);
    if (f == 1) {
      std::printf(" row64=");
      for (int x = 0; x < 16; ++x) std::printf("%02x", y[64*stride+x]);
      bool exact = true;
      for (int x = 0; x < w; ++x)
        if (y[64*stride+x] != uint8_t(0x41+(x&63))) exact = false;
      std::printf(" exact=%d", exact);
    }
    std::printf("\n");
    heif_image_release(img);
  }
  heif_track_release(track);
  heif_context_free(ctx);
  return 0;
}

int main(int argc, char** argv)
{
  if (argc < 3) { std::fprintf(stderr, "usage: %s make|check FILE\n", argv[0]); return 64; }
  return std::strcmp(argv[1], "make") == 0 ? make(argv[2]) : check(argv[2]);
}
