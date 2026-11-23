// W178 probe: can an ISO/IEC 23001-17 uncompressed-coded sequence supply a
// mixed-size frame whose decoded Y row is byte-exact? The pinned JPEG-coded
// build (W177) distorts independently chosen block values, so this tests the
// charter's "another codec or build" ceiling item on the same v1.23.6 pin.
//
// Build against a plain Release tree with WITH_UNCOMPRESSED_CODEC=ON:
//   SRC=lab/frontier/libheif2shell/src/libheif-v1.23.6
//   B=/tmp/libheif2shell-unci
//   g++ -std=c++17 -g -O0 -U_GNU_SOURCE -I"$SRC/libheif/api" -I"$B" \
//     lab/frontier/libheif2shell/real/uncompressed_mixed.cc \
//     "$B/libheif/libheif.a" $(pkg-config --libs x265 libjpeg zlib 2>/dev/null) \
//     -ldl -o /tmp/uncompressed_mixed
//   /tmp/uncompressed_mixed make /tmp/unci-mixed.heif 1122334455667788...
//   /tmp/uncompressed_mixed check /tmp/unci-mixed.heif
//
// `make` writes frame 0 at 512x64 and frame 1 at 64x65, with the chosen 64
// bytes in frame 1's Y row 64. `check` prints the track resolution and the
// decoded row. No overflow is triggered here; the file is replayed through the
// committed reencode_sequence.cc x265 driver separately.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libheif/heif.h>
#include <libheif/heif_sequences.h>

static void report(const char* what, heif_error e)
{
  if (e.code) {
    std::fprintf(stderr, "%s: rc=%d sub=%d %s\n", what, e.code, e.subcode,
                 e.message ? e.message : "(no message)");
  }
  else {
    std::fprintf(stdout, "%s: ok\n", what);
  }
}

static heif_image* make_image(int w, int h, bool second, const uint8_t* row)
{
  heif_image* img = nullptr;
  report("create", heif_image_create(w, h, heif_colorspace_YCbCr,
                                     heif_chroma_420, &img));
  if (!img) return nullptr;
  report("Y plane", heif_image_add_plane(img, heif_channel_Y, w, h, 8));
  report("Cb plane", heif_image_add_plane(img, heif_channel_Cb, (w+1)/2, (h+1)/2, 8));
  report("Cr plane", heif_image_add_plane(img, heif_channel_Cr, (w+1)/2, (h+1)/2, 8));
  int sy = 0, sc = 0;
  uint8_t* y = heif_image_get_plane(img, heif_channel_Y, &sy);
  uint8_t* cb = heif_image_get_plane(img, heif_channel_Cb, &sc);
  uint8_t* cr = heif_image_get_plane(img, heif_channel_Cr, &sc);
  if (!y || !cb || !cr) { std::fprintf(stderr, "missing plane\n"); return nullptr; }
  for (int r = 0; r < h; ++r)
    for (int x = 0; x < w; ++x)
      y[r*sy+x] = (second && r == 64 && x < 64) ? row[x] : 0x80;
  for (int r = 0; r < (h+1)/2; ++r)
    for (int x = 0; x < (w+1)/2; ++x) { cb[r*sc+x] = 0x80; cr[r*sc+x] = 0x80; }
  heif_image_set_duration(img, 1);
  return img;
}

static int parse_row(const char* hex, uint8_t* row)
{
  if (!hex || std::strlen(hex) != 128) {
    std::fprintf(stderr, "row must be 128 hex characters (64 bytes)\n");
    return 0;
  }
  for (int i = 0; i < 64; ++i) {
    unsigned v = 0;
    if (std::sscanf(hex + 2*i, "%2x", &v) != 1) return 0;
    row[i] = static_cast<uint8_t>(v);
  }
  return 1;
}

static void print_track_resolution(heif_track* track, const char* what)
{
  uint16_t w = 0, h = 0;
  report(what, heif_track_get_image_resolution(track, &w, &h));
  std::printf("%s = %ux%u\n", what, w, h);
}

static int make(const char* out, const char* hex)
{
  uint8_t row[64];
  if (!parse_row(hex, row)) return 64;

  heif_context* ctx = heif_context_alloc();
  heif_encoder* enc = nullptr;
  report("get uncompressed encoder",
         heif_context_get_encoder_for_format(ctx, heif_compression_uncompressed, &enc));
  if (!enc) return 2;
  const char* name = heif_encoder_get_name(enc);
  std::printf("encoder name: %s\n", name ? name : "(null)");

  heif_track* track = nullptr;
  report("add track", heif_context_add_visual_sequence_track(
                          ctx, 512, 64, heif_track_type_image_sequence,
                          nullptr, nullptr, &track));
  if (!track) return 3;
  print_track_resolution(track, "track before");

  const bool both_small = std::getenv("BOTH_SMALL") != nullptr;
  const int sizes[2][2] = {{512, 64}, {64, 65}};
  for (int f = 0; f < 2; ++f) {
    const int fw = both_small ? 64 : sizes[f][0];
    const int fh = both_small ? 65 : sizes[f][1];
    heif_image* img = make_image(fw, fh, f == 1 || std::getenv("BOTH_ROWS"), row);
    if (!img) return 4;
    std::printf("frame %d input: %dx%d\n", f, fw, fh);
    report("encode", heif_track_encode_sequence_image(track, img, enc, nullptr));
    print_track_resolution(track, "track after");
    heif_image_release(img);
  }
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
  if (!heif_context_has_sequence(ctx)) { std::printf("no sequence\n"); return 1; }
  heif_track* track = heif_context_get_track(ctx, 0);
  if (!track) return 2;
  print_track_resolution(track, "file track");
  for (int f = 0;; ++f) {
    heif_image* img = nullptr;
    heif_error err = heif_track_decode_next_image(track, &img, heif_colorspace_YCbCr,
                                                  heif_chroma_420, nullptr);
    if (err.code == heif_error_End_of_sequence) break;
    if (err.code) { report("decode", err); return 3; }
    int w = heif_image_get_width(img, heif_channel_Y);
    int h = heif_image_get_height(img, heif_channel_Y);
    int stride = 0;
    const uint8_t* y = heif_image_get_plane_readonly(img, heif_channel_Y, &stride);
    std::printf("frame %d decoded: %dx%d stride=%d\n", f, w, h, stride);
    if (h > 64 && y) {
      std::printf("row64:");
      for (int x = 0; x < 64; ++x) std::printf(" %02x", y[64*stride+x]);
      std::printf("\n");
    }
    heif_image_release(img);
  }
  heif_track_release(track);
  heif_context_free(ctx);
  return 0;
}

int main(int argc, char** argv)
{
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s make OUT HEX128 | check IN\n", argv[0]);
    return 64;
  }
  if (!std::strcmp(argv[1], "make")) return make(argv[2], argc > 3 ? argv[3] : nullptr);
  if (!std::strcmp(argv[1], "check")) return check(argv[2]);
  return 64;
}
