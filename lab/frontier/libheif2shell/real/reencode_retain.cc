// Real-libheif heap-adjacency probe: like reencode_sequence.cc, but keeps the
// first decoded frame alive through frame 1's encode. This changes only the
// consumer's image lifetime, so the allocator cannot recycle frame 0's plane
// for the frame-1 replacement plane. No markers or synthetic objects.
// Usage: reencode_retain INPUT.heif OUTPUT.heif
#include <cstdio>
#include <libheif/heif.h>
#include <libheif/heif_sequences.h>

static void report(const char* what, heif_error err)
{
  if (err.code) {
    std::fprintf(stderr, "%s: rc=%d sub=%d %s\n", what, err.code, err.subcode,
                 err.message ? err.message : "(no message)");
  }
}

int main(int argc, char** argv)
{
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s INPUT.heif OUTPUT.heif\n", argv[0]);
    return 64;
  }

  heif_context* in = heif_context_alloc();
  report("read", heif_context_read_from_file(in, argv[1], nullptr));
  if (!heif_context_has_sequence(in)) return 1;
  heif_track* in_track = heif_context_get_track(in, 0);
  uint16_t tw = 0, th = 0;
  report("track resolution", heif_track_get_image_resolution(in_track, &tw, &th));
  std::printf("track declared: %ux%u\n", tw, th);

  heif_context* out = heif_context_alloc();
  heif_track* out_track = nullptr;
  heif_encoder* encoder = nullptr;
  report("get x265 encoder", heif_context_get_encoder_for_format(out, heif_compression_HEVC, &encoder));
  if (!encoder) return 2;
  report("add track", heif_context_add_visual_sequence_track(out, tw, th,
                                                             heif_track_type_image_sequence,
                                                             nullptr, nullptr, &out_track));
  if (!out_track) return 3;

  heif_image* held = nullptr;
  for (int frame = 0;; ++frame) {
    heif_image* img = nullptr;
    heif_error err = heif_track_decode_next_image(in_track, &img,
                                                  heif_colorspace_YCbCr,
                                                  heif_chroma_420, nullptr);
    if (err.code == heif_error_End_of_sequence) break;
    if (err.code) { report("decode", err); return 4; }
    int stride = 0;
    heif_image_get_plane_readonly(img, heif_channel_Y, &stride);
    std::printf("frame %d decoded: %dx%d stride=%d\n", frame,
                heif_image_get_width(img, heif_channel_Y),
                heif_image_get_height(img, heif_channel_Y), stride);
    std::fflush(stdout);
    const heif_error enc_err = heif_track_encode_sequence_image(out_track, img, encoder, nullptr);
    report("encode", enc_err);
    std::printf("frame %d encoded rc=%d\n", frame, enc_err.code);
    std::fflush(stdout);
    if (frame == 0) {
      held = img;             // retain frame 0's planes across frame 1's padding call
    } else {
      heif_image_release(img);
    }
  }
  if (held) {
    std::printf("releasing retained frame 0\n");
    std::fflush(stdout);
    heif_image_release(held);
  }
  report("end sequence", heif_track_encode_end_of_sequence(out_track, encoder));
  report("write", heif_context_write_to_file(out, argv[2]));
  heif_encoder_release(encoder);
  heif_track_release(out_track);
  heif_context_free(out);
  heif_track_release(in_track);
  heif_context_free(in);
  return 0;
}
