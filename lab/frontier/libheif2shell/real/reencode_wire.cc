// Synthetic loopback wire-input lane for GHSA-hpg4-g2gc-pq42 (W172).
//
// This is NOT a real-world libheif network service. It is a one-shot consumer
// that accepts one HEIF byte stream on 127.0.0.1, feeds those bytes to the
// pinned public libheif decoder, then re-encodes every decoded frame through a
// fixed-size x265 sequence encoder — the exact call path that triggers the
// mixed-size padding overflow. It measures whether WIRE-DERIVED bytes reach
// the overflow; it does not establish a remote command execution path.
//
// Usage: reencode_wire OUTPUT.heif [retain]
//   Prints "WIRE_PORT <port>" then blocks for one connection on 127.0.0.1.
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

static void report(const char* what, heif_error err)
{
  if (err.code) {
    std::fprintf(stderr, "%s: rc=%d sub=%d %s\n", what, err.code, err.subcode,
                 err.message ? err.message : "(no message)");
  }
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

  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) return 10;
  int one = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0; // ephemeral
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
  if (!heif_context_has_sequence(in)) {
    std::fprintf(stderr, "WIRE input has no sequence\n");
    return 1;
  }
  heif_track* in_track = heif_context_get_track(in, 0);
  uint16_t tw = 0, th = 0;
  report("track resolution", heif_track_get_image_resolution(in_track, &tw, &th));
  std::printf("WIRE_TRACK %ux%u\n", tw, th);

  heif_context* out = heif_context_alloc();
  heif_track* out_track = nullptr;
  heif_encoder* encoder = nullptr;
  report("get x265 encoder", heif_context_get_encoder_for_format(out, heif_compression_HEVC, &encoder));
  if (!encoder) return 2;
  report("add track", heif_context_add_visual_sequence_track(
                          out, tw, th, heif_track_type_image_sequence,
                          nullptr, nullptr, &out_track));
  if (!out_track) return 3;

  int last_encode_rc = 0;
  heif_image* held = nullptr;
  for (int frame = 0;; ++frame) {
    heif_image* img = nullptr;
    heif_error err = heif_track_decode_next_image(in_track, &img,
                                                  heif_colorspace_YCbCr,
                                                  heif_chroma_420, nullptr);
    if (err.code == heif_error_End_of_sequence) break;
    if (err.code) { report("decode", err); return 4; }
    const int w = heif_image_get_width(img, heif_channel_Y);
    const int h = heif_image_get_height(img, heif_channel_Y);
    int stride = 0;
    heif_image_get_plane_readonly(img, heif_channel_Y, &stride);
    std::printf("WIRE_FRAME %d decoded %dx%d stride=%d\n", frame, w, h, stride);
    if (frame == 1 && h > th) std::printf("WIRE_MIXED_FRAME h=%u padded=%u\n", h, th);
    std::fflush(stdout);

    const heif_error enc_err = heif_track_encode_sequence_image(out_track, img, encoder, nullptr);
    last_encode_rc = enc_err.code;
    report("encode", enc_err);
    std::printf("WIRE_ENCODE_RC %d\n", enc_err.code);
    std::fflush(stdout);

    if (retain_frame1 && frame == 1) held = img;
    else heif_image_release(img);
  }

  report("end sequence", heif_track_encode_end_of_sequence(out_track, encoder));
  report("write", heif_context_write_to_file(out, argv[1]));
  std::printf("WIRE_DONE last_encode_rc=%d\n", last_encode_rc);
  std::fflush(stdout);
  if (held) heif_image_release(held);
  heif_encoder_release(encoder);
  heif_track_release(out_track);
  heif_context_free(out);
  heif_track_release(in_track);
  heif_context_free(in);
  return 0;
}
