// Harness-owned frame for pinned SRS RTCP decoder bytes. Not upstream code.
#include <arpa/inet.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <cstddef>
#include <new>
#include <unistd.h>

typedef const char *srs_error_t;
static const srs_error_t srs_success = NULL;
static const int ERROR_RTC_RTCP = 1001;

#define srs_assert(x) do { if (!(x)) { \
    fprintf(stderr, "srs_assert failed: %s\n", #x); abort(); } } while (0)

static srs_error_t srs_error_new(int code, const char *fmt, ...)
{
    static char msg[512];
    va_list ap;
    va_start(ap, fmt);
    int n = snprintf(msg, sizeof(msg), "code=%d ", code);
    vsnprintf(msg + n, sizeof(msg) - n, fmt, ap);
    va_end(ap);
    return msg;
}

static srs_error_t srs_error_wrap(srs_error_t err, const char *fmt, ...)
{
    (void)fmt;
    return err;
}

@@HPP_STRUCT@@

const int kRtcpPacketSize = 1500;

class SrsBuffer
{
private:
    char *bytes_;
    char *p_;
    int nb_bytes_;

public:
    SrsBuffer(char *bytes, int nb_bytes) : bytes_(bytes), p_(bytes), nb_bytes_(nb_bytes) {}
    char *head();
    char *data();
    int size();
    int left();
    bool empty() { return !bytes_ || (p_ >= bytes_ + nb_bytes_); }
    bool require(int required_size);
    int32_t read_4bytes();
    void read_bytes(char *data, int size);
};

class SrsRtcpCommon
{
protected:
    SrsRtcpHeader header_;
    uint32_t ssrc_;
    uint8_t payload_[kRtcpPacketSize];
    int payload_len_;
    char *data_;
    int nb_data_;
    srs_error_t decode_header(SrsBuffer *buffer);

public:
    static size_t payload_offset() { return offsetof(SrsRtcpCommon, payload_); }
    SrsRtcpCommon() : ssrc_(0), payload_len_(0), data_(NULL), nb_data_(0) {}
    virtual ~SrsRtcpCommon() {}
    virtual srs_error_t decode(SrsBuffer *buffer);
};

class SrsRtcpTWCC : public SrsRtcpCommon
{
public:
    srs_error_t decode(SrsBuffer *buffer);
};

@@BUF_REQUIRE@@
@@BUF_READ_BYTES@@
@@BUF_READ4@@

char *SrsBuffer::head() { return p_; }
char *SrsBuffer::data() { return bytes_; }
int SrsBuffer::size() { return nb_bytes_; }
int SrsBuffer::left() { return nb_bytes_ - (int)(p_ - bytes_); }

@@DECODE_HEADER@@
@@DECODE_COMMON@@
@@DECODE_TWCC@@
