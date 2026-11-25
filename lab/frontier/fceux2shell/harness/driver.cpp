// FCEUX UNIF MAPR heap write harness.
// SetBoardName() and the MAPR chunk-header parse are copied verbatim from
// pinned src/unif.cpp: 1e1de9b (vulnerable parent) and d9132c2 (fixed).
// Only the FCEUFILE wrappers are stand-ins (real FILE*, fread/malloc).
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <climits>
#include <unistd.h>
// Upstream FCEU headers define these aliases; pinned bodies use them verbatim.
typedef uint8_t  uint8;
typedef uint32_t uint32;
typedef uint64_t uint64;

#if defined(FIXED)
#include <limits>
#endif

typedef struct {
    char ID[4];
    uint32 info;
} UNIF_HEADER;
static UNIF_HEADER uchead;
static uint8* boardname;
static uint8* sboardname;
struct FCEUFILE { FILE* f; };

static void* FCEU_malloc(size_t n) { return malloc(n); }
static size_t FCEU_fread(void* p, size_t sz, size_t n, FCEUFILE* fp) {
    return fread(p, sz, n, fp->f);
}
static int FCEU_read32le(uint32* p, FCEUFILE* fp) {
    uint8 b[4];
    if (fread(b, 1, 4, fp->f) != 4) return 0;
    *p = uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24);
    return 1;
}
static uint64 FCEU_ftell(FCEUFILE* fp) { return (uint64)ftell(fp->f); }
static uint64 FCEU_fgetsize(FCEUFILE* fp) {
    long old = ftell(fp->f);
    fseek(fp->f, 0, SEEK_END);
    long n = ftell(fp->f);
    fseek(fp->f, old, SEEK_SET);
    return (uint64)n;
}
static void FCEU_printf(const char* fmt, ...) { (void)fmt; }

#if defined(VULN)
// Verbatim: pins/unif-parent.cpp lines 280-290.
static int SetBoardName(FCEUFILE *fp) {
	if (!(boardname = (uint8*)FCEU_malloc(uchead.info + 1)))
		return(0);
	FCEU_fread(boardname, 1, uchead.info, fp);
	boardname[uchead.info] = 0;
	FCEU_printf(" Board name: %s\n", boardname);
	sboardname = boardname;
	if (!memcmp(boardname, "NES-", 4) || !memcmp(boardname, "UNL-", 4) || !memcmp(boardname, "HVC-", 4) || !memcmp(boardname, "BTL-", 4) || !memcmp(boardname, "BMC-", 4))
		sboardname += 4;
	return(1);
}
#elif defined(FIXED)
// Verbatim: pins/unif-fixed.cpp lines 282-302.
static int SetBoardName(FCEUFILE *fp) {
	const size_t info = uchead.info;
	constexpr size_t maxSize = std::numeric_limits<size_t>::max() - 1;
	if (info > maxSize)
	{
		return(0);
	}
	boardname = (uint8*)FCEU_malloc(static_cast<size_t>(info) + 1);
	if (boardname == nullptr)
	{
		return(0);
	}
	if (FCEU_fread(boardname, 1, info, fp) != info)
	{
		return(0);
	}
	boardname[info] = 0;
	FCEU_printf(" Board name: %s\n", boardname);
	sboardname = boardname;
	if (info >= 4 &&
		(!memcmp(boardname, "NES-", 4) || !memcmp(boardname, "UNL-", 4) || !memcmp(boardname, "HVC-", 4) || !memcmp(boardname, "BTL-", 4) || !memcmp(boardname, "BMC-", 4)))
		sboardname += 4;
	return(1);
}
#else
#error define VULN or FIXED
#endif

#if defined(PLAIN)
// The wild terminator store (boardname + 0xffffffff) faults. Before exiting,
// print file-selected bytes that the earlier short fread placed past the
// zero-sized allocation. No allocator or pointer manipulation is performed.
static void segv_handler(int) {
    static char line[64];
    static const char hx[] = "0123456789abcdef";
    size_t k = 0;
    const char pre[] = "PAST_ALLOC=";
    for (size_t i = 0; i < sizeof(pre) - 1; ++i) line[k++] = pre[i];
    for (int i = 1; i <= 16; ++i) {
        uint8 v = boardname[i];
        line[k++] = hx[v >> 4];
        line[k++] = hx[v & 15];
    }
    line[k++] = '\n';
    (void)!write(2, line, k);
    _exit(42);
}
#endif

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 2;
    FCEUFILE fp = { f };

    // Verbatim from pins/unif-parent.cpp lines 501-508 (chunk header parse).
    int t = FCEU_fread(&uchead, 1, 4, &fp);
    if (t < 4) { if (t > 0) return 0; return 1; }
    if (!(FCEU_read32le(&uchead.info, &fp))) return 0;
#if defined(FIXED)
    // Verbatim from pins/unif-fixed.cpp lines 522-530 (declared-size check).
    const uint64 position = FCEU_ftell(&fp);
    const uint64 size = FCEU_fgetsize(&fp);
    if (position > size || uchead.info > size - position)
    {
        FCEU_printf("Invalid UNIF chunk %.4s: data extends beyond end of file.\n", uchead.ID);
        return 0;
    }
#endif
    if (memcmp(uchead.ID, "MAPR", 4)) return 0;

#if defined(PLAIN)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = segv_handler;
    sigaction(SIGSEGV, &sa, nullptr);
#endif

    if (!SetBoardName(&fp)) { fclose(f); return 3; }
    printf("OK board=%s\n", sboardname ? (char*)sboardname : "(null)");
    fclose(f);
    return 0;
}
