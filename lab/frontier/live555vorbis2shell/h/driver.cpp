// Frontier-authored scaffolding: libc-only base64Decode plus a direct call
// into the verbatim pinned parseVorbisOrTheoraConfigStr() translation unit.
// No RTSP server, SDP parser, socket or live555 build is used.
#include <sys/types.h>
#include <string.h>
#include <stdio.h>

void parseVorbisOrTheoraConfigStr(char const* configStr,
                                  u_int8_t*& identificationHdr, unsigned& identificationHdrSize,
                                  u_int8_t*& commentHdr, unsigned& commentHdrSize,
                                  u_int8_t*& setupHdr, unsigned& setupHdrSize,
                                  u_int32_t& identField);

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0; // live555 maps invalid characters (including '=') to zero
}

// Exact-size allocation; live555's base64Decode also uses new[] and trims
// trailing zeros only when padding was present. All vectors here are unpadded.
u_int8_t* base64Decode(char const* str, unsigned& resultSize) {
    unsigned groups = (unsigned)(strlen(str) / 4);
    u_int8_t* out = new u_int8_t[groups * 3];
    for (unsigned i = 0; i < groups; ++i) {
        int a = b64val(str[4 * i]), b = b64val(str[4 * i + 1]);
        int c = b64val(str[4 * i + 2]), d = b64val(str[4 * i + 3]);
        out[3 * i]     = (u_int8_t)((a << 2) | (b >> 4));
        out[3 * i + 1] = (u_int8_t)((b << 4) | (c >> 2));
        out[3 * i + 2] = (u_int8_t)((c << 6) | d);
    }
    resultSize = groups * 3;
    return out;
}

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s BASE64_CONFIG\n", argv[0]); return 2; }
    u_int8_t* id = NULL; unsigned idSize = 0;
    u_int8_t* co = NULL; unsigned coSize = 0;
    u_int8_t* su = NULL; unsigned suSize = 0;
    u_int32_t ident = 0;
    parseVorbisOrTheoraConfigStr(argv[1], id, idSize, co, coSize, su, suSize, ident);
    printf("id=%u comment=%u setup=%u ident=%u\n", idSize, coSize, suSize, ident);
    delete[] id; delete[] co; delete[] su;
    return 0;
}
