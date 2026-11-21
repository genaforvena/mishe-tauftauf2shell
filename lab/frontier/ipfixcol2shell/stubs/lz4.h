/* Minimal ABI-compatible declarations for liblz4.so.1 (no lz4-dev on host).
 * Signatures taken from upstream lz4.h 1.9.x; no logic is reimplemented here.
 */
#pragma once
#include <cstddef>

extern "C" {
typedef struct LZ4_streamDecode_s LZ4_streamDecode_t;
LZ4_streamDecode_t *LZ4_createStreamDecode(void);
int LZ4_freeStreamDecode(LZ4_streamDecode_t *streamPtr);
int LZ4_setStreamDecode(LZ4_streamDecode_t *streamPtr, const char *dictionary, int dictSize);
int LZ4_decompress_safe_continue(LZ4_streamDecode_t *streamPtr,
                                 const char *src, char *dst,
                                 int compressedSize, int dstCapacity);
}
