/* Minimal ABI declarations for host liblz4.so.1, copied from the frontier
 * harness stub (no lz4-dev on this host). No logic is reimplemented. */
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
