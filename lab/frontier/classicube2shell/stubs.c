/* Minimal platform/memory shims for the ASan harness.
   MEMORY: malloc/free so ASan tracks every allocation performed by pinned code.
   No PNG/DEFLATE logic is stubbed -- those are the real pinned Bitmap.c/Deflate.c/Stream.c. */
#include "Platform.h"
#include "Utils.h"
#include "Funcs.h"
#include "Logger.h"
#include "String_.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

/* --- memory: ASan-visible, exact-size allocations --- */
void* Mem_TryAlloc(cc_uint32 numElems, cc_uint32 elemsSize) {
	return malloc((size_t)numElems * elemsSize);
}
void* Mem_TryAllocCleared(cc_uint32 numElems, cc_uint32 elemsSize) {
	return calloc(numElems, elemsSize);
}
void* Mem_Alloc(cc_uint32 numElems, cc_uint32 elemsSize, const char* place) {
	(void)place; return Mem_TryAlloc(numElems, elemsSize);
}
void* Mem_AllocCleared(cc_uint32 numElems, cc_uint32 elemsSize, const char* place) {
	(void)place; return Mem_TryAllocCleared(numElems, elemsSize);
}
void Mem_Free(void* mem) { free(mem); }
int Mem_Equal(const void* a, const void* b, cc_uint32 numBytes) {
	return memcmp(a, b, numBytes) == 0;
}
void* TempMem_Alloc(int size) { return malloc((size_t)size); }

/* --- byte-order helpers (real pinned code calls these; trivial pure helpers) --- */
cc_uint32 Mem_ReadU32_BE(const void* src) {
	const cc_uint8* p = (const cc_uint8*)src;
	return ((cc_uint32)p[0] << 24) | ((cc_uint32)p[1] << 16) | ((cc_uint32)p[2] << 8) | p[3];
}
cc_uint32 Mem_ReadU32_LE(const void* src) {
	const cc_uint8* p = (const cc_uint8*)src;
	return ((cc_uint32)p[3] << 24) | ((cc_uint32)p[2] << 16) | ((cc_uint32)p[1] << 8) | p[0];
}
void* Mem_Copy(void* dst, const void* src, cc_uint32 numBytes) {
	return memcpy(dst, src, numBytes);
}
void* Mem_Set(void* dst, cc_uint8 value, cc_uint32 numBytes) {
	return memset(dst, value, numBytes);
}

/* --- abort/logging: only reached on impossible internal states --- */
void Process_Abort2(cc_result result, const char* raw_msg) {
	(void)result; fprintf(stderr, "PROCESS_ABORT: %s\n", raw_msg); abort();
}
void Logger_DoAbort(cc_result result, const char* raw_msg, void* ctx) {
	(void)result; (void)ctx; fprintf(stderr, "LOGGER_ABORT: %s\n", raw_msg); abort();
}
void Logger_FailToStart(const char* raw_msg) {
	fprintf(stderr, "LOGGER_FAIL: %s\n", raw_msg); abort();
}


