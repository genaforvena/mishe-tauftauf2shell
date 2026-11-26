#ifndef SD_FRONTIER_UTIL_STUB_H
#define SD_FRONTIER_UTIL_STUB_H
/* Minimal logging/assert macros; the load_imatrix sink needs LOG_ERROR only. */
#include <cstdio>
#include <cstdlib>
#define LOG_ERROR(...) do { std::fprintf(stderr, "ERROR "); std::fprintf(stderr, __VA_ARGS__); } while (0)
#define LOG_WARN(...)  do { std::fprintf(stderr, "WARN  "); std::fprintf(stderr, __VA_ARGS__); } while (0)
#define GGML_UNUSED(x) ((void)(x))
#define GGML_ASSERT(x) do { if (!(x)) std::abort(); } while (0)
#endif
