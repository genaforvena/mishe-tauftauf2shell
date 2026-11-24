#pragma once
// Minimal stand-in for ggml-impl.h: log.h only needs the forward declaration
// and the GGML_LOG_* macros. No ggml computation is used by the RPC transport.
#include <cstdio>
struct ggml_tensor;
#define GGML_LOG_INFO(...)  do { std::printf(__VA_ARGS__); } while (0)
#define GGML_LOG_WARN(...)  do { std::printf(__VA_ARGS__); } while (0)
#define GGML_LOG_ERROR(...) do { std::printf(__VA_ARGS__); } while (0)
#define GGML_LOG_DEBUG(...) do { std::printf(__VA_ARGS__); } while (0)
