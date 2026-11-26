#ifndef SD_FRONTIER_GGML_BACKEND_STUB_H
#define SD_FRONTIER_GGML_BACKEND_STUB_H
#include "ggml.h"
bool ggml_backend_buffer_is_host(void* buffer);
void ggml_backend_tensor_get(const ggml_tensor* t, void* data, size_t offset, size_t nbytes);
#endif
