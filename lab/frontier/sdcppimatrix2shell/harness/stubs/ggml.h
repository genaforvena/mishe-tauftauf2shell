#ifndef SD_FRONTIER_GGML_STUB_H
#define SD_FRONTIER_GGML_STUB_H
/* Type surface needed to compile the verbatim shipped imatrix.cpp. The
 * collection callback is never invoked by this file-only loader harness. */
#include <cstddef>
#include <cstdint>
struct ggml_tensor;
struct ggml_backend;
enum ggml_op { GGML_OP_NONE = 0, GGML_OP_MUL_MAT, GGML_OP_MUL_MAT_ID };
struct ggml_tensor {
    enum ggml_op op;
    struct ggml_tensor* src[10];
    int64_t ne[4];
    size_t nb[4];
    void* data;
    void* buffer;
    char name[128];
};
size_t ggml_nelements(const ggml_tensor* t);
size_t ggml_nbytes(const ggml_tensor* t);
#endif
