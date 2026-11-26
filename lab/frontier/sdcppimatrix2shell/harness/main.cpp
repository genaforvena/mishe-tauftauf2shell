// Calls the shipped IMatrixCollector::load_imatrix() via the shipped global
// load_imatrix() entry point. No parser logic is reimplemented here.
#include "stable-diffusion.h"
#include "runtime/imatrix.h"
#include <cstdio>
#include <cstdlib>

bool load_imatrix(const char* imatrix_path);

size_t ggml_nelements(const ggml_tensor*) { std::abort(); }
size_t ggml_nbytes(const ggml_tensor*) { std::abort(); }
bool ggml_backend_buffer_is_host(void* buffer) { (void)buffer; return true; }
void ggml_backend_tensor_get(const ggml_tensor*, void*, size_t, size_t) { std::abort(); }
void sd_set_backend_eval_callback(sd_eval_callback, void*) {}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s imatrix-file\n", argv[0]);
        return 2;
    }
    const bool ok = load_imatrix(argv[1]);
    std::printf("load_imatrix=%d\n", ok ? 1 : 0);
    return ok ? 0 : 3;
}
