#ifndef SD_FRONTIER_SD_STUB_H
#define SD_FRONTIER_SD_STUB_H
struct ggml_tensor;
typedef bool (*sd_eval_callback)(struct ggml_tensor*, bool, void*);
void sd_set_backend_eval_callback(sd_eval_callback callback, void* user_data);
#endif
