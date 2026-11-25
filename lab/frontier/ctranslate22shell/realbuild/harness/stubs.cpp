// Out-of-line definitions for upstream symbols reachable only through
// quantization / tensor-parallel branches that this single-variable CPU load
// never takes. They are deliberately throwing stubs: if the exercised path
// ever reaches one, the run fails loudly rather than silently faking behavior.
#include <stdexcept>
#include <string>
#include <vector>

#include "ctranslate2/ops/activation.h"
#include "ctranslate2/ops/concat.h"
#include "ctranslate2/ops/dequantize.h"
#include "ctranslate2/ops/gemm.h"
#include "ctranslate2/ops/quantize.h"
#include "ctranslate2/ops/split.h"
#include "ctranslate2/storage_view.h"

namespace ctranslate2 {

  bool starts_with(const std::string& s, const std::string& prefix) {
    return s.compare(0, prefix.size(), prefix) == 0;
  }
  bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size()
      && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
  }
  bool string_to_bool(const std::string& s) {
    return s == "1" || s == "true" || s == "TRUE";
  }

  namespace ops {

    const float Quantize::global_int16_scale = 127.F;
Quantize::Quantize(const ScaleType t, const bool s, const bool r)
  : _int16_scale_type(t), _shift_to_uint8(s), _round_before_cast(r) {}
    void Quantize::operator()(const StorageView&, StorageView&, StorageView&) const {
      throw std::runtime_error("Quantize stub reached");
    }

    Dequantize::Dequantize(const ActivationType*) {}
    void Dequantize::operator()(const StorageView&, const StorageView&, StorageView&) const {
      throw std::runtime_error("Dequantize stub reached");
    }

    StorageView Gemm::pack_b_input(const StorageView&, const bool, const dim_t, const dim_t, const float) {
      throw std::runtime_error("Gemm::pack_b_input stub reached");
    }
    StorageView Gemm::compensate_u8_input(const StorageView&, const bool, const dim_t, const dim_t, const float) {
      throw std::runtime_error("Gemm::compensate_u8_input stub reached");
    }

    Split::Split(const dim_t, const std::vector<dim_t>&, const bool) {}
    void Split::operator()(const StorageView&, std::vector<StorageView*>&) const {
      throw std::runtime_error("Split stub reached");
    }

    Concat::Concat(const int) {}
    void Concat::operator()(const std::vector<const StorageView*>&, StorageView&) const {
      throw std::runtime_error("Concat stub reached");
    }

  }
  namespace cpu {
    bool cpu_supports_sse41() { return false; }
    bool cpu_supports_avx() { return false; }
    bool cpu_supports_avx2() { return false; }
    bool cpu_supports_avx512() { return false; }
  }
}
