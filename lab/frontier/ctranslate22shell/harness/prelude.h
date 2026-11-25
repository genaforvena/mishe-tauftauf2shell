// Stand-ins for the model-loader consumer. The upstream functions under test
// are pinned verbatim in pinned_consume.h and in the two probe sources.
#pragma once
#include <cstdint>
#include <string>
namespace ctranslate2 {
  static std::string binary_file = "crafted.bin";
}
