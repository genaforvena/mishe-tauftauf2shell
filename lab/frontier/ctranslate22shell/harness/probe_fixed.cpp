// Consumer stand-in around verbatim pins/model-fixed.cc:646-661.
#include "prelude.h"
#include "pinned_consume.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace ctranslate2;
using dim_t = int64_t;
static const size_t binary_version = 4;
enum class DataType { FLOAT = 0 };
static std::string name = "model.w";
static DataType get_dtype_from_item_size(uint8_t) { return DataType::FLOAT; }
struct Shape {
  std::vector<uint32_t> d;
  Shape(const uint32_t* b, const uint32_t* e) : d(b, e) {}
};
static char* g_marker = nullptr;
struct Region { char buf[16]; char marker[32]; };
struct StorageView {
  Shape shape;
  DataType dtype;
  char* buf = nullptr;
  Region* region = nullptr;
  StorageView(Shape s, DataType t) : shape(std::move(s)), dtype(t) {
#ifdef MISHE_ASAN
    buf = new char[16];
#else
    region = new Region;
    std::memset(region->buf, 0, 16);
    std::memset(region->marker, 0, 32);
    g_marker = region->marker;
    buf = region->buf;
#endif
  }
  ~StorageView() {
#ifdef MISHE_ASAN
    delete [] buf;
#endif
  }
  dim_t size() const { return 4; }
  dim_t item_size() const { return 4; }
  char* buffer() { return buf; }
};

static void append_u8(std::string& s, uint8_t v) { s.push_back(static_cast<char>(v)); }
static void append_u32(std::string& s, uint32_t v) {
  for (int i = 0; i < 4; ++i) append_u8(s, static_cast<uint8_t>(v >> (8 * i)));
}
static std::string make_model(uint32_t payload_size) {
  std::string s;
  append_u8(s, 2);
  append_u32(s, 2); append_u32(s, 2);
  append_u8(s, 0);
  append_u32(s, payload_size);
  const char pattern[] = "MISHE-CT2-OOB-WRITE";
  for (uint32_t i = 0; i < payload_size; ++i) append_u8(s, pattern[i % (sizeof(pattern) - 1)]);
  return s;
}

static void load_one(std::istream& model_file) {
        const size_t rank = consume<uint8_t>(model_file);
        const auto* dimensions = consume<uint32_t>(model_file, rank);
        Shape shape(dimensions, dimensions + rank);
        delete [] dimensions;

        DataType dtype;
        dim_t num_bytes = 0;
        if (binary_version >= 4) {
          const auto type_id = consume<uint8_t>(model_file);
          dtype = static_cast<DataType>(type_id);
          num_bytes = consume<uint32_t>(model_file);
        } else {
          const auto item_size = consume<uint8_t>(model_file);
          dtype = get_dtype_from_item_size(item_size);
          num_bytes = consume<uint32_t>(model_file) * item_size;
        }

        StorageView variable(std::move(shape), dtype);
        if (num_bytes != variable.size() * variable.item_size())
          throw std::runtime_error("Variable '" + name + "' has an invalid payload size");
        consume<char>(model_file, num_bytes, static_cast<char*>(variable.buffer()));
}

int main(int argc, char** argv) {
  uint32_t payload = argc > 1 ? static_cast<uint32_t>(std::stoul(argv[1])) : 17;
  std::istringstream in(make_model(payload));
  try {
    load_one(in);
  } catch (const std::exception& e) {
    std::cout << "rejected: " << e.what() << "\n";
    return 0;
  }
#ifndef __SANITIZE_ADDRESS__
  if (g_marker) {
    std::cout << "marker=";
    for (int i = 0; i < 16; ++i) {
      unsigned char c = static_cast<unsigned char>(g_marker[i]);
      if (c >= 0x20 && c < 0x7f) std::cout << static_cast<char>(c);
      else std::cout << '.';
    }
    std::cout << "\n";
  }
#endif
  std::cout << "clean\n";
  return 0;
}
