// SYNTHETIC mechanics harness — NOT the stock DragonflyDB binary.
// Mirrors the exact v1.40.1 source lines in src/facade/reply_builder.cc:
//   Flush(required): target_capacity = min(max(cap+required, cap*2), kMaxBufferSize=8192)
//   WritePieces: char* dest = buffer_.AppendBuffer().data();
//                char* ptr = dest;
//                (write_piece(pieces, ptr), ...);   // write_piece(string_view) = bare memcpy
//   MCReplyBuilder::SendValue: WritePieces("VALUE ", key, " ", mc_flag, " ", value.size())
// The 20000-byte key comes from the observed stock-binary trigger.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

int main() {
  constexpr size_t kMaxBufferSize = 8192;
  const std::string key(20000, 'k');
  const std::string_view value = "value";
  const uint32_t mc_flag = 0;

  // Flush(required) in the stock code clamps the scratch buffer to 8192.
  char* scratch = static_cast<char*>(malloc(kMaxBufferSize));
  if (!scratch) return 2;
  char* dest = scratch;  // AppendBuffer().data()

  // WritePieces("VALUE ", key, " ", mc_flag, " ", value.size())
  // write_piece(const char (&)[S], dest) -> memcpy(dest, arr, S-1)
  memcpy(dest, "VALUE ", 6); dest += 6;
  // write_piece(string_view, dest) -> memcpy(dest, str.data(), str.size()); NO BOUND
  memcpy(dest, key.data(), key.size()); dest += key.size();
  memcpy(dest, " ", 1); dest += 1;
  // FastIntToBuffer(mc_flag) writes at most kFastToBufferSize bytes; 0 needs 1.
  *dest++ = '0';
  memcpy(dest, " ", 1); dest += 1;
  *dest++ = '5';

  printf("wrote %zu bytes into an %zu-byte scratch\n", static_cast<size_t>(dest - scratch),
         kMaxBufferSize);
  free(scratch);
  return 0;
}
