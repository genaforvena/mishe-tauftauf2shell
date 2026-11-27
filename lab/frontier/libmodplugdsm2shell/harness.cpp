// Frontier harness: reads a local DSM file and calls the verbatim pinned
// CSoundFile::Create() -> ReadDSM(). No sockets, no external systems.
#include "stdafx.h"
#include "sndfile.h"
#include <fstream>
#include <iterator>
#include <vector>

int main(int argc, char **argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: harness FILE.dsm\n"); return 2; }
    std::printf("ARGV1=%s\n", argv[1]);
    std::ifstream f(argv[1], std::ios::in | std::ios::binary);
    f.seekg(0, std::ios::end);
    std::streamoff n = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<unsigned char> buf(n > 0 ? (size_t)n : 0);
    if (n > 0) f.read(reinterpret_cast<char *>(buf.data()), n);
    std::printf("BUFSIZE=%zu FIRST=%02x%02x%02x%02x\n", buf.size(),
                buf.size() > 3 ? buf[0] : 0, buf.size() > 3 ? buf[1] : 0,
                buf.size() > 3 ? buf[2] : 0, buf.size() > 3 ? buf[3] : 0);
    CSoundFile sf;
    BOOL ok = sf.ReadDSM(buf.data(), static_cast<DWORD>(buf.size()));
    std::printf("READDMS=%d TYPE=%u NCH=%u ORDER[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                (int)ok, (unsigned)sf.m_nType, (unsigned)sf.m_nChannels,
                sf.Order[0], sf.Order[1], sf.Order[2], sf.Order[3],
                sf.Order[4], sf.Order[5], sf.Order[6], sf.Order[7]);
    return 0;
}
