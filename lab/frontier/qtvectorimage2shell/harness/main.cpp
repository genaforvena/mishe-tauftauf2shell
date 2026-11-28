// Drive the verbatim pinned index-copy block from triangulateFill().
// Usage: qtindex <vuln|fixed> <heap|slab> <ushort|uint> <count> <last-index>
#include "shim.h"
#include <cstdio>
#include <cstdlib>

bool g_slab_mode = false;
alignas(16) unsigned char g_slab[200000];
std::size_t g_slab_used = 0;

static void copy_indices(const QTriangleSet &ts, QList<quint32> *fillIndices,
                         QSGGeometry::Type *indexType) {
#include "block.inc"
}

int main(int argc, char **argv) {
    if (argc != 6)
        return 2;
    const char *arm = argv[1];
    const char *layout = argv[2];
    const char *type = argv[3];
    const int count = std::atoi(argv[4]);
    const unsigned long last = std::strtoul(argv[5], nullptr, 0);
    if (count < 1 || count > 65535 || last > 65535)
        return 2;
    if (std::strcmp(arm, "vuln") && std::strcmp(arm, "fixed"))
        return 2;
    if (std::strcmp(layout, "heap") && std::strcmp(layout, "slab"))
        return 2;
    if (std::strcmp(type, "ushort") && std::strcmp(type, "uint"))
        return 2;

    g_slab_mode = std::strcmp(layout, "slab") == 0;
    g_slab_used = 0;
    std::memset(g_slab, 0xbeef, sizeof(g_slab));
    QTriangleSet ts;
    if (!std::strcmp(type, "ushort")) {
        ts.indices.t = QVertexIndexVector::UnsignedShort;
        ts.indices.indices16.resize(count);
        for (int i = 0; i < count; ++i)
            ts.indices.indices16[i] = static_cast<quint16>(i);
        ts.indices.indices16.back() = static_cast<quint16>(last);
    } else {
        ts.indices.t = QVertexIndexVector::UnsignedInt;
        ts.indices.indices32.resize(count);
        for (int i = 0; i < count; ++i)
            ts.indices.indices32[i] = static_cast<quint32>(i);
        ts.indices.indices32.back() = static_cast<quint32>(last);
    }

    QList<quint32> fillIndices;
    QSGGeometry::Type indexType = QSGGeometry::UnsignedIntType;
    std::printf("QTINDEX arm=%s layout=%s type=%s count=%d last=0x%lx\n",
                arm, layout, type, count, last);
    std::fflush(stdout);
    copy_indices(ts, &fillIndices, &indexType);
    std::printf("RETURN slots=%zu index_type=%d", fillIndices.size(),
                static_cast<int>(indexType));
    if (g_slab_mode) {
        auto *victim = reinterpret_cast<quint16 *>(
            reinterpret_cast<unsigned char *>(fillIndices.data()) +
            fillIndices.size() * sizeof(quint32));
        std::printf(" victim=0x%04x", *victim);
    }
    std::printf("\n");
    return 0;
}
