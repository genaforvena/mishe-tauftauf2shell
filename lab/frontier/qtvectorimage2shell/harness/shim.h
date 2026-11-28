#pragma once
// Minimal host stand-ins for the types used by the pinned index-copy block.
// This is not Qt and does not render SVG. FakeArrayData models QArrayData's
// header-plus-exact-capacity allocation; slab mode places a victim immediately
// after the logical data end for chosen-byte readback.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

using quint16 = std::uint16_t;
using quint32 = std::uint32_t;

#define Q_ASSERT(expr) do { if (!(expr)) std::abort(); } while (0)

struct QSGGeometry {
    enum Type { UnsignedShortType, UnsignedIntType };
};

struct FakeArrayData {
    std::uint32_t ref = 1;
    std::size_t size = 0;
    std::size_t allocated = 0;
    std::size_t offset = 0;
};

extern bool g_slab_mode;
extern unsigned char g_slab[];
extern std::size_t g_slab_used;

template <typename T>
class QList {
public:
    QList() = default;
    QList(const QList &) = delete;
    QList &operator=(const QList &) = delete;
    ~QList() { release(); }

    void resize(std::size_t n) {
        release();
        m_size = n;
        if (g_slab_mode) {
            if (g_slab_used + sizeof(FakeArrayData) + n * sizeof(T) > 200000)
                std::abort();
            auto *h = reinterpret_cast<FakeArrayData *>(g_slab + g_slab_used);
            h->ref = 1;
            h->size = n;
            h->allocated = n;
            h->offset = 0;
            m_data = reinterpret_cast<T *>(h + 1);
            m_heap = false;
            g_slab_used += sizeof(FakeArrayData) + n * sizeof(T);
        } else {
            auto *h = static_cast<FakeArrayData *>(
                std::malloc(sizeof(FakeArrayData) + n * sizeof(T)));
            if (!h)
                std::abort();
            h->ref = 1;
            h->size = n;
            h->allocated = n;
            h->offset = 0;
            m_data = reinterpret_cast<T *>(h + 1);
            m_heap = true;
        }
    }

    T *data() { return m_data; }
    const T *data() const { return m_data; }
    std::size_t size() const { return m_size; }

private:
    void release() {
        if (m_heap && m_data)
            std::free(reinterpret_cast<FakeArrayData *>(m_data) - 1);
        m_data = nullptr;
        m_heap = false;
        m_size = 0;
    }

    T *m_data = nullptr;
    std::size_t m_size = 0;
    bool m_heap = false;
};

struct QVertexIndexVector {
    enum Type { UnsignedInt, UnsignedShort };
    Type t = UnsignedShort;
    std::vector<quint16> indices16;
    std::vector<quint32> indices32;

    Type type() const { return t; }
    const void *data() const {
        return t == UnsignedInt ? static_cast<const void *>(indices32.data())
                                : static_cast<const void *>(indices16.data());
    }
    int size() const {
        return static_cast<int>(t == UnsignedInt ? indices32.size() : indices16.size());
    }
};

struct QTriangleSet {
    QVertexIndexVector indices;
};
