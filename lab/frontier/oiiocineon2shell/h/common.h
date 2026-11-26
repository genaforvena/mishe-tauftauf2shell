// Frontier-authored scaffolding. The sink functions themselves are generated
// from verbatim pinned cineoninput.cpp lines by gen_sink.py.
#pragma once
#include "libcineon/Cineon.h"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

struct FakeHeader {
    int n;
    int NumberOfElements() const { return n; }
    cineon::Descriptor ImageDescriptor(int) const {
        return cineon::kUndefinedDescriptor;
    }
};
struct FakeReader {
    FakeHeader header;
};
extern FakeReader m_cin;

static char* get_descriptor_string(cineon::Descriptor) {
    return const_cast<char*>("Undefined");
}
static void errorfmt(const char*, ...) {}
static void close() {}

extern "C" bool open_like();
