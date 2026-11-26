#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <speex/speex_bits.h>

/* Exercise the public API with valid caller-owned and library-owned buffers. */
int main(int argc, char **argv)
{
    SpeexBits bits;
    unsigned char input[2048], storage[64];
    unsigned char *buffer = storage;
    const char *mode = argc > 1 ? argv[1] : "partial";
    int exact = argc > 2 && !strcmp(argv[2], "exact");
    int initial = 8, append = 16, capacity = 16, consumed = 0;
    int owned = !strcmp(mode, "owned") || !strcmp(mode, "owned-grow");
    int bad = 0;
    memset(input, 0x42, sizeof input);
    memset(storage, 0xa5, sizeof storage);
    if (!strcmp(mode, "empty")) initial = 0;
    if (!strcmp(mode, "fits")) append = 4;
    if (!strcmp(mode, "full")) initial = 16;
    if (!strcmp(mode, "consumed")) { initial = 16; consumed = 4; }
    if (!strcmp(mode, "unaligned")) initial = 0;
    if (!strcmp(mode, "one")) { capacity = 1; initial = 1; append = 1; }
    if (exact) {
        buffer = malloc(capacity);
        if (!buffer) return 2;
        memset(buffer, 0xa5, capacity);
    }
    if (!strcmp(mode, "owned-grow")) initial = 2000;
    if (owned) {
        speex_bits_init(&bits);
        capacity = bits.buf_size;
        speex_bits_read_from(&bits, (const char *)input, initial);
    } else if (!strcmp(mode, "full") || !strcmp(mode, "one") || consumed) {
        speex_bits_set_bit_buffer(&bits, buffer, capacity);
    } else {
        speex_bits_init_buffer(&bits, buffer, capacity);
        if (initial) speex_bits_read_from(&bits, (const char *)input, initial);
    }
    if (!strcmp(mode, "unaligned")) speex_bits_pack(&bits, 5, 3);
    for (int i = 0; i < consumed; i++) speex_bits_unpack_unsigned(&bits, 8);
    int before = bits.nbBits;
    speex_bits_read_whole_bytes(&bits, (const char *)input, append);
    if (!owned && !exact) {
        for (int i = capacity; i < (int)sizeof storage; i++) {
            if (storage[i] != 0xa5) bad++;
        }
    }
    printf("case=%s before=%d consumed=%d after=%d capacity=%d overwritten=%d\n",
           mode, before, consumed, bits.nbBits, bits.buf_size, bad);
    int failed = bad || bits.nbBits < before - consumed * 8 ||
                 bits.nbBits < 0 || bits.nbBits > bits.buf_size * 8;
    speex_bits_destroy(&bits);
    if (exact) free(buffer);
    return failed ? 1 : 0;
}
