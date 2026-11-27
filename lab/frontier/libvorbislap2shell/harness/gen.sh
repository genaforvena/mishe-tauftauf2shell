#!/bin/sh
# Generate a C driver whose body is the verbatim pinned _ov_getlap() tail.
# Usage: sh harness/gen.sh <pinned-source-dir> <output-c-file>
set -eu
src=$1
out=$2
line=$(grep -n 'failed to get lapping data' "$src/lib/vorbisfile.c" | cut -d: -f1)
start=$((line - 1))
end=$((line + 14))
mkdir -p "$(dirname "$out")"
{
cat <<'EOF'
/* Generated: pinned sink body, stand-in surrounding types only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

typedef struct { int channels; } vi_stub;
typedef struct { int unused; } vd_stub;
typedef struct { vd_stub vd; } vf_stub;

static float *g_src;
static int g_samples;

static int vorbis_synthesis_lapout(vd_stub *vd, float ***pcm)
{
    (void)vd;
    *pcm = &g_src;
    return g_samples;
}

int main(int argc, char **argv)
{
    int i;
    int lapcount = 8;
    const int lapsize = 64;
    float **lappcm = alloca(sizeof(*lappcm) * 2);
    float *buf0 = alloca(sizeof(**lappcm) * lapsize);
    float *buf1 = alloca(sizeof(**lappcm) * lapsize);
    vi_stub vi_local;
    vf_stub vf_local;
    vi_stub *vi = &vi_local;
    vf_stub *vf = &vf_local;
    float **pcm = NULL;

    if (argc != 2) return 2;
    g_samples = atoi(argv[1]);
    for (i = 0; i < lapsize; i++) { buf0[i] = 0x43; buf1[i] = 0x43; }
    g_src = buf1;
    lappcm[0] = buf0;
    vi->channels = 1;
EOF
printf '#line %d "%s/lib/vorbisfile.c"\n' "$start" "$src"
awk -v s="$start" -v e="$end" 'NR>=s && NR<=e' "$src/lib/vorbisfile.c"
printf '#line %d "generated.c"\n' $((end + 2))
cat <<'EOF'
    printf("RETURN lapcount=%d\n", lapcount);
    return 0;
}
EOF
} > "$out"
