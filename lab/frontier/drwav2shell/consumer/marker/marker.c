/* Lab-only benign marker for drwav2shell rung-4 control-flow mechanics.
 *
 * Built as a shared object with -Wl,-Ttext-segment=0x50000000 so both entry
 * points have fixed addresses below 4 GiB and can be named by the crafted
 * WAV's file-controlled u32 fields. This is a lab mechanism, NOT an attacker
 * capability: an LD_PRELOAD is needed to load it, and no remote command or
 * shell is involved. The consumer source and pinned dr_wav.h are untouched.
 */
#include <stdio.h>

void drwav_marker(void *p)
{
    FILE *f;
    (void)p;
    f = fopen("/tmp/drwav-marker/hit", "w");
    if (f) {
        fputs("drwav-marker\n", f);
        fclose(f);
    }
}

int drwav_noop(void *p, long a, long b)
{
    (void)p;
    (void)a;
    (void)b;
    return 0;
}
