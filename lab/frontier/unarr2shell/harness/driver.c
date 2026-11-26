/* unarr2shell — real public-API driver. Opens an attacker-supplied tar,
 * parses the first entry and asks unarr for its name. The USTAR prefix/name
 * concatenation in tar_get_name() is the sink under test.
 *
 * Usage: driver <tar-file>
 * Build: cc -fsanitize=address -g -O0 -I<tree> driver.c <libunarr.a> -o driver
 */
#include "unarr.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <tar-file>\n", argv[0]);
        return 2;
    }
    ar_stream *stream = ar_open_file(argv[1]);
    if (!stream) {
        fprintf(stderr, "open failed\n");
        return 3;
    }
    ar_archive *ar = ar_open_tar_archive(stream);
    if (!ar) {
        fprintf(stderr, "tar open failed\n");
        ar_close(stream);
        return 4;
    }
    if (!ar_parse_entry(ar)) {
        fprintf(stderr, "parse failed\n");
        ar_close_archive(ar);
        ar_close(stream);
        return 5;
    }
    const char *name = ar_entry_get_name(ar); /* tar_get_name() sink */
    printf("entry name: %s\n", name ? name : "(null)");
    ar_close_archive(ar);
    ar_close(stream);
    return 0;
}
