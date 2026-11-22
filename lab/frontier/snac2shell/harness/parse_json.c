/* Real snac2 single-header JSON parser harness for CVE-2026-112021.
 * Compiled against the pinned xs.h / xs_json.h of tag 2.92 (vuln) and
 * tag 2.93 (fixed). The input file is the exact JSON bytes a pre-auth
 * POST hands to xs_json_loads() in activitypub_post_handler().
 */
#define XS_IMPLEMENTATION
#include "xs.h"
#include "xs_json.h"

int main(int argc, char **argv)
{
    FILE *f;
    xs_val *root;

    if (argc != 2)
        return 2;
    f = fopen(argv[1], "rb");
    if (!f)
        return 3;
    root = xs_json_load(f);
    fclose(f);
    printf("parsed=%p\n", (void *)root);
    if (root)
        xs_free(root);
    return 0;
}
