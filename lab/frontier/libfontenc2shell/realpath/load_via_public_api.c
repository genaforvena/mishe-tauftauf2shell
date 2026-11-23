/*
 * libfontenc2shell: exercise the public library API, not a direct call to the
 * static parser.  FontEncFind() is the exported entry point used by the X
 * server's font backends; it calls static FontEncLoad() -> FontEncReallyLoad()
 * in src/fontenc.c, which reads encodings.dir and calls parseEncodingFile().
 *
 * Build against a verbatim upstream build tree at a pinned commit.  The
 * FONT_ENCODINGS_DIRECTORY environment variable selects a temporary font path
 * holding encodings.dir plus a crafted .enc file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <X11/fonts/fontenc.h>

int
main(int argc, char **argv)
{
    const char *charset = (argc > 1) ? argv[1] : "crafted";
    const char *envdir = getenv("FONT_ENCODINGS_DIRECTORY");
    FontEncPtr enc;
    const char *filename = (argc > 2) ? argv[2] : NULL;

    printf("PUBLIC-API-DRIVER charset=%s filename=%s envdir=%s dir=%s\n",
           charset, filename ? filename : "(null)",
           envdir ? envdir : "(null)", FontEncDirectory());
    fflush(stdout);

    enc = FontEncFind(charset, filename);

    printf("FontEncFind=%p\n", (void *)enc);
    if (enc != NULL) {
        printf("name=%s size=%d row_size=%d mappings=%p\n",
               enc->name, enc->size, enc->row_size, (void *)enc->mappings);
        printf("map_type=%d first_col=%d\n",
               enc->mappings ? enc->mappings->type : -1, enc->first_col);
        fflush(stdout);
    }
    return enc ? 0 : 1;
}
