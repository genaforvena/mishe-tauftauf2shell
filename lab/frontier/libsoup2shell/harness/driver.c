/* Lab-only driver: calls the verbatim libsoup soup_uri_decode_data_uri()
 * and reads every byte of the returned GBytes so an out-of-bounds length
 * becomes an observed ASan READ. No socket, request or command path. */
#include <glib.h>
#include <stdio.h>
#include <string.h>

GBytes *soup_uri_decode_data_uri (const char *uri, char **content_type);

/* Only needed to link the verbatim source; unrelated to the decoder. */
guint soup_str_case_hash (gconstpointer key) { return g_str_hash (key); }

static void probe_one (const char *uri)
{
        char *ctype = NULL;
        GBytes *bytes = soup_uri_decode_data_uri (uri, &ctype);
        printf ("URI=%s\n", uri);
        if (!bytes) {
                printf ("  RESULT=NULL ctype=%s\n", ctype ? ctype : "(null)");
                g_free (ctype);
                return;
        }
        gsize n = g_bytes_get_size (bytes);
        printf ("  RESULT=bytes size=%zu ctype=%s\n", n, ctype ? ctype : "(null)");
        const guchar *p = g_bytes_get_data (bytes, NULL);
        gsize sum = 0;
        for (gsize i = 0; i < n; i++)
                sum += p[i];
        printf ("  READ_OK bytes=%zu sum=%zu\n", n, sum);
        g_bytes_unref (bytes);
        g_free (ctype);
}

int main (int argc, char **argv)
{
        if (argc > 1 && !strcmp (argv[1], "glib-probe")) {
                char text[] = "A\0B";
                gsize out = 0x4141414141414141ULL;
                char *r = g_base64_decode_inplace (text, &out);
                printf ("glib_base64_decode_inplace out=%zu r=%p text0=%02x\n",
                        out, (void *)r, (unsigned char)text[0]);
                return 0;
        }
        if (argc > 1 && !strcmp (argv[1], "safe")) {
                probe_one ("data:,hello");
                probe_one ("data:;base64,aGVsbG8=");
                return 0;
        }
        if (argc > 1 && !strcmp (argv[1], "groom")) {
                gsize n = argc > 2 ? (gsize) g_ascii_strtoull (argv[2], NULL, 10) : 1024;
                guchar *src = g_malloc0 (n);
                gchar *b64 = g_base64_encode (src, n);
                char *uri = g_strdup_printf ("data:;base64,%s", b64);
                probe_one (uri);
                probe_one ("data:;base64,A%00B");
                g_free (uri);
                g_free (b64);
                g_free (src);
                return 0;
        }
        const char *vectors[] = {
                "data:;base64,%00%00%00",
                "data:;base64,aGVs%00bG8=",
                "data:;base64,A%00B",
                "data:;base64,aGVsbG8=",
                "data:,hello",
        };
        for (guint i = 0; i < G_N_ELEMENTS (vectors); i++)
                probe_one (vectors[i]);
        return 0;
}
