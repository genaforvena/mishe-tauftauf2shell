/* Wire-triggered stale status buffer, reclaimed by the next public operation.
 *
 * Public APIs only. Operation 1 is a real gpg verify whose public key is
 * auto-retrieved from the loopback HKP server; the deliberately long
 * [GNUPG:] IMPORTED line makes the status callback error on the pinned
 * early-return path before pointer writeback. Operation 2 is a keylist on
 * the SAME context. Whether the stale block is reclaimed there or only at
 * gpgme_release is the measured question; no r5 claim.
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
  fprintf (stderr,
           "status_cb call=%d keyword=%s arglen=%zu byte[1000]=0x%02x\n",
           cb_calls, keyword, strlen (args),
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
  gpgme_data_t sig = NULL;
  gpgme_error_t err;
  const char *version;

  if (argc != 4)
    {
      fprintf (stderr, "usage: %s GPG_PATH SIGNED_FILE GNUPGHOME\n", argv[0]);
      return 2;
    }
  version = gpgme_check_version (NULL);
  if (!version)
    return 2;
  fprintf (stderr, "gpgme version=%s\n", version);
  err = gpgme_set_engine_info (GPGME_PROTOCOL_OpenPGP, argv[1], argv[3]);
  if (err)
    {
      fprintf (stderr, "set_engine_info failed: %s\n", gpgme_strerror (err));
      return 2;
    }
  err = gpgme_new (&ctx);
  if (err)
    return 2;
  gpgme_set_ctx_flag (ctx, "full-status", "1");
  gpgme_set_status_cb (ctx, failing_status_cb, NULL);
  err = gpgme_data_new_from_file (&sig, argv[2], 1);
  if (err)
    return 2;

  /* Operation 1: long wire-derived status line, callback error.  */
  err = gpgme_op_verify (ctx, sig, NULL, NULL);
  fprintf (stderr, "op1 verify err=%s cb_calls=%d\n",
           gpgme_strerror (err), cb_calls);
  gpgme_data_release (sig);

  /* Operation 2: short-line keylist on the same context.  */
  do_keylist (ctx, 2);

  gpgme_release (ctx);
  puts ("release done");
  return 0;
}
