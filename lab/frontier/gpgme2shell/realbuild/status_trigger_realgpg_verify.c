/* Real GPGME + real gpg verify with loopback HKP auto-key-retrieve.
 *
 * Public APIs only. The attacker-controlled wire response supplies the key
 * whose long UID makes gpg emit a >1024-byte [GNUPG:] IMPORTED status line;
 * the failing status callback takes the pinned early return before writeback.
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
  if (strlen (args) > 500)
    return gpg_error (GPG_ERR_GENERAL);
  return 0;
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
    {
      fprintf (stderr, "gpgme_new failed: %s\n", gpgme_strerror (err));
      return 2;
    }
  gpgme_set_ctx_flag (ctx, "full-status", "1");
  gpgme_set_status_cb (ctx, failing_status_cb, NULL);
  err = gpgme_data_new_from_file (&sig, argv[2], 1);
  if (err)
    {
      fprintf (stderr, "data_new_from_file failed: %s\n", gpgme_strerror (err));
      return 2;
    }
  err = gpgme_op_verify (ctx, sig, NULL, NULL);
  fprintf (stderr, "verify err=%s cb_calls=%d\n",
           gpgme_strerror (err), cb_calls);
  gpgme_data_release (sig);
  gpgme_release (ctx);
  puts ("release done");
  return 0;
}
