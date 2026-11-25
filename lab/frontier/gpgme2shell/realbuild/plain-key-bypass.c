/* Standalone glibc 2.39 mechanics probe for CVE-2026-129975 (W13).
 *
 * Models the plain-glibc free order in gpgme 2.2.0:
 *   realloc() frees the 0x410 status buffer into tcache (read_status:1494);
 *   an attacker-sized strdup(rest) reclaims that chunk (engine-gpg.c:1564)
 *   and overwrites its tcache key with chosen bytes;
 *   gpg_release frees status.buffer (:602), then cmd.keyword (:607-608),
 *   with no allocation in between. A guard allocation forces realloc to move.
 *
 * CASE=key:   that order (expect glibc abort on the second free).
 * CASE=drain: one held malloc of the stale size between the two frees (the
 *             W8 lab-callback alias shape; expect a silent double free).
 * CASE=full:  tcache 0x410 bin full before the first free (W10 shape).
 *
 * No GPGME, no network, no sanitizer: allocator mechanics only. Rung-4
 * mechanics, not a live path, a chosen-address write, or an RCE claim.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (void)
{
  const char *case_name = getenv ("CASE");
  char *stale, *old, *guard, *grown, *alias, *held;
  char *full[7];
  int i;

  if (!case_name)
    case_name = "key";

  stale = malloc (1024);
  if (!stale)
    return 2;
  memset (stale, 'H', 1024);
  old = stale;
  guard = malloc (64); /* blocks in-place growth */
  if (!guard)
    return 2;

  if (!strcmp (case_name, "full"))
    for (i = 0; i < 7; i++)
      {
        full[i] = malloc (1024);
        if (!full[i])
          return 2;
      }
  if (!strcmp (case_name, "full"))
    for (i = 0; i < 7; i++)
      free (full[i]);

  grown = realloc (stale, 2048);
  if (!grown)
    return 2;
  printf ("case=%s old=%p grown=%p moved=%d\n", case_name, (void *) old,
          (void *) grown, old != grown);
  fflush (stdout);

  /* GPGME-internal strdup(rest): attacker bytes at chunk offsets 0..15. */
  alias = malloc (1024);
  if (!alias)
    return 2;
  memset (alias, 'A', 1024);
  printf ("alias=%p first16=%.16s\n", (void *) alias, alias);
  fflush (stdout);

  /* gpg_release:602 -- stale status.buffer free. */
  free (old);
  printf ("first free done\n");
  fflush (stdout);

  if (!strcmp (case_name, "drain"))
    {
      held = malloc (1024);
      if (!held)
        return 2;
      memset (held, 'A', 1024);
      printf ("held=%p (not freed)\n", (void *) held);
      fflush (stdout);
    }

  /* gpg_release:607-608 -- cmd.keyword free. */
  free (alias);
  printf ("second free done\n");
  fflush (stdout);
  free (grown);
  free (guard);
  return 0;
}
