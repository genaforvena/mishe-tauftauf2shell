// Pinned-sink harness: calls the unmodified static procheader() from the
// pinned lrz.c with a sender-chosen filename. The ZMODEM file header supplies
// name_static in the live receiver; here the same bytes are supplied directly
// to isolate the malloc(PATH_MAX*2)/strcpy sink.
#define main lrz_unused_main
#include "lrz.c"
#undef main

int main(int argc, char **argv)
{
  size_t len = argc > 1 ? (size_t)strtoul(argv[1], NULL, 10) : 12000;
  int fill = argc > 2 ? atoi(argv[2]) : 0x43;
  struct zm_fileinfo zi;
  protocol = ZM_ZMODEM;
  memset(&zi, 0, sizeof(zi));
  char *name = malloc(len + 64);
  if (!name) return 2;
  memset(name, 0, len + 64);
  memset(name, fill, len);
  name[len] = 0;
  int rc = procheader(name, &zi);
  printf("rc=%d Pathname_len=%zu\n", rc, Pathname ? strlen(Pathname) : 0);
  return rc == OK ? 0 : 1;
}
