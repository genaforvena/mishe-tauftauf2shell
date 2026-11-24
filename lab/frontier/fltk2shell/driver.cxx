#include <FL/Fl_BMP_Image.H>
#include <FL/Fl.H>
#include <stdio.h>

// Constructs the image exactly as a consumer would: the constructor is the
// vulnerable path, per FLTK issue #1647.
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  Fl_BMP_Image img(argv[1]);
  printf("RESULT fail=%d w=%d h=%d d=%d\n", img.fail(), img.w(), img.h(), img.d());
  return 0;
}
