// Minimal headless FLTK-style consumer used to probe image-loading APIs.
// No display is opened: only the loader/constructor path is exercised.
#include <FL/Fl.H>
#include <FL/Fl_Shared_Image.H>
#include <FL/Fl_BMP_Image.H>
#include <FL/Fl_ICO_Image.H>
#include <cstdio>
#include <cstring>

static void report(const char *api, const char *file, int fail, int w, int h, int d) {
  printf("%s RESULT file=%s fail=%d w=%d h=%d d=%d\n", api, file, fail, w, h, d);
  fflush(stdout);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <shared|ico|direct> <image-file>\n", argv[0]);
    return 2;
  }
  const char *mode = argv[1];
  const char *file = argv[2];

  if (!strcmp(mode, "shared")) {
    // The normal application startup sequence: register extra formats,
    // then load a user-supplied file through the shared-image cache.
    fl_register_images();
    Fl_Shared_Image *img = Fl_Shared_Image::get(file);
    if (!img) {
      printf("SHARED RESULT file=%s get=NULL\n", file);
      fflush(stdout);
      return 0;
    }
    printf("SHARED RESULT file=%s w=%d h=%d d=%d image=%p\n",
           file, img->w(), img->h(), img->d(), (void *)img->image());
    fflush(stdout);
    img->release();
  } else if (!strcmp(mode, "ico")) {
    Fl_ICO_Image img(file);
    report("ICO", file, img.fail(), img.w(), img.h(), img.d());
  } else if (!strcmp(mode, "direct")) {
    Fl_BMP_Image img(file);
    report("DIRECT", file, img.fail(), img.w(), img.h(), img.d());
  } else {
    fprintf(stderr, "unknown mode: %s\n", mode);
    return 2;
  }
  return 0;
}
