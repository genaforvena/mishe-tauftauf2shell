// Real X11 FLTK GUI consumer: open a window, draw a safe image, then load a
// second file through the standard Fl_Shared_Image::get() application API
// while the window is live.  No synthetic loader/consumer: all image decoding
// and drawing happens inside the pinned FLTK 1.4.5 libraries.
#include <FL/Fl.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Shared_Image.H>
#include <FL/Fl_BMP_Image.H>
#include <cstdio>

static int draw_count = 0;
class CountingBox : public Fl_Box {
public:
  CountingBox(int x, int y, int w, int h) : Fl_Box(x, y, w, h) {}
  void draw() override {
    ++draw_count;
    Fl_Box::draw();
  }
};

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s safe.bmp [second-file]\n", argv[0]);
    return 2;
  }
  fl_register_images();
  Fl_Shared_Image *safe = Fl_Shared_Image::get(argv[1]);
  if (!safe) {
    printf("GUI RESULT safe=NULL file=%s\n", argv[1]);
    return 3;
  }
  Fl_Double_Window win(320, 240, "fltk2shell GUI consumer");
  CountingBox box(10, 10, 300, 200);
  box.image(safe);
  win.end();
  win.show();
  Fl::flush();
  for (int i = 0; i < 5; ++i) Fl::wait(0.05);
  printf("GUI RESULT shown draw_count=%d safe=%dx%d depth=%d\n",
         draw_count, safe->w(), safe->h(), safe->d());
  fflush(stdout);

  if (argc == 3) {
    // Application-level image load with a real display and window alive.
    Fl_Shared_Image *second = Fl_Shared_Image::get(argv[2]);
    printf("GUI RESULT second file=%s image=%p\n", argv[2], (void *)second);
    fflush(stdout);
    if (second) second->release();
  }
  safe->release();
  return 0;
}
