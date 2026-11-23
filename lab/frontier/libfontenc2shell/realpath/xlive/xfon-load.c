/* Open one font by XLFD on a loopback X display; forces the X server's
 * font backend to resolve the encoding charset through libfontenc. */
#include <stdio.h>
#include <stdlib.h>
#include <X11/Xlib.h>

int
main(int argc, char **argv)
{
    Display *d;
    XFontStruct *f;
    const char *name = (argc > 2) ? argv[2] :
        "-misc-fixed-medium-r-semicondensed--13-120-75-75-c-60-crafted-1";

    d = XOpenDisplay(argv[1]);
    if (d == NULL) {
        fprintf(stderr, "XOpenDisplay failed\n");
        return 2;
    }
    f = XLoadQueryFont(d, name);
    printf("XLoadQueryFont(%s)=%p\n", name, (void *)f);
    fflush(stdout);
    if (f != NULL)
        XFreeFont(d, f);
    XCloseDisplay(d);
    return f ? 0 : 1;
}
