/* Lab-only headless shim: upstream test/testmixer.c source is not modified.
   The lab SDL3 build has no video backend, so mask SDL_INIT_VIDEO only. */
#include <SDL3/SDL.h>

bool SDLCALL testmixer_headless_Init(Uint32 flags)
{
    return SDL_Init(flags & ~SDL_INIT_VIDEO);
}
