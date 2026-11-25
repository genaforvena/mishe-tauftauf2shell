/* W206: real-consumer lane. Drive the crafted Vorbis file through SDL_mixer's
 * PUBLIC MIX_LoadAudio_IO() -> MIX decoder table -> vendored stb_vorbis v1.22.
 * The pinned stb_vorbis.c under lab/frontier/stbvorbis2shell/pinned/ is NOT
 * used here: the consumer's own vendored copy is the code under test.
 * A NULL result from MIX_LoadAudio_IO is a clean rejection, not a pass. */
#include <SDL3/SDL.h>
#include <SDL3_mixer/SDL_mixer.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s file.ogg [preload.ogg]\n", argv[0]);
        return 2;
    }
    MIX_Audio *preload = NULL;
    if (!SDL_Init(SDL_INIT_AUDIO)) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return 2;
    }
    if (!MIX_Init()) {
        fprintf(stderr, "MIX_Init failed: %s\n", SDL_GetError());
        return 2;
    }
    if (argc == 3) {
        SDL_IOStream *preio = SDL_IOFromFile(argv[2], "rb");
        if (!preio) {
            fprintf(stderr, "SDL_IOFromFile failed: %s\n", SDL_GetError());
            return 2;
        }
        preload = MIX_LoadAudio_IO(NULL, preio, 1, 1);
        fprintf(stderr, "MIX_PRELOAD=%p err=%s\n", (void *)preload, SDL_GetError());
        if (!preload) return 2;
    }
    SDL_IOStream *io = SDL_IOFromFile(argv[1], "rb");
    if (!io) {
        fprintf(stderr, "SDL_IOFromFile failed: %s\n", SDL_GetError());
        return 2;
    }
    /* predecode=true forces decoding during LoadAudio, which exercises
     * stb_vorbis_open_io() and the setup parse in the caller's own path. */
    MIX_Audio *audio = MIX_LoadAudio_IO(NULL, io, 1, 1);
    fprintf(stderr, "MIX_LoadAudio_IO=%p err=%s\n", (void *)audio, SDL_GetError());
    if (audio) MIX_DestroyAudio(audio);
    if (preload) MIX_DestroyAudio(preload);
    MIX_Quit();
    SDL_Quit();
    return 0;
}
