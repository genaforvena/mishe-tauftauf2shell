/*
 * Real SDL_mixer 3.2.4 API driver for crafted RIFF/WAVE files.
 * Modes:
 *   decode : MIX_CreateAudioDecoder(path) + MIX_DecodeAudio() on the main thread
 *   play   : dummy audio device + MIX_CreateMixerDevice/MIX_LoadAudio/MIX_PlayTrack
 */
#include <SDL3/SDL.h>
#include <SDL3_mixer/SDL_mixer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : NULL;
    const char *mode = (argc > 2) ? argv[2] : "decode";
    if (!path) {
        fprintf(stderr, "usage: %s WAVFILE [decode|play]\n", argv[0]);
        return 2;
    }

    SDL_SetHint(SDL_HINT_AUDIO_DRIVER, "dummy");
    if (!SDL_Init(SDL_INIT_AUDIO)) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return 2;
    }
    if (!MIX_Init()) {
        fprintf(stderr, "MIX_Init failed: %s\n", SDL_GetError());
        return 2;
    }
    printf("MODE=%s PATH=%s AUDIO_DRIVER=%s MIX_DECODERS=%d\n",
           mode, path, SDL_GetCurrentAudioDriver() ? SDL_GetCurrentAudioDriver() : "(null)",
           MIX_GetNumAudioDecoders());
    fflush(stdout);

    if (strcmp(mode, "decode") == 0) {
        MIX_AudioDecoder *dec = MIX_CreateAudioDecoder(path, 0);
        if (!dec) {
            printf("RESULT=LOAD_ERROR ERROR=%s\n", SDL_GetError());
            fflush(stdout);
            MIX_Quit();
            SDL_Quit();
            return 1;
        }
        SDL_AudioSpec spec;
        if (!MIX_GetAudioDecoderFormat(dec, &spec)) {
            printf("RESULT=SPEC_ERROR ERROR=%s\n", SDL_GetError());
            MIX_DestroyAudioDecoder(dec);
            MIX_Quit();
            SDL_Quit();
            return 1;
        }
        printf("SPEC freq=%d format=%u channels=%d framesize=%d\n",
               spec.freq, (unsigned) spec.format, spec.channels, SDL_AUDIO_FRAMESIZE(spec));
        fflush(stdout);

        static unsigned char out[4096];
        int total = 0;
        for (int round = 0; round < 4; round++) {
            int got = MIX_DecodeAudio(dec, out, (int) sizeof(out), &spec);
            printf("DECODE round=%d got=%d\n", round, got);
            fflush(stdout);
            if (got <= 0) {
                break;
            }
            total += got;
        }
        printf("RESULT=OK total=%d\n", total);
        MIX_DestroyAudioDecoder(dec);
    } else if (strcmp(mode, "play") == 0) {
        MIX_Mixer *mixer = MIX_CreateMixerDevice(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, NULL);
        if (!mixer) {
            printf("RESULT=MIXER_ERROR ERROR=%s\n", SDL_GetError());
            MIX_Quit();
            SDL_Quit();
            return 1;
        }
        MIX_Audio *audio = MIX_LoadAudio(mixer, path, false);
        if (!audio) {
            printf("RESULT=LOAD_ERROR ERROR=%s\n", SDL_GetError());
            MIX_DestroyMixer(mixer);
            MIX_Quit();
            SDL_Quit();
            return 1;
        }
        MIX_Track *track = MIX_CreateTrack(mixer);
        if (!track || !MIX_SetTrackAudio(track, audio)) {
            printf("RESULT=TRACK_ERROR ERROR=%s\n", SDL_GetError());
            MIX_DestroyMixer(mixer);
            MIX_Quit();
            SDL_Quit();
            return 1;
        }
        bool playing = MIX_PlayTrack(track, 0);
        printf("PLAY started=%d\n", playing ? 1 : 0);
        fflush(stdout);
        SDL_Delay(300);
        printf("RESULT=OK still_playing=%d\n", MIX_TrackPlaying(track) ? 1 : 0);
        MIX_DestroyMixer(mixer);
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        MIX_Quit();
        SDL_Quit();
        return 2;
    }

    MIX_Quit();
    SDL_Quit();
    return 0;
}
