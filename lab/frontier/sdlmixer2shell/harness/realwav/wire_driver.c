/*
 * Loopback-wire input for the real SDL_mixer 3.2.4 WAV decoder.
 * Binds 127.0.0.1:PORT, accepts one connection, reads the WAV bytes from the
 * socket (no file path), wraps them in an SDL_IOStream and feeds the real
 * MIX_CreateAudioDecoder_IO / MIX_DecodeAudio (decode) or MIX_LoadAudio_IO /
 * MIX_PlayTrack (play) API. Bind is loopback-only by construction.
 */
#include <SDL3/SDL.h>
#include <SDL3_mixer/SDL_mixer.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s PORT [decode|play]\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);
    const char *mode = (argc > 2) ? argv[2] : "decode";
    if (port < 1 || port > 65535) return 2;

    SDL_SetHint(SDL_HINT_AUDIO_DRIVER, "dummy");
    if (!SDL_Init(SDL_INIT_AUDIO)) {
        fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return 2;
    }
    if (!MIX_Init()) {
        fprintf(stderr, "MIX_Init failed: %s\n", SDL_GetError());
        return 2;
    }
    printf("MODE=%s AUDIO_DRIVER=%s MIX_DECODERS=%d\n", mode,
           SDL_GetCurrentAudioDriver() ? SDL_GetCurrentAudioDriver() : "(null)",
           MIX_GetNumAudioDecoders());
    fflush(stdout);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 2; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t) port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) { perror("bind"); return 2; }
    if (listen(fd, 1) < 0) { perror("listen"); return 2; }
    printf("LISTEN=127.0.0.1:%d\n", port);
    fflush(stdout);
    int peer = accept(fd, NULL, NULL);
    if (peer < 0) { perror("accept"); return 2; }

    static unsigned char wire[4096];
    size_t n = 0;
    for (;;) {
        ssize_t got = recv(peer, wire + n, sizeof(wire) - n, 0);
        if (got < 0) { perror("recv"); return 2; }
        if (got == 0) break;
        n += (size_t) got;
        if (n == sizeof(wire)) break;
    }
    close(peer);
    close(fd);
    printf("WIRE bytes=%zu first4=%02x%02x%02x%02x\n", n,
           wire[0], wire[1], wire[2], wire[3]);
    fflush(stdout);

    SDL_IOStream *io = SDL_IOFromMem(wire, n);
    if (!io) {
        printf("RESULT=IO_ERROR ERROR=%s\n", SDL_GetError());
        return 1;
    }

    int rc = 0;
    if (strcmp(mode, "decode") == 0) {
        MIX_AudioDecoder *dec = MIX_CreateAudioDecoder_IO(io, true, 0);
        if (!dec) {
            printf("RESULT=LOAD_ERROR ERROR=%s\n", SDL_GetError());
            rc = 1;
        } else {
            SDL_AudioSpec spec;
            if (!MIX_GetAudioDecoderFormat(dec, &spec)) {
                printf("RESULT=SPEC_ERROR ERROR=%s\n", SDL_GetError());
                rc = 1;
            } else {
                printf("SPEC freq=%d format=%u channels=%d framesize=%d\n",
                       spec.freq, (unsigned) spec.format, spec.channels,
                       SDL_AUDIO_FRAMESIZE(spec));
                fflush(stdout);
                static unsigned char out[4096];
                int total = 0;
                for (int round = 0; round < 4; round++) {
                    int got = MIX_DecodeAudio(dec, out, (int) sizeof(out), &spec);
                    printf("DECODE round=%d got=%d\n", round, got);
                    fflush(stdout);
                    if (got <= 0) break;
                    total += got;
                }
                printf("RESULT=OK total=%d\n", total);
            }
            MIX_DestroyAudioDecoder(dec);
        }
    } else if (strcmp(mode, "play") == 0) {
        MIX_Mixer *mixer = MIX_CreateMixerDevice(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, NULL);
        if (!mixer) {
            printf("RESULT=MIXER_ERROR ERROR=%s\n", SDL_GetError());
            rc = 1;
        } else {
            MIX_Audio *audio = MIX_LoadAudio_IO(mixer, io, false, true);
            if (!audio) {
                printf("RESULT=LOAD_ERROR ERROR=%s\n", SDL_GetError());
                rc = 1;
            } else {
                MIX_Track *track = MIX_CreateTrack(mixer);
                if (!track || !MIX_SetTrackAudio(track, audio)) {
                    printf("RESULT=TRACK_ERROR ERROR=%s\n", SDL_GetError());
                    rc = 1;
                } else {
                    printf("PLAY started=%d\n", MIX_PlayTrack(track, 0) ? 1 : 0);
                    fflush(stdout);
                    SDL_Delay(300);
                    printf("RESULT=OK still_playing=%d\n", MIX_TrackPlaying(track) ? 1 : 0);
                }
            }
            MIX_DestroyMixer(mixer);
        }
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        rc = 2;
    }

    MIX_Quit();
    SDL_Quit();
    return rc;
}
