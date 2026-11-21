#ifndef SHIM_FSTREAM_H
#define SHIM_FSTREAM_H
#include <sys/types.h>
struct gpfxdist_t;
typedef struct fstream_t fstream_t;
struct fstream_options{
    int header;
    int is_csv;
    int verbose;
    char quote;
    char escape;
    int eol_type;
    int bufsize;
    int forwrite;
    int usesync;
    struct gpfxdist_t* transform;
};
struct fstream_filename_and_offset{
    char fname[256];
    int64_t line_number;
    int64_t foff;
};
int fstream_read(fstream_t*, void*, int, struct fstream_filename_and_offset*,
                 const int, const char*, const int);
int fstream_write(fstream_t*, void*, int, const int, const char*, const int);
int fstream_eof(fstream_t* fs);
int64_t fstream_get_compressed_size(fstream_t* fs);
int64_t fstream_get_compressed_position(fstream_t* fs);
const char* fstream_get_error(fstream_t* fs);
fstream_t* fstream_open(const char* path, const struct fstream_options* options,
                        int* response_code, const char** response_string);
void fstream_close(fstream_t* fs);
int fstream_is_win_pipe(fstream_t* fs);
#endif
