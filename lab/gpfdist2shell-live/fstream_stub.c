/* Minimal fstream backend for the gpfdist2shell live harness.
 * The file-I/O backend is irrelevant to the segment-header OOB write; these
 * stubs let the REAL pinned gpfdist.c reach session_attach() and the OPEN_SEQ
 * store. No production fstream code is modified. */
#include <stdint.h>
#include <fstream/fstream.h>
struct fstream_t { int dummy; };
static struct fstream_t the_stream;

fstream_t *fstream_open(const char *path, const struct fstream_options *options,
                        int *response_code, const char **response_string)
{
    (void)path; (void)options;
    if (response_code) *response_code = 200;
    if (response_string) *response_string = "OK";
    return &the_stream;
}
int fstream_read(fstream_t *fs, void *buf, int size,
                 struct fstream_filename_and_offset *fo, const int whole,
                 const char *delim, const int delim_len)
{ (void)fs; (void)buf; (void)fo; (void)whole; (void)delim; (void)delim_len; return 0; }
int fstream_write(fstream_t *fs, void *buf, int size, const int whole,
                  const char *delim, const int delim_len)
{ (void)fs; (void)buf; (void)size; (void)whole; (void)delim; (void)delim_len; return size; }
int fstream_eof(fstream_t *fs) { (void)fs; return 1; }
int64_t fstream_get_compressed_size(fstream_t *fs) { (void)fs; return 0; }
int64_t fstream_get_compressed_position(fstream_t *fs) { (void)fs; return 0; }
const char *fstream_get_error(fstream_t *fs) { (void)fs; return ""; }
void fstream_close(fstream_t *fs) { (void)fs; }
int fstream_is_win_pipe(fstream_t *fs) { (void)fs; return 0; }
