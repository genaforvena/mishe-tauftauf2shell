#ifndef CONN_H_STANDIN
#define CONN_H_STANDIN
/* Minimal Abyss TConn stand-in that preserves the real struct's field names,
   order and types up to buffer[], plus one extra socket fd our ConnRead uses.
   Real abyss conn.h at fbac12b451a1 defines BUFFER_SIZE 4096 and the same
   buffer union; only fields ws.c touches need to be ABI-faithful here. */
#include <stdint.h>
#include <strings.h>
#include <openssl/sha.h>
#define BUFFER_SIZE 4096
struct _TConn {
    struct _TConn *nextOutstandingP;
    void *server;
    uint32_t buffersize;
    uint32_t bufferpos;
    uint32_t inbytes, outbytes;
    void *channelP;
    void *channelInfoP;
    int hasOwnThread;
    void *threadP;
    int finished;
    const char *trace;
    void *job;
    void *done;
    union {
        unsigned char b[BUFFER_SIZE];
        char t[BUFFER_SIZE];
    } buffer;
    int fd; /* loopback socket descriptor, used by our ConnRead */
};
typedef struct _TConn TConn;
int ConnWrite(TConn *c, const void *data, uint32_t len);
void ConnRead(TConn *c, int flags, void *a, void *b, const char **readError);
void ConnReadInit(TConn *c);
#endif
