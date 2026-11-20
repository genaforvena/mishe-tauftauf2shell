#ifndef SESSION_H_STANDIN
#define SESSION_H_STANDIN
/* Minimal Abyss TSession stand-in for the real-source ws.c loopback test.
   ws.c only dereferences tsession->connP. */
struct _TConn;
typedef struct _TSession {
    struct _TConn *connP;
} TSession;
#endif
