#line 1170 "packets.h"
struct mesg_s_spacket
  {
    char    type;				 /* SP_S_MESSAGE */
    unsigned char m_flags;
    unsigned char m_recpt;
    unsigned char m_from;
    unsigned char length;			 /* Length of whole packet */
    char    mesg;
    char    pad2;
    char    pad3;
    char    pad[76];
  };
