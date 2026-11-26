#line 916 "short.c"
void    handleSMessage(struct mesg_s_spacket *packet)
{
  char    buf[100];
  char    addrbuf[9];

  if (debug)
    printf("Length of Message is: %zd  total Size %d \n", strlen(&packet->mesg), (int) packet->length);
  if (packet->m_from >= MAXPLAYER)
    packet->m_from = 255;

  if (packet->m_from == 255)
    strcpy(addrbuf, "GOD->");
  else
    {
      sprintf(addrbuf, " %c%c->", teamlet[players[packet->m_from].p_team],
	      shipnos[players[packet->m_from].p_no]);
    }

  switch (packet->m_flags & (MTEAM | MINDIV | MALL))
    {
    case MALL:
      sprintf(addrbuf + 5, "ALL");
      break;
    case MTEAM:
      sprintf(addrbuf + 5, "%s", teamshort[me->p_team]);
      break;
    case MINDIV:
      /* I know that it's me -> xxx but i copied it straight ... */
      if (packet->m_recpt >= MAXPLAYER)
        sprintf(addrbuf + 5, "?? ");
      else
        sprintf(addrbuf + 5, "%c%c ", teamlet[players[packet->m_recpt].p_team],
	        shipnos[packet->m_recpt]);
      break;
    default:
      sprintf(addrbuf + 5, "ALL");
      break;
    }
  {
    size_t body_max = (packet->length > offsetof(struct mesg_s_spacket, mesg))
                    ? (size_t)(packet->length - offsetof(struct mesg_s_spacket, mesg)) : 0;
    char body[sizeof(buf)];
    size_t n = strnlen(&packet->mesg, body_max);
    if (n >= sizeof(body)) n = sizeof(body) - 1;
    memcpy(body, &packet->mesg, n);
    body[n] = 0;
    snprintf(buf, sizeof(buf), "%-9s%s", addrbuf, body);
  }
  dmessage(buf, packet->m_flags, packet->m_from, packet->m_recpt);
}
