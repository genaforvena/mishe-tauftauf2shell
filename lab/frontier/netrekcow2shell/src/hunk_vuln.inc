#line 914 "short.c"
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
      sprintf(addrbuf + 5, "%c%c ", teamlet[players[packet->m_recpt].p_team],
	      shipnos[packet->m_recpt]);
      break;
    default:
      sprintf(addrbuf + 5, "ALL");
      break;
    }
  sprintf(buf, "%-9s%s", addrbuf, &packet->mesg);
  dmessage(buf, packet->m_flags, packet->m_from, packet->m_recpt);
}
