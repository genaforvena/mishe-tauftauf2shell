static void
ms_kill(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	const char *user;
	const char *reason;
	char default_reason[] = "<No reason given>";
	const char *path;

	*buf = '\0';

	user = parv[1];

	if(EmptyString(parv[2]))
	{
		reason = default_reason;

		/* hyb6 takes the nick of the killer from the path *sigh* --fl_ */
		path = source_p->name;
	}
	else
	{
		char *s = LOCAL_COPY(parv[2]), *t;
		t = strchr(s, ' ');

		if(t)
		{
			*t = '\0';
			t++;

			if(strlen(t) > (size_t) KILLLEN)
				t[KILLLEN] = '\0';

			reason = t;
		}
		else
			reason = default_reason;

		path = s;
	}

	if((target_p = find_person(user)) == NULL)
	{
		/*
		 * If the user has recently changed nick, but only if its
		 * not an uid, automatically rewrite the KILL for this new nickname.
		 * --this keeps servers in synch when nick change and kill collide
		 */
		if(IsDigit(*user) || (!(target_p = whowas_get_history(user, (long) KILLCHASETIMELIMIT))))
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					   form_str(ERR_NOSUCHNICK), IsDigit(*user) ? "*" : user);
			return;
		}
		sendto_one_notice(source_p, ":KILL changed from %s to %s", user, target_p->name);
	}

	if(IsServer(target_p) || IsMe(target_p))
	{
		sendto_one_numeric(source_p, ERR_CANTKILLSERVER, form_str(ERR_CANTKILLSERVER));
		return;
	}

	if(MyConnect(target_p))
	{
		if(IsServer(source_p))
		{
			sendto_one(target_p, ":%s KILL %s :%s",
				   source_p->name, target_p->name, reason);
		}
		else
			sendto_one(target_p, ":%s!%s@%s KILL %s :%s",
				   source_p->name, source_p->username, source_p->host,
				   target_p->name, reason);
	}

	/* Be warned, this message must be From %s, or it confuses clients
	 * so dont change it to From: or the case or anything! -- fl -- db */
	/* path must contain at least 2 !'s, or bitchx falsely declares it
	 * local --fl
	 */
	if(IsOper(source_p))	/* send it normally */
	{
		sendto_realops_snomask(IsService(source_p) ? SNO_SKILL : SNO_GENERAL, L_ALL,
				     "Received KILL message for %s!%s@%s. From %s Path: %s!%s!%s!%s %s",
				     target_p->name, target_p->username, target_p->orighost, source_p->name,
				     source_p->servptr->name, source_p->host, source_p->username,
				     source_p->name, reason);

		ilog(L_KILL, "%c %s %s!%s@%s %s %s",
		     MyConnect(target_p) ? 'O' : 'R', get_oper_name(source_p),
		     target_p->name, target_p->username, target_p->host,
		     target_p->servptr->name, reason);
	}
	else
	{
		sendto_realops_snomask(SNO_SKILL, L_ALL,
				     "Received KILL message for %s!%s@%s. From %s %s",
				     target_p->name, target_p->username, target_p->orighost,
				     source_p->name, reason);

		ilog(L_KILL, "S %s %s!%s@%s %s %s",
		     source_p->name, target_p->name, target_p->username,
		     target_p->host, target_p->servptr->name, reason);
	}

	relay_kill(client_p, source_p, target_p, path, reason);

	/* FLAGS_KILLED prevents a quit being sent out */
	target_p->flags |= FLAGS_KILLED;

	sprintf(buf, "Killed (%s %s)", source_p->name, reason);

	exit_client(client_p, target_p, source_p, buf);
}
