		if (cryptStatusOK(cryptGetAttributeString(ssh_session, CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, terminal, &l)) && l > 0) {
			if (l < (int)sizeof(terminal))
				terminal[l] = 0;
			else
				terminal[sizeof(terminal) - 1] = 0;
			lprintf(LOG_DEBUG, "%04d SSH [%s] term: %s", client_socket.load(), client.addr, terminal);
		}
