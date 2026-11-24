		// cryptGetAttributeString() does not take a destination size.
		size_t ssh_terminal_length = 0;
		char* ssh_terminal = get_binary_crypt_attribute(ssh_session, CRYPT_SESSINFO_SSH_CHANNEL_TERMINAL, &ssh_terminal_length);
		if (ssh_terminal != nullptr && ssh_terminal_length > 0) {
			SAFECOPY(terminal, ssh_terminal);
			lprintf(LOG_DEBUG, "%04d SSH [%s] term: %s", client_socket.load(), client.addr, terminal);
		}
		free_crypt_attrstr(ssh_terminal);
