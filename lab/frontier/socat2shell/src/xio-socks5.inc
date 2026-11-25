static int _xioopen_socks5_read_reply(
	struct single *sfd, struct socks5_reply *reply, int level)
{
	int result = 0;
	int bytes_read = 0;
	int bytes_to_read = 5;
	bool typechecked = false;

	while (bytes_to_read >= 0) {
		Info("reading SOCKS5 reply");
		do {
			result = readfull(sfd->fd,
					  ((unsigned char *)reply) + bytes_read,
					  bytes_to_read-bytes_read,
					  NULL, level-1);
		} while (result < 0 && errno == EINTR);
		if (result < 0) {
			Msg4(level, "read(%d, %p, %d): %s",
			     sfd->fd, ((unsigned char *)reply) + bytes_read,
			     bytes_to_read-bytes_read, strerror(errno));
			if (Close(sfd->fd) < 0) {
				Info2("close(%d): %s", sfd->fd, strerror(errno));
			}
			return STAT_RETRYLATER;
		}
		if (result == 0) {
			Msg(level, "read(): EOF during read of SOCKS5 reply");
			if (Close(sfd->fd) < 0) {
				Info2("close(%d): %s",
				      sfd->fd, strerror(errno));
			}
			return STAT_RETRYLATER;
		}
		Debug5("received SOCKS5 reply %02x %02x %02x %02x %02x",
		       ((unsigned char *)reply+bytes_read)[0],
		       ((unsigned char *)reply+bytes_read)[1],
		       ((unsigned char *)reply+bytes_read)[2],
		       ((unsigned char *)reply+bytes_read)[3],
		       ((unsigned char *)reply+bytes_read)[4]);
		bytes_read += result;

		/* Once we've read 5 bytes, figure out total message length and
		*  update bytes_to_read accordingly. */
		if (!typechecked && bytes_read <= 5) {
			switch(reply->address_type) {
			case SOCKS5_ATYPE_IPv4:
				/* 6 fixed bytes, and 4 bytes for v4 address */
				bytes_to_read = 10;
				break;
			case SOCKS5_ATYPE_IPv6:
				/* 6 fixed bytes, and 16 bytes for v6 address */
				bytes_to_read = 22;
				break;
			case SOCKS5_ATYPE_DOMAINNAME:
				/* 6 fixed bytes, 1 byte for strlen,
				   and 0-255 bytes for domain name */
				bytes_to_read = 7 + reply->dstdata[0];
				break;
			default:
				Msg1(level, "invalid SOCKS5 reply address type (%d)",
				     reply->address_type);
				if (Close(sfd->fd) < 0) {
					Info2("close(%d): %s",
					      sfd->fd, strerror(errno));
				}
				return STAT_RETRYLATER;
			}
			typechecked = true;
			continue;
		}

		if (bytes_to_read == bytes_read) {
			Debug1("received all %d bytes", bytes_read);
			break;
		}

		Debug2("received %d of %d bytes, waiting",
		       bytes_read, bytes_to_read);
	}

	if (result <= 0) {
		return STAT_RETRYLATER;
	}

	return STAT_OK;
}
