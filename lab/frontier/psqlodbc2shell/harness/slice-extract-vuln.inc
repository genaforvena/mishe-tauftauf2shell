#define F_ExtractOldTo(qp, buf, ch, maxsize) \
do { \
	size_t	c = 0; \
	while ((qp)->statement[qp->opos] != '\0' && (qp)->statement[qp->opos] != ch) \
	{ \
		if (c >= maxsize) \
			break; \
		buf[c++] = (qp)->statement[qp->opos++];	\
	} \
	if ((qp)->statement[qp->opos] == '\0')	\
		{retval = SQL_ERROR; goto cleanup;} \
	buf[c] = '\0'; \
} while (0)
