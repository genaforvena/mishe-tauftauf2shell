static void rpmfiSetFound(rpmfi fi, int ix)
{
    fi->found[ix >> 3] |= (1 << (ix % 8));
}

static int rpmfiFound(rpmfi fi, int ix)
{
    return fi->found[ix >> 3] & (1 << (ix % 8));
}

static int iterReadArchiveNext(rpmfi fi)
{
    int rc;
    int fx = -1;
    int fc = rpmfilesFC(fi->files);
    char * path = NULL;

    if (fi->archive == NULL)
	return -1;

    /* Read next payload header. */
    rc = rpmcpioHeaderRead(fi->archive, &path, &fx);

    /* if archive ended, check if we found all files */
    if (rc == RPMERR_ITER_END) {
	for (int i=0; i<fc; i++) {
	    if (!rpmfiFound(fi, i) &&
			!(rpmfilesFFlags(fi->files, i) & RPMFILE_GHOST)) {
                rc = RPMERR_MISSING_FILE;
		break;
            }
	}
    }
    if (rc) {
	return rc;
    }

    if (path) {
	/* Regular cpio archive, identify mapping index. */
	fx = rpmfilesFindOFN(fi->files, path);
	free(path);
    }

    if (fx >= 0 && fx < fc) {
	rpm_loff_t fsize = 0;
	rpm_mode_t mode = rpmfilesFMode(fi->files, fx);

	/* %ghost in payload, should not be there but rpm < 4.11 sometimes did this */
	if (rpmfilesFFlags(fi->files, fx) & RPMFILE_GHOST)
	    return RPMERR_ITER_SKIP;

	if (S_ISREG(mode)) {
	    const int * links;
	    uint32_t numlinks = rpmfilesFLinks(fi->files, fx, &links);
	    if (!(numlinks > 1 && links[numlinks-1] != fx))
		fsize = rpmfilesFSize(fi->files, fx);
	} else if (S_ISLNK(mode)) {
	    /* Cross-check symlink data, strings are capped by header size. */
	    rpm_loff_t lsize = rpmfilesFSize(fi->files, fx);
	    const char *link = rpmfilesFLink(fi->files, fx);
	    if (link == NULL || lsize != strlen(link))
		return RPMERR_BAD_HEADER;
	    /* Skip over symlink target data in payload */
	    char *buf = (char *)xmalloc(lsize + 1);
	    if (rpmcpioRead(fi->archive, buf, lsize) != lsize)
		rc = RPMERR_READ_FAILED;
	    /* XXX should we validate the payload matches? */
	    free(buf);
	}
	rpmcpioSetExpectedFileSize(fi->archive, fsize);
	rpmfiSetFound(fi, fx);
    } else {
	/* Mapping error */
	rc = RPMERR_UNMAPPED_FILE;
    }
    return (rc != 0) ? rc : fx;
}
