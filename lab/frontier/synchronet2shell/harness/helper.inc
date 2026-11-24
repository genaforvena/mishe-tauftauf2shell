void free_crypt_attrstr(char *attr)
{
	free(attr);
}

char* get_binary_crypt_attribute(CRYPT_HANDLE sess, C_IN CRYPT_ATTRIBUTE_TYPE attr, size_t *sz)
{
	int   len = 0;
	char *estr = NULL;
	int   status;

	status = cryptGetAttributeString(sess, attr, NULL, &len);
	if (cryptStatusOK(status)) {
		estr = malloc(len + 1);
		if (estr) {
			if (cryptStatusOK(cryptGetAttributeString(sess, attr, estr, &len))) {
				if (len >= 0) {
					estr[len] = 0;
					if (sz)
						*sz = len;
					return estr;
				}
			}
			free(estr);
		}
	}
	return NULL;
}
