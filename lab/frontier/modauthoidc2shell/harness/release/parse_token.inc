#line 204 "state.c.v2.4.19.4"
static int oidc_state_cookies_parse_token(request_rec *r, const oidc_cfg_t *c, char *cookie,
					  const char *currentCookieName, oidc_state_cookies_t **first,
					  oidc_state_cookies_t **last) {
	while (*cookie == OIDC_CHAR_SPACE)
		cookie++;

	if (_oidc_strstr(cookie, oidc_cfg_dir_state_cookie_prefix_get(r)) != cookie)
		return 0;

	char *cookieName = cookie;
	/* stop at the string terminator as well as at '='; the previous "cookie != NULL" condition could
	 * never be false (cookie is only incremented) so a state-prefixed token without a '=' would scan
	 * past the end of the buffer (out-of-bounds read, and a subsequent out-of-bounds NUL write) */
	while ((*cookie != '\0') && (*cookie != OIDC_CHAR_EQUAL))
		cookie++;
	if (*cookie != OIDC_CHAR_EQUAL)
		return 0;

	*cookie = '\0';
	cookie++;

	return oidc_state_cookies_process_one(r, c, cookieName, cookie, currentCookieName, first, last);
}
