#line 204 "state.c.4301b536"
static int oidc_state_cookies_parse_token(request_rec *r, const oidc_cfg_t *c, char *cookie,
					  const char *currentCookieName, oidc_state_cookies_t **first,
					  oidc_state_cookies_t **last) {
	while (*cookie == OIDC_CHAR_SPACE)
		cookie++;

	if (_oidc_strstr(cookie, oidc_cfg_dir_state_cookie_prefix_get(r)) != cookie)
		return 0;

	char *cookieName = cookie;
	while (cookie != NULL && *cookie != OIDC_CHAR_EQUAL)
		cookie++;
	if (*cookie != OIDC_CHAR_EQUAL)
		return 0;

	*cookie = '\0';
	cookie++;

	return oidc_state_cookies_process_one(r, c, cookieName, cookie, currentCookieName, first, last);
}
