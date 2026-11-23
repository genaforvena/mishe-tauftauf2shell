#line 105 "state.c.v2.4.19.4"
// element in a list of state cookies
typedef struct oidc_state_cookies_t {
	char *name;
	apr_time_t timestamp;
	struct oidc_state_cookies_t *next;
} oidc_state_cookies_t;
