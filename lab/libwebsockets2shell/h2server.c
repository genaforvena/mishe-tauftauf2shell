/*
 * Loopback-only libwebsockets H2 server used to observe the real HPACK
 * :path consumer.  No external network access.  Build against the pinned
 * v4.3.10 ASan build in this directory.
 */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <libwebsockets.h>

static volatile int stop;

static void on_sigint(int sig) { (void)sig; stop = 1; }

static int cb_http(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	(void)wsi; (void)user; (void)in; (void)len;
	switch (reason) {
	case LWS_CALLBACK_HTTP:
		lwsl_notice("server: LWS_CALLBACK_HTTP\n");
		if (lws_return_http_status(wsi, HTTP_STATUS_OK, "ok\n"))
			return -1;
		break;
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		break;
	default:
		break;
	}
	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "http-only", cb_http, 0, 0, 0, NULL, 0 },
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	struct lws_context *context;
	int port = 18777, loglevel = LLL_NOTICE;

	if (argc > 1)
		port = atoi(argv[1]);
	if (argc > 2)
		loglevel = atoi(argv[2]);

	memset(&info, 0, sizeof(info));
	info.port = port;
	info.iface = "127.0.0.1";
	info.protocols = protocols;
	info.gid = -1;
	info.uid = -1;
	info.max_http_header_data = 32;
	info.max_http_header_pool = 4;
	info.options = LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	lws_set_log_level(loglevel, NULL);

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);

	context = lws_create_context(&info);
	if (!context) {
		fprintf(stderr, "lws_create_context failed\n");
		return 2;
	}
	lwsl_notice("server: listening 127.0.0.1:%d, max_http_header_data=32\n",
		    port);

	while (!stop)
		lws_service(context, 50);

	lws_context_destroy(context);
	return 0;
}
