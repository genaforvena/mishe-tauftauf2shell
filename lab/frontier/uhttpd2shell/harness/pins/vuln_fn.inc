static void vuln_uh_ubus_send_request(struct client *cl, const char *sid, struct blob_attr *args)
{
	struct dispatch *d = &cl->dispatch;
	struct dispatch_ubus *du = &d->ubus;
	struct blob_attr *cur;
	static struct blob_buf req;
	int ret, rem;

	blob_buf_init(&req, 0);
	blobmsg_for_each_attr(cur, args, rem) {
		if (!strcmp(blobmsg_name(cur), "ubus_rpc_session"))
			return uh_ubus_json_rpc_error(cl, ERROR_PARAMS);
		blobmsg_add_blob(&req, cur);
	}

	blobmsg_add_string(&req, "ubus_rpc_session", sid);

	blob_buf_init(&du->buf, 0);
	memset(&du->req, 0, sizeof(du->req));
	ret = ubus_invoke_async(ctx, du->obj, du->func, req.head, &du->req);
	if (ret)
		return uh_ubus_json_rpc_error(cl, ERROR_INTERNAL);

	du->req.data_cb = uh_ubus_request_data_cb;
	du->req.complete_cb = uh_ubus_request_cb;
	ubus_complete_request_async(ctx, &du->req);

	du->timeout.cb = uh_ubus_timeout_cb;
	uloop_timeout_set(&du->timeout, conf.script_timeout * 1000);

	du->req_pending = true;
}
