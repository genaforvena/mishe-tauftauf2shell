#line 523 "forward.c.47db630c"
static int secure_forward_pong(struct flb_forward *ctx, char *buf, int buf_size)
{
    int ret;
    char msg[32] = {0};
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_object root;
    msgpack_object o;

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }

    root = result.data;
    if (root.type != MSGPACK_OBJECT_ARRAY) {
        goto error;
    }

    if (root.via.array.size < 4) {
        goto error;
    }

    o = root.via.array.ptr[0];
    if (o.type != MSGPACK_OBJECT_STR) {
        goto error;
    }

    if (strncmp(o.via.str.ptr, "PONG", 4) != 0 || o.via.str.size != 4) {
        goto error;
    }

    o = root.via.array.ptr[1];
    if (o.type != MSGPACK_OBJECT_BOOLEAN) {
        goto error;
    }

    if (o.via.boolean) {
        msgpack_unpacked_destroy(&result);
        return 0;
    }
    else {
        o = root.via.array.ptr[2];
        memcpy(msg, o.via.str.ptr, o.via.str.size);
        flb_plg_error(ctx->ins, "failed authorization: %s", msg);
    }

 error:
    msgpack_unpacked_destroy(&result);
    return -1;
}
