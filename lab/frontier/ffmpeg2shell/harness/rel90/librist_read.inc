#line 200 "librist.c.n9.0"
static int librist_read(URLContext *h, uint8_t *buf, int size)
{
    RISTContext *s = h->priv_data;
    int ret;

    struct rist_data_block *data_block;
    ret = rist_receiver_data_read2(s->ctx, &data_block, POLLING_TIME);

    if (ret < 0)
        return risterr2ret(ret);

    if (ret == 0)
        return AVERROR(EAGAIN);

    if (data_block->payload_len > MAX_PAYLOAD_SIZE) {
        rist_receiver_data_block_free2(&data_block);
        return AVERROR_EXTERNAL;
    }

    if (data_block->flags & RIST_DATA_FLAGS_OVERFLOW) {
        if (!s->overrun_nonfatal) {
            av_log(h, AV_LOG_ERROR, "Fifo buffer overrun. "
                    "To avoid, increase fifo_size option. "
                    "To survive in such case, use overrun_nonfatal option\n");
            size = AVERROR(EIO);
            goto out_free;
        }
    }

    size = data_block->payload_len;
    memcpy(buf, data_block->payload, size);
out_free:
    rist_receiver_data_block_free2(&data_block);
    return size;
}
