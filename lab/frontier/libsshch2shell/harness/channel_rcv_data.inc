/* is_stderr is set to 1 if the data are extended, ie stderr */
SSH_PACKET_CALLBACK(channel_rcv_data)
{
    ssh_channel channel = NULL;
    ssh_string str = NULL;
    ssh_buffer buf = NULL;
    void *data = NULL;
    uint32_t len;
    int extended, is_stderr = 0;
    int rest;

    (void)user;

    if (type == SSH2_MSG_CHANNEL_DATA) {
        extended = 0;
    } else { /* SSH_MSG_CHANNEL_EXTENDED_DATA */
        extended = 1;
    }

    channel = channel_from_msg(session, packet);
    if (channel == NULL) {
        SSH_LOG(SSH_LOG_FUNCTIONS, "%s", ssh_get_error(session));

        return SSH_PACKET_USED;
    }

    if (extended) {
        uint32_t data_type_code, rc;
        rc = ssh_buffer_get_u32(packet, &data_type_code);
        if (rc != sizeof(uint32_t)) {
            SSH_LOG(SSH_LOG_PACKET,
                    "Failed to read data type code: rc = %" PRIu32, rc);

            return SSH_PACKET_USED;
        }
        is_stderr = 1;
        data_type_code = ntohl(data_type_code);
        if (data_type_code != SSH2_EXTENDED_DATA_STDERR) {
            SSH_LOG(SSH_LOG_PACKET, "Invalid data type code %" PRIu32 "!",
                    data_type_code);
        }
    }

    str = ssh_buffer_get_ssh_string(packet);
    if (str == NULL) {
        SSH_LOG(SSH_LOG_PACKET, "Invalid data packet!");

        return SSH_PACKET_USED;
    }
    /* STRING_SIZE_MAX < UINT32_MAX */
    len = (uint32_t)ssh_string_len(str);

    SSH_LOG(SSH_LOG_PACKET,
            "Channel receiving %" PRIu32 " bytes data%s (local win=%" PRIu32
            " remote win=%" PRIu32 ") on channel %" PRIu32 ":%" PRIu32,
            len,
            is_stderr ? " in stderr" : "",
            channel->local_window,
            channel->remote_window,
            channel->local_channel,
            channel->remote_channel);

#ifdef LIBSSH_FIXED
    if (channel->flags & SSH_CHANNEL_FLAG_CLOSED_REMOTE) {
        SSH_LOG(SSH_LOG_WARNING, "Received data on (remotely) closed channel");
        ssh_set_error(session, SSH_FATAL, "Received data on (remotely) closed channel");
        SSH_STRING_FREE(str);
        return SSH_PACKET_USED;
    }
#endif
    if (len > channel->local_window) {
        SSH_LOG(SSH_LOG_RARE,
                "Data packet too big for our window(%" PRIu32 " vs %" PRIu32 ")",
                len,
                channel->local_window);

        SSH_STRING_FREE(str);

        ssh_set_error(session, SSH_FATAL, "Window exceeded");

        return SSH_PACKET_USED;
    }

    data = ssh_string_data(str);
    if (channel_default_bufferize(channel, data, len, is_stderr) < 0) {
        SSH_STRING_FREE(str);

        return SSH_PACKET_USED;
    }

    channel->local_window -= len;

    SSH_LOG(SSH_LOG_PACKET,
            "Channel windows are now (local win=%" PRIu32 " remote win=%" PRIu32 ")",
            channel->local_window,
            channel->remote_window);

    SSH_STRING_FREE(str);

    if (is_stderr) {
        buf = channel->stderr_buffer;
    } else {
        buf = channel->stdout_buffer;
    }

    ssh_callbacks_iterate(channel->callbacks,
                          ssh_channel_callbacks,
                          channel_data_function) {
        if (ssh_buffer_get(buf) == NULL) {
            break;
        }
        rest = ssh_callbacks_iterate_exec(channel_data_function,
                                          channel->session,
                                          channel,
                                          ssh_buffer_get(buf),
                                          ssh_buffer_get_len(buf),
                                          is_stderr);
        if (rest > 0) {
            int rc;
            if (channel->counter != NULL) {
                channel->counter->in_bytes += rest;
            }
            ssh_buffer_pass_bytes(buf, rest);

            rc = grow_window(session, channel);
            if (rc == SSH_ERROR) {
              return -1;
            }
        }
    }
    ssh_callbacks_iterate_end();

    return SSH_PACKET_USED;
}
