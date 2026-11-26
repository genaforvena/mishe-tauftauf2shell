        frame->type = (fport->base.info.fmt.type == PJMEDIA_TYPE_VIDEO ?
                       PJMEDIA_FRAME_TYPE_VIDEO : PJMEDIA_FRAME_TYPE_AUDIO);

        if (frame->type == PJMEDIA_FRAME_TYPE_AUDIO) {
            if (size_to_read > fport->size_left)
                size_to_read = fport->size_left;
            status = file_read3(fport->fd, (char *)frame->buf + frame->size -
                                size_to_read, size_to_read,
                                fport->bits_per_sample, &size_read);
            if (status != PJ_SUCCESS)
                goto on_error2;
            fport->size_left -= size_to_read;
        } else {
            pj_assert(frame->size >= ch.len);
            status = file_read3(fport->fd, frame->buf, ch.len,
                                0, &size_read);
            if (status != PJ_SUCCESS)
                goto on_error2;
            frame->size = ch.len;
            fport->size_left = 0;
        }
