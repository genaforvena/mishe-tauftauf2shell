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
            pj_uint32_t read_len = ch.len;

            /* Clamp the read to the frame buffer capacity. A crafted
             * file may declare a chunk larger than the buffer, whose
             * size is derived from the (also file-supplied) video
             * dimensions; never write past frame->buf (frame->size
             * bytes). Do not rely on pj_assert() here, as it is a no-op
             * in release builds.
             */
            if (read_len > frame->size) {
                PJ_LOG(3, (THIS_FILE,
                           "AVI video chunk (%u) exceeds frame buffer "
                           "(%u), truncating",
                           (unsigned)ch.len, (unsigned)frame->size));
                read_len = (pj_uint32_t)frame->size;
            }

            status = file_read3(fport->fd, frame->buf, read_len,
                                0, &size_read);
            if (status != PJ_SUCCESS)
                goto on_error2;

            /* Skip any remaining chunk bytes that did not fit, so the
             * file position stays aligned to the next chunk.
             */
            if (ch.len > read_len) {
                status = pj_file_setpos(fport->fd,
                                        (pj_off_t)ch.len - read_len,
                                        PJ_SEEK_CUR);
                if (status != PJ_SUCCESS)
                    goto on_error2;
            }

            frame->size = read_len;
            fport->size_left = 0;
        }
