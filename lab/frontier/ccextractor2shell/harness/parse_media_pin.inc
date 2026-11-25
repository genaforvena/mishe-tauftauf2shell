/* Verbatim excerpts from CCExtractor master 2c1c1c6f0602563d2064f2b0c36f13b3c7a09489,
 * src/lib_ccx/ccx_gxf.c lines 1146-1151 and 1199-1221 (comments retained).
 * The driver below reproduces only the MPEG2 branch; other branches and
 * unrelated media-header fields are stand-ins, not modified source.
 */
		case TRACK_TYPE_MPEG1_525:
		case TRACK_TYPE_MPEG2_525:
			mpeg_pic_size = buffered_get_be32(demux);
			mpeg_frame_desc_flag = mpeg_pic_size >> 24;
			mpeg_pic_size &= 0xFFFFFF;
			len -= 4;
			break;
...
	else if (media_type == TRACK_TYPE_MPEG2_525 && !ctx->ad_track)
	{
		if (!ctx->vid_track)
		{
			goto end;
		}
...
		set_mpeg_frame_desc(ctx->vid_track, mpeg_frame_desc_flag);
		parse_mpeg_packet(demux, mpeg_pic_size, data);
		len -= mpeg_pic_size;
	}
