/* Verbatim from CCExtractor master 2c1c1c6f0602563d2064f2b0c36f13b3c7a09489,
 * src/lib_ccx/ccx_gxf.c lines 938-949. Only whitespace before the function
 * (leading indentation) is unchanged; no statement has been edited.
 */
static int parse_mpeg_packet(struct ccx_demuxer *demux, int len, struct demuxer_data *data)
{
	int ret = CCX_OK;
	int result = 0;

	result = buffered_read(demux, data->buffer + data->len, len);
	data->len += len;
	demux->past += result;
	if (result != len)
		ret = CCX_EOF;
	return ret;
}
