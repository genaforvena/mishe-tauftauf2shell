static void
vips_image_sanity(VipsObject *object, VipsBuf *buf)
{
	VipsImage *image = VIPS_IMAGE(object);
	guint64 es, ps, ls, sizeof_image;

	if (image->Xsize <= 0 ||
		image->Ysize <= 0 ||
		image->Bands <= 0)
		vips_buf_appends(buf, "bad dimensions\n");
	if (image->BandFmt < -1 ||
		image->BandFmt > VIPS_FORMAT_DPCOMPLEX ||
		(image->Coding != -1 &&
			image->Coding != VIPS_CODING_NONE &&
			image->Coding != VIPS_CODING_LABQ &&
			image->Coding != VIPS_CODING_RAD) ||
		image->Type >= VIPS_INTERPRETATION_LAST ||
		image->dtype > VIPS_IMAGE_PARTIAL ||
		image->dhint > VIPS_DEMAND_STYLE_ANY)
		vips_buf_appends(buf, "bad enum\n");
	if (image->Xres < 0 ||
		image->Yres < 0)
		vips_buf_appends(buf, "bad resolution\n");

	es = VIPS_IMAGE_SIZEOF_ELEMENT(image);

	/* Guard for `es * bands * width * height <= UINT64_MAX`, i.e. check
	 * whether the VIPS_IMAGE_SIZEOF_PEL(), VIPS_IMAGE_SIZEOF_LINE()
	 * and VIPS_IMAGE_SIZEOF_IMAGE() macros can be safely used.
	 *
	 * A scanline (i.e. `es * bands * width`) has to fit in INT_MAX.
	 *
	 * Also ensure that vips_tracked_malloc(VIPS_IMAGE_SIZEOF_IMAGE(image))
	 * can be called safely for setbuf types.
	 */
	if (!g_uint64_checked_mul(&ps, es, image->Bands) ||
		!g_uint64_checked_mul(&ls, ps, image->Xsize) ||
		ls >= INT_MAX ||
		!g_uint64_checked_mul(&sizeof_image, ls, image->Ysize) ||
		(image->dtype == VIPS_IMAGE_SETBUF &&
			sizeof_image > G_MAXSIZE - 16))
		vips_buf_appends(buf, "dimension overflow\n");

	/* These checks are expensive -- only do in leakcheck mode.
	 */
	if (vips__leak) {
		/* Must lock around inter-image links.
		 */
		g_mutex_lock(&vips__global_lock);

		if (vips_slist_map2(image->upstream,
				(VipsSListMap2Fn) vips_image_sanity_upstream, image, NULL))
			vips_buf_appends(buf, "upstream broken\n");
		if (vips_slist_map2(image->downstream,
				(VipsSListMap2Fn) vips_image_sanity_downstream, image, NULL))
			vips_buf_appends(buf, "downstream broken\n");

		g_mutex_unlock(&vips__global_lock);
	}

	VIPS_OBJECT_CLASS(vips_image_parent_class)->sanity(object, buf);
}

