int
vips_region_image(VipsRegion *reg, const VipsRect *r)
{
	VipsImage *image = reg->im;

	VipsRect all;
	VipsRect clipped;

	/* Sanity check.
	 */
	vips__region_check_ownership(reg);

	/* Clip against image.
	 */
	all.top = 0;
	all.left = 0;
	all.width = image->Xsize;
	all.height = image->Ysize;
	vips_rect_intersectrect(r, &all, &clipped);

	if (vips_rect_isempty(&clipped)) {
		vips_error("VipsRegion",
			"%s", _("valid clipped to nothing"));
		return -1;
	}

	reg->invalid = FALSE;
	VIPS_FREEF(vips_buffer_unref, reg->buffer);

	if (image->data) {
		/* We have the whole image available ... easy!
		 */
		VIPS_FREEF(vips_window_unref, reg->window);

		/* We can't just set valid = whole image, since this may be an
		 * incompletely calculated memory buffer. Just set valid to r.
		 */
		reg->valid = clipped;
		reg->bpl = VIPS_IMAGE_SIZEOF_LINE(image);
		reg->data = VIPS_IMAGE_ADDR(image, clipped.left, clipped.top);
		reg->type = VIPS_REGION_OTHER_IMAGE;
	}
