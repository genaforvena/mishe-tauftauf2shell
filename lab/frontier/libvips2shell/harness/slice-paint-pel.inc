void
vips_region_paint_pel(VipsRegion *reg, const VipsRect *r, const VipsPel *ink)
{
	VipsRect ovl;

	vips_rect_intersectrect(r, &reg->valid, &ovl);
	if (!vips_rect_isempty(&ovl)) {
		int ps = VIPS_IMAGE_SIZEOF_PEL(reg->im);
		int ws = ovl.width * ps;
		int ls = VIPS_REGION_LSKIP(reg);

		VipsPel *to, *q;
		int x, y, z;

		/* We plot the first line pointwise, then memcpy() it for the
		 * subsequent lines.
		 */
		to = VIPS_REGION_ADDR(reg, ovl.left, ovl.top);

		q = to;
		for (x = 0; x < ovl.width; x++) {
			/* Faster than memcpy() for about n<20.
			 */
			for (z = 0; z < ps; z++)
				q[z] = ink[z];

			q += ps;
		}

		q = to + ls;
		for (y = 1; y < ovl.height; y++) {
			memcpy(q, to, ws);
			q += ls;
		}
	}
}
