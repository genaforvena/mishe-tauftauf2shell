static gboolean
ReadJeffsImage (FILE       *fd,
                guchar     *dest,
                guchar      bpp,
                gint        len,
                gint        height,
                gboolean    alpha_frame,
                GimpImage **image,
                GError    **error)
{
  guchar    block_size = 255;
  z_stream  zs;
  guchar    block[255];
  guchar   *compressed;
  guchar   *indexes;
  guint     data_size;
  guint     count = 0;
  guint     pos   = 0;
  guint     mask  = 0;
  gint      ret;

  /* Indexes are stored as 1, 2, 4, or 8 bits per pixel
   * in the uncompressed image. */
  if (bpp < 1 || bpp > 8)
    {
      read_error (_("image data"), *image, error);
      return FALSE;
    }

  for (gint i = 7; i > 7 - bpp; i--)
    {
      if (i >= 0)
        mask |= 1 << i;
    }

  data_size = len * height;
  if (alpha_frame)
    data_size *= 2;
  compressed = g_try_malloc (data_size * 255);
  indexes    = g_try_malloc (data_size);

  if (compressed == NULL ||
      indexes    == NULL)
    {
      read_error (_("image data"), *image, error);
      g_free (compressed);
      g_free (indexes);
      return FALSE;
    }

  /* Image data is stored as a zlib stream, arbitrarily broken
   * in chunks of 255 bytes or less. We read in the chunk size,
   * then that many bytes of compressed data to recreate the
   * full zlib stream. */
  while (block_size != 0)
    {
      if (! ReadOK (fd, &block_size, 1))
        {
          read_error (_("image data"), *image, error);
          g_free (compressed);
          g_free (indexes);
          return FALSE;
        }
      if (block_size == 0)
        break;

      if (! ReadOK (fd, block, block_size))
        {
          read_error (_("image data"), *image, error);
          g_free (compressed);
          g_free (indexes);
          return FALSE;
        }

      for (gint i = 0; i < block_size; i++)
        {
          if ((i + count) >= (data_size * 255))
            {
              read_error (_("image data"), *image, error);
              g_free (compressed);
              g_free (indexes);
              return FALSE;
            }

          compressed[i + count] = block[i];
        }

      count += block_size;
    }

  zs.next_in   = (guchar *) compressed;
  zs.avail_in  = count;
  zs.next_out  = (guchar *) indexes;
  zs.avail_out = len * height;
  zs.zalloc    = Z_NULL;
  zs.zfree     = Z_NULL;
  zs.opaque    = Z_NULL;

  if (inflateInit (&zs) != Z_OK)
    {
      read_error (_("image data"), *image, error);
      g_free (compressed);
      g_free (indexes);
      return FALSE;
    }
  ret = inflate (&zs, Z_NO_FLUSH);
  if (ret != Z_OK && ret != Z_STREAM_END)
    {
      read_error (_("inflate failed"), *image, error);
      inflateEnd (&zs);
      g_free (compressed);
      g_free (indexes);
      return FALSE;
    }

  /* We then extract the indexes based on the bits per pixel
   * set in the header */
  for (gint i = 0; i < zs.total_out; i++)
    {
      for (gint j = 0; j < 8; j += bpp)
        {
          if (pos >= data_size)
            break;

          dest[pos++] = (indexes[i] & (mask >> j)) >> (8 - bpp - j);

          if (alpha_frame)
            {
              dest[pos] = (dest[pos - 1] == Gif89.transparent) ? 0 : 255;
              pos++;
            }
        }
    }
  g_free (indexes);
  g_free (compressed);
  inflateEnd (&zs);

  return TRUE;
}
