#line 282 "THeaderTransport.cpp.parent"
void THeaderTransport::untransform(uint8_t* ptr, uint32_t sz) {
  // Update the transform buffer size if needed
  resizeTransformBuffer();

  for (vector<uint16_t>::const_iterator it = readTrans_.begin(); it != readTrans_.end(); ++it) {
    const uint16_t transId = *it;

    if (transId == ZLIB_TRANSFORM) {
      z_stream stream;
      int err;

      stream.next_in = ptr;
      stream.avail_in = sz;

      // Setting these to 0 means use the default free/alloc functions
      stream.zalloc = (alloc_func)nullptr;
      stream.zfree = (free_func)nullptr;
      stream.opaque = (voidpf)nullptr;
      err = inflateInit(&stream);
      if (err != Z_OK) {
        throw TApplicationException(TApplicationException::MISSING_RESULT,
                                    "Error while zlib deflateInit");
      }
      stream.next_out = tBuf_.get();
      stream.avail_out = tBufSize_;
      err = inflate(&stream, Z_FINISH);
      if (err != Z_STREAM_END || stream.avail_out == 0) {
        throw TApplicationException(TApplicationException::MISSING_RESULT,
                                    "Error while zlib deflate");
      }
      sz = stream.total_out;

      err = inflateEnd(&stream);
      if (err != Z_OK) {
        throw TApplicationException(TApplicationException::MISSING_RESULT,
                                    "Error while zlib deflateEnd");
      }

      memcpy(ptr, tBuf_.get(), sz);
    } else {
      throw TApplicationException(TApplicationException::MISSING_RESULT, "Unknown transform");
    }
  }

  setReadBuffer(ptr, sz);
}
