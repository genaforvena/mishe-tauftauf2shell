L_BYTEA *
l_byteaInitFromStream(FILE  *fp)
{
l_uint8  *data;
size_t    nbytes;
L_BYTEA  *ba;

    if (!fp)
        return (L_BYTEA *)ERROR_PTR("stream not defined", __func__, NULL);

    if ((data = l_binaryReadStream(fp, &nbytes)) == NULL)
        return (L_BYTEA *)ERROR_PTR("data not read", __func__, NULL);
    if (nbytes > MaxArraySize) {
        LEPT_FREE(data);
        return (L_BYTEA *)ERROR_PTR("stream too large", __func__, NULL);
    }
    if ((ba = l_byteaCreate(nbytes)) == NULL) {
        LEPT_FREE(data);
        return (L_BYTEA *)ERROR_PTR("ba not made", __func__, NULL);
    }
    memcpy(ba->data, data, nbytes);
    ba->size = nbytes;
    LEPT_FREE(data);
    return ba;
}
