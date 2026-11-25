L_BYTEA *
l_byteaCreate(size_t  nbytes)
{
L_BYTEA  *ba;

    if (nbytes <= 0 || nbytes > MaxArraySize)
        nbytes = InitialArraySize;
    ba = (L_BYTEA *)LEPT_CALLOC(1, sizeof(L_BYTEA));
    ba->data = (l_uint8 *)LEPT_CALLOC(nbytes + 1, sizeof(l_uint8));
    if (!ba->data) {
        l_byteaDestroy(&ba);
        return (L_BYTEA *)ERROR_PTR("ba array not made", __func__, NULL);
    }
    ba->nalloc = nbytes + 1;
    ba->refcount = 1;
    return ba;
}
