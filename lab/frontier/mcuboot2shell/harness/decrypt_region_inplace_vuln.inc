/* Verbatim from mcu-tools/mcuboot parent commit
 * 099379647ada83b31cc094e4c0c94a7d0e895639 (fix 6e1465c38e3d),
 * boot/boot_serial/src/boot_serial_encryption.c:118-204. No edits. */
static int
decrypt_region_inplace(struct enc_key_data *enc_data,
                       const struct flash_area *fap,
                       struct image_header *hdr,
                       uint32_t off, uint32_t sz)
{
    uint32_t bytes_copied;
    int chunk_sz;
    int rc;
    uint32_t tlv_off;
    size_t blk_off;
    uint16_t idx;
    uint32_t blk_sz;
    uint8_t buf[sz] __attribute__((aligned));
    assert(sz <= sizeof buf);

    bytes_copied = 0;
    while (bytes_copied < sz) {
        if (sz - bytes_copied > sizeof buf) {
            chunk_sz = sizeof buf;
        } else {
            chunk_sz = sz - bytes_copied;
        }

        rc = flash_area_read(fap, off + bytes_copied, buf, chunk_sz);
        if (rc != 0) {
            rc = BOOT_EFLASH;
            goto out;
        }

        if (IS_ENCRYPTED(hdr)) {
            blk_sz = chunk_sz;
            idx = 0;
            if (off + bytes_copied < hdr->ih_hdr_size) {
                /* do not decrypt header */
                if (hdr->ih_hdr_size > (off + bytes_copied + chunk_sz)) {
                    /* all bytes in header, skip decryption */
                    blk_sz = 0;
                }
                else {
                    blk_sz = off + bytes_copied + chunk_sz - hdr->ih_hdr_size;
                }

                blk_off = 0;
                idx = hdr->ih_hdr_size;
            } else {
                blk_off = ((off + bytes_copied) - hdr->ih_hdr_size) & 0xf;
            }
            tlv_off = BOOT_TLV_OFF(hdr);
            if (off + bytes_copied + chunk_sz > tlv_off) {
                /* do not decrypt TLVs */
                if (off + bytes_copied >= tlv_off) {
                    blk_sz = 0;
                } else {
                    blk_sz = tlv_off - (off + bytes_copied);
                }
            }
            rc = boot_enc_decrypt(enc_data,
                    (off + bytes_copied + idx) - hdr->ih_hdr_size, blk_sz,
                    blk_off, &buf[idx]);
            if (rc != 0) {
                rc = BOOT_EBADIMAGE;
                goto out;
            }
        }
        rc = boot_erase_region(fap, off + bytes_copied, chunk_sz, false);
        if (rc != 0) {
            rc = BOOT_EFLASH;
            goto out;
        }
        rc = flash_area_write(fap, off + bytes_copied, buf, chunk_sz);
        if (rc != 0) {
            rc = BOOT_EFLASH;
            goto out;
        }

        bytes_copied += chunk_sz;

        MCUBOOT_WATCHDOG_FEED();
    }

    rc = 0;
out:
    /* buf may hold decrypted image plaintext; clear it before returning. */
    bootutil_wipe_memory(buf, sizeof buf);
    return rc;
}
