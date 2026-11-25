/* Verbatim from mcu-tools/mcuboot commit
 * 6e1465c38e3dba4849caed650ad83d0ba5c277b6 (PR #3006),
 * boot/boot_serial/src/boot_serial_encryption.c:118-210. No edits. */
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
    uint32_t idx;
    uint32_t blk_sz;
    uint32_t abs_off;
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
            abs_off = off + bytes_copied;
            blk_sz = chunk_sz;
            idx = 0;
            if (abs_off < hdr->ih_hdr_size) {
                /* do not decrypt header */
                if (hdr->ih_hdr_size >= abs_off + chunk_sz) {
                    /* all bytes in header, skip decryption */
                    blk_sz = 0;
                }
                else {
                    idx = hdr->ih_hdr_size - abs_off;
                    blk_sz = chunk_sz - idx;
                }

                blk_off = 0;
            } else {
                blk_off = (abs_off - hdr->ih_hdr_size) & 0xf;
            }
            tlv_off = BOOT_TLV_OFF(hdr);
            if (blk_sz > 0 && abs_off + chunk_sz > tlv_off) {
                /* do not decrypt TLVs */
                if (abs_off >= tlv_off) {
                    blk_sz = 0;
                } else {
                    blk_sz = tlv_off - abs_off - idx;
                }
            }
            if (idx > (uint32_t)chunk_sz || blk_sz > (uint32_t)chunk_sz - idx) {
                rc = BOOT_EBADIMAGE;
                goto out;
            }
            rc = boot_enc_decrypt(enc_data,
                    (abs_off + idx) - hdr->ih_hdr_size, blk_sz,
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
