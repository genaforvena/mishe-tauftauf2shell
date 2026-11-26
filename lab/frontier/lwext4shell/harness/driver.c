/* Stand-in driver for verbatim ext4_fs_init_inode_bitmap() bytes pinned from
 * lwext4 src/ext4_fs.c at v1.0.0 (vulnerable) and b9c842f1 (fix).
 * No lwext4 library build: block device, transaction and checksum hooks are
 * stubs; the pinned function body itself is never edited. */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EOK 0
#define EIO 5

typedef uint64_t ext4_fsblk_t;

struct ext4_sblock {
	uint32_t inodes_per_group;
	uint32_t block_size;
};

struct ext4_fs {
	struct ext4_sblock sb;
	void *bdev;
};

struct ext4_bgroup {
	ext4_fsblk_t inode_bitmap;
};

struct ext4_block_group_ref {
	struct ext4_fs *fs;
	struct ext4_bgroup *block_group;
	uint32_t index;
	bool dirty;
};

struct ext4_block {
	uint8_t *data;
	void *buf;
};

struct fake_bdev {
	uint32_t block_size;
};

#define ext4_get32(sb, field) ((sb)->field)

static uint32_t
ext4_sb_get_block_size(struct ext4_sblock *sb)
{
	return sb->block_size;
}

static ext4_fsblk_t
ext4_bg_get_inode_bitmap(struct ext4_bgroup *bg, struct ext4_sblock *sb)
{
	(void) sb;
	return bg->inode_bitmap;
}

static uint8_t *g_last_data;

static int
ext4_trans_block_get_noread(void *bdev, struct ext4_block *b,
			    ext4_fsblk_t addr)
{
	struct fake_bdev *dev = (struct fake_bdev *) bdev;
	(void) addr;
#ifdef PLAIN_MODE
	/* A readable tail keeps the out-of-bounds byte observable after the
	 * pinned function returns; the first dev->block_size bytes are the
	 * logical one-block object. */
	b->data = (uint8_t *) malloc((size_t) dev->block_size + 64);
	if (!b->data)
		return EIO;
	memset(b->data, 0x4d, (size_t) dev->block_size + 64);
#else
	b->data = (uint8_t *) malloc(dev->block_size);
	if (!b->data)
		return EIO;
	memset(b->data, 0, dev->block_size);
#endif
	b->buf = b->data;
	g_last_data = b->data;
	return EOK;
}

/* ASan-visible bit set: the pinned function writes one byte past the logical
 * 4096-byte object when the image-derived start bit is past its end. */
static void
ext4_bmap_bit_set(void *bitmap, uint32_t bit)
{
	uint8_t *p = (uint8_t *) bitmap;
	p[bit >> 3] |= (uint8_t) (1u << (bit & 7));
}

static void ext4_trans_set_block_dirty(void *buf) { (void) buf; }
static void ext4_ialloc_set_bitmap_csum(struct ext4_sblock *sb,
					struct ext4_bgroup *bg, uint8_t *data)
{
	(void) sb; (void) bg; (void) data;
}

static int
ext4_block_set(void *bdev, struct ext4_block *b)
{
	(void) bdev;
#ifndef PLAIN_MODE
	free(b->data);
	b->data = NULL;
#endif
	return EOK;
}

#ifdef VARIANT_FIXED
#include "pins/lwext4-fixed.inc"
#else
#include "pins/lwext4-vulnerable.inc"
#endif

int
main(int argc, char **argv)
{
	const char *mode = (argc > 1) ? argv[1] : "safe";
	uint32_t ipg;
	if (!strcmp(mode, "attack"))
		ipg = 32777;       /* ipg+7 = 32784 -> 4098-byte zero fill */
	else if (!strcmp(mode, "attack2"))
		ipg = 32778;       /* same length, different chosen bit byte */
	else
		ipg = 8192, mode = "safe";

	struct fake_bdev dev = { 4096 };
	struct ext4_sblock sb = { ipg, dev.block_size };
	struct ext4_bgroup bg = { 7 };
	struct ext4_fs fs = { sb, &dev };
	struct ext4_block_group_ref ref = { &fs, &bg, 0, false };

	int rc = ext4_fs_init_inode_bitmap(&ref);
	printf("MODE=%s IPG=%u RC=%d DIRTY=%d\n", mode, ipg, rc, ref.dirty);
#ifdef PLAIN_MODE
	printf("CANARY_AT=%u FIRST=", dev.block_size);
	for (unsigned i = 0; i < 8; i++)
		printf("%02x", g_last_data[dev.block_size + i]);
	printf("\n");
#endif
	return 0;
}
