// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/slab.h>
#include <asm/unaligned.h>
#include <linux/buffer_head.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

static int __exfat_ent_get(struct super_block *sb, unsigned int loc,
		unsigned int *content)
{
	unsigned int off, _content;
	unsigned long long sec;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;

	sec = sbi->FAT1_start_sector + (loc >> (sb->s_blocksize_bits-2));
	off = (loc << 2) & (sb->s_blocksize - 1);

	bh = sb_bread(sb, sec);
	if (!bh)
		return -EIO;

	_content = le32_to_cpu(*(__le32 *)(&bh->b_data[off]));

	/* remap reserved clusters to simplify code */
	if (_content >= CLUSTER_32(0xFFFFFFF8))
		_content = EOF_CLUSTER;

	*content = CLUSTER_32(_content);
	brelse(bh);
	return 0;
}

int exfat_ent_set(struct super_block *sb, unsigned int loc,
		unsigned int content)
{
	unsigned int off;
	unsigned long long sec;
	__le32 *fat_entry;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;

	sec = sbi->FAT1_start_sector + (loc >> (sb->s_blocksize_bits-2));
	off = (loc << 2) & (sb->s_blocksize - 1);

	bh = sb_bread(sb, sec);
	if (!bh)
		return -EIO;

	fat_entry = (__le32 *)&(bh->b_data[off]);
	*fat_entry = cpu_to_le32(content);
	exfat_update_bh(sb, bh, 0);
	brelse(bh);
	return 0;
}

static inline bool is_reserved_cluster(unsigned int clus)
{
	if (clus == FREE_CLUSTER || clus == EOF_CLUSTER || clus == BAD_CLUSTER)
		return true;
	return false;
}

static inline bool is_valid_cluster(struct exfat_sb_info *sbi,
		unsigned int clus)
{
	if (clus < BASE_CLUSTER || sbi->num_clusters <= clus)
		return false;
	return true;
}

int exfat_ent_get(struct super_block *sb, unsigned int loc,
		unsigned int *content)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	int err;

	if (!is_valid_cluster(sbi, loc)) {
		exfat_fs_error(sb, "invalid access to FAT (entry 0x%08x)",
			loc);
		return -EIO;
	}

	err = __exfat_ent_get(sb, loc, content);
	if (err) {
		exfat_fs_error(sb,
			"failed to access to FAT (entry 0x%08x, err:%d)",
			loc, err);
		return err;
	}

	if (!is_reserved_cluster(*content) &&
			!is_valid_cluster(sbi, *content)) {
		exfat_fs_error(sb,
			"invalid access to FAT (entry 0x%08x) bogus content (0x%08x)",
			loc, *content);
		return -EIO;
	}

	if (*content == FREE_CLUSTER) {
		exfat_fs_error(sb,
			"invalid access to FAT free cluster (entry 0x%08x)",
			loc);
		return -EIO;
	}

	if (*content == BAD_CLUSTER) {
		exfat_fs_error(sb,
			"invalid access to FAT bad cluster (entry 0x%08x)",
			loc);
		return -EIO;
	}

	return 0;
}

int exfat_chain_cont_cluster(struct super_block *sb, unsigned int chain,
		unsigned int len)
{
	if (!len)
		return 0;

	while (len > 1) {
		if (exfat_ent_set(sb, chain, chain + 1))
			return -EIO;
		chain++;
		len--;
	}

	if (exfat_ent_set(sb, chain, EOF_CLUSTER))
		return -EIO;
	return 0;
}

int exfat_free_cluster(struct super_block *sb, struct exfat_chain *p_chain)
{
	unsigned int num_clusters = 0;
	unsigned int clu;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	/* invalid cluster number */
	if (p_chain->dir == FREE_CLUSTER || p_chain->dir == EOF_CLUSTER)
		return 0;

	/* no cluster to truncate */
	if (p_chain->size == 0)
		return 0;

	/* check cluster validation */
	if ((p_chain->dir < 2) && (p_chain->dir >= sbi->num_clusters)) {
		exfat_msg(sb, KERN_ERR, "invalid start cluster (%u)",
				p_chain->dir);
		return -EIO;
	}

	exfat_set_sb_dirty(sb);
	clu = p_chain->dir;

	if (p_chain->flags == 0x03) {
		do {
			exfat_clr_alloc_bitmap(sb, clu-2);
			clu++;

			num_clusters++;
		} while (num_clusters < p_chain->size);
	} else {
		do {
			exfat_clr_alloc_bitmap(sb, (clu - BASE_CLUSTER));

			if (exfat_get_next_cluster(sb, &clu))
				goto out;

			num_clusters++;
		} while (clu != EOF_CLUSTER);
	}

out:
	sbi->used_clusters -= num_clusters;
	return 0;
}

int exfat_find_last_cluster(struct super_block *sb, struct exfat_chain *p_chain,
		unsigned int *ret_clu)
{
	unsigned int clu, next;
	unsigned int count = 0;

	next = p_chain->dir;
	if (p_chain->flags == 0x03) {
		*ret_clu = next + p_chain->size - 1;
		return 0;
	}

	do {
		count++;
		clu = next;
		if (exfat_ent_get(sb, clu, &next))
			return -EIO;
	} while (next != EOF_CLUSTER);

	if (p_chain->size != count) {
		exfat_fs_error(sb,
			"bogus directory size (clus : ondisk(%d) != counted(%d))",
			p_chain->size, count);
		return -EIO;
	}

	*ret_clu = clu;
	return 0;
}

int exfat_clear_cluster(struct inode *inode, unsigned int clu)
{
	unsigned long long s, n;
	struct super_block *sb = inode->i_sb;
	int ret = 0;
	struct buffer_head *bh = NULL;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	s = exfat_cluster_to_sector(sbi, clu);
	n = s + sbi->sect_per_clus;

	if (IS_DIRSYNC(inode)) {
		ret = exfat_zeroed_cluster(sb, s, sbi->sect_per_clus);
		if (ret == -EIO)
			return ret;
	}

	/* Trying buffered zero writes
	 * if it doesn't have DIRSYNC or exfat_zeroed_cluster() returned -EAGAIN
	 */
	for ( ; s < n; s++) {
		bh = sb_getblk(sb, s);
		if (!bh) {
			ret = -ENOMEM;
			goto out;
		}
		memset(bh->b_data, 0x0, sb->s_blocksize);
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		brelse(bh);
	}
out:
	return ret;
}

int exfat_alloc_cluster(struct super_block *sb, unsigned int num_alloc,
		struct exfat_chain *p_chain)
{
	int ret = -ENOSPC;
	unsigned int num_clusters = 0, total_cnt;
	unsigned int hint_clu, new_clu, last_clu = EOF_CLUSTER;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	/* Check if there are reserved clusters up to max. */
	if ((sbi->used_clusters + sbi->reserved_clusters) >=
			(sbi->num_clusters - BASE_CLUSTER))
		return -ENOSPC;

	total_cnt = sbi->num_clusters - BASE_CLUSTER;

	if (unlikely(total_cnt < sbi->used_clusters)) {
		exfat_fs_error_ratelimit(sb,
			"%s: invalid used clusters(t:%u,u:%u)\n",
			__func__, total_cnt, sbi->used_clusters);
		return -EIO;
	}

	if (num_alloc > total_cnt - sbi->used_clusters)
		return -ENOSPC;

	hint_clu = p_chain->dir;
	/* find new cluster */
	if (hint_clu == EOF_CLUSTER) {
		if (sbi->clu_srch_ptr < BASE_CLUSTER) {
			exfat_msg(sb, KERN_ERR,
				"sbi->clu_srch_ptr is invalid (%u)\n",
				sbi->clu_srch_ptr);
			sbi->clu_srch_ptr = BASE_CLUSTER;
		}

		hint_clu = exfat_test_alloc_bitmap(sb,
				sbi->clu_srch_ptr - BASE_CLUSTER);
		if (hint_clu == EOF_CLUSTER)
			return -ENOSPC;
	}

	/* check cluster validation */
	if ((hint_clu < BASE_CLUSTER) && (hint_clu >= sbi->num_clusters)) {
		exfat_msg(sb, KERN_ERR, "hint_cluster is invalid (%u)\n",
			hint_clu);
		hint_clu = BASE_CLUSTER;
		if (p_chain->flags == 0x03) {
			if (exfat_chain_cont_cluster(sb, p_chain->dir,
					num_clusters))
				return -EIO;
			p_chain->flags = 0x01;
		}
	}

	exfat_set_sb_dirty(sb);

	p_chain->dir = EOF_CLUSTER;

	while ((new_clu = exfat_test_alloc_bitmap(sb,
			hint_clu - BASE_CLUSTER)) != EOF_CLUSTER) {
		if ((new_clu != hint_clu) && (p_chain->flags == 0x03)) {
			if (exfat_chain_cont_cluster(sb, p_chain->dir,
					num_clusters)) {
				ret = -EIO;
				goto error;
			}
			p_chain->flags = 0x01;
		}

		/* update allocation bitmap */
		if (exfat_set_alloc_bitmap(sb, new_clu - BASE_CLUSTER)) {
			ret = -EIO;
			goto error;
		}

		num_clusters++;

		/* update FAT table */
		if (p_chain->flags == 0x01) {
			if (exfat_ent_set(sb, new_clu, EOF_CLUSTER)) {
				ret = -EIO;
				goto error;
			}
		}

		if (p_chain->dir == EOF_CLUSTER) {
			p_chain->dir = new_clu;
		} else if (p_chain->flags == 0x01) {
			if (exfat_ent_set(sb, last_clu, new_clu)) {
				ret = -EIO;
				goto error;
			}
		}
		last_clu = new_clu;

		if ((--num_alloc) == 0) {
			sbi->clu_srch_ptr = hint_clu;
			sbi->used_clusters += num_clusters;

			p_chain->size += num_clusters;
			return 0;
		}

		hint_clu = new_clu + 1;
		if (hint_clu >= sbi->num_clusters) {
			hint_clu = BASE_CLUSTER;

			if (p_chain->flags == 0x03) {
				if (exfat_chain_cont_cluster(sb, p_chain->dir,
						num_clusters)) {
					ret = -EIO;
					goto error;
				}
				p_chain->flags = 0x01;
			}
		}
	}
error:
	if (num_clusters)
		exfat_free_cluster(sb, p_chain);
	return ret;
}

int exfat_count_num_clusters(struct super_block *sb,
		struct exfat_chain *p_chain, unsigned int *ret_count)
{
	unsigned int i, count;
	unsigned int clu;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	if (!p_chain->dir || p_chain->dir == EOF_CLUSTER) {
		*ret_count = 0;
		return 0;
	}

	if (p_chain->flags == 0x03) {
		*ret_count = p_chain->size;
		return 0;
	}

	clu = p_chain->dir;
	count = 0;
	for (i = BASE_CLUSTER; i < sbi->num_clusters; i++) {
		count++;
		if (exfat_ent_get(sb, clu, &clu))
			return -EIO;
		if (clu == EOF_CLUSTER)
			break;
	}

	*ret_count = count;
	return 0;
}

int exfat_mirror_bhs(struct super_block *sb, unsigned long long sec,
		struct buffer_head *bh)
{
	struct buffer_head *c_bh;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned long long sec2;
	int err = 0;

	if (sbi->FAT2_start_sector != sbi->FAT1_start_sector) {
		sec2 = sec - sbi->FAT1_start_sector + sbi->FAT2_start_sector;
		c_bh = sb_getblk(sb, sec2);
		if (!c_bh) {
			err = -ENOMEM;
			goto out;
		}
		memcpy(c_bh->b_data, bh->b_data, sb->s_blocksize);
		set_buffer_uptodate(c_bh);
		mark_buffer_dirty(c_bh);
		if (sb->s_flags & SB_SYNCHRONOUS)
			err = sync_dirty_buffer(c_bh);
		brelse(c_bh);
	}
out:
	return err;
}
