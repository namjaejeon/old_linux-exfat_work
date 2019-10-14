// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/blkdev.h>
#include <linux/slab.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

static unsigned char free_bit[] = {
	0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2,/*  0 ~  19*/
	0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3,/* 20 ~  39*/
	0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2,/* 40 ~  59*/
	0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,/* 60 ~  79*/
	0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2,/* 80 ~  99*/
	0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3,/*100 ~ 119*/
	0, 1, 0, 2, 0, 1, 0, 7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2,/*120 ~ 139*/
	0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5,/*140 ~ 159*/
	0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2,/*160 ~ 179*/
	0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 6, 0, 1, 0, 2, 0, 1, 0, 3,/*180 ~ 199*/
	0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2,/*200 ~ 219*/
	0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4,/*220 ~ 239*/
	0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0                /*240 ~ 254*/
};

static unsigned char used_bit[] = {
	0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3,/*  0 ~  19*/
	2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4,/* 20 ~  39*/
	2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5,/* 40 ~  59*/
	4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,/* 60 ~  79*/
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4,/* 80 ~  99*/
	3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,/*100 ~ 119*/
	4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4,/*120 ~ 139*/
	3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,/*140 ~ 159*/
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5,/*160 ~ 179*/
	4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 2, 3, 3, 4, 3, 4, 4, 5,/*180 ~ 199*/
	3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6,/*200 ~ 219*/
	5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,/*220 ~ 239*/
	4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8             /*240 ~ 255*/
};

/*
 *  Allocation Bitmap Management Functions
 */
int load_alloc_bmp(struct super_block *sb)
{
	unsigned int i, j, map_size, type, need_map_size;
	unsigned long long sector;
	struct exfat_chain clu;
	struct exfat_bmap_dentry *ep;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	clu.dir = sbi->root_dir;
	clu.flags = 0x01;

	while (!IS_CLUS_EOF(clu.dir)) {
		for (i = 0; i < sbi->dentries_per_clu; i++) {
			ep = (struct exfat_bmap_dentry *) get_dentry_in_dir(sb, &clu, i,
				NULL);
			if (!ep)
				return -EIO;

			type = exfat_get_entry_type((struct exfat_dentry *) ep);

			if (type == TYPE_UNUSED)
				break;
			if (type != TYPE_BITMAP)
				continue;

			if (ep->flags == 0x0) {
				sbi->map_clu  = le32_to_cpu(ep->start_clu);
				map_size =
					(unsigned int) le64_to_cpu(ep->size);

				need_map_size = (((sbi->num_clusters -
						CLUS_BASE) - 1) >> 3) + 1;
				if (need_map_size != map_size) {
					exfat_msg(sb, KERN_ERR,
						"bogus allocation bitmap size(need : %u, cur : %u)",
						need_map_size, map_size);
					/*
					 * Only allowed when bogus allocation
					 * bitmap size is large
					 */
					if (need_map_size > map_size)
						return -EIO;
				}
				sbi->map_sectors = ((need_map_size - 1) >>
					(sb->s_blocksize_bits)) + 1;
				sbi->vol_amap =
					kmalloc((sizeof(struct buffer_head *) *
						sbi->map_sectors), GFP_KERNEL);
				if (!sbi->vol_amap)
					return -ENOMEM;

				sector = CLUS_TO_SECT(sbi, sbi->map_clu);

				for (j = 0; j < sbi->map_sectors; j++) {
					sbi->vol_amap[j] =
						sb_bread(sb, sector+j);
					if (!sbi->vol_amap[j]) {
						/*
						 * release all buffers and
						 * free vol_amap
						 */
						i = 0;
						while (i < j)
							brelse(sbi->vol_amap[i++]);

						/* kfree(NULL) is safe */
						kfree(sbi->vol_amap);
						sbi->vol_amap = NULL;
						return -EIO;
					}
				}

				sbi->pbr_bh = NULL;
				return 0;
			}
		}

		if (get_next_clus_safe(sb, &clu.dir))
			return -EIO;
	}

	return -EINVAL;
}

void free_alloc_bmp(struct super_block *sb)
{
	int i;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	brelse(sbi->pbr_bh);

	for (i = 0; i < sbi->map_sectors; i++)
		__brelse(sbi->vol_amap[i]);

	/* kfree(NULL) is safe */
	kfree(sbi->vol_amap);
	sbi->vol_amap = NULL;
}

void sync_alloc_bmp(struct super_block *sb)
{
	int i;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	if (sbi->vol_amap == NULL)
		return;

	for (i = 0; i < sbi->map_sectors; i++)
		sync_dirty_buffer(sbi->vol_amap[i]);
}

/* WARN :
 * If the value of "clu" is 0, it means cluster 2 which is
 * the first cluster of cluster heap.
 */
int set_alloc_bitmap(struct super_block *sb, unsigned int clu)
{
	int i, b;
	unsigned long long sector;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	i = clu >> (sb->s_blocksize_bits + 3);
	b = clu & (unsigned int)((sb->s_blocksize << 3) - 1);

	sector = CLUS_TO_SECT(sbi, sbi->map_clu) + i;
	bitmap_set((unsigned long *)(sbi->vol_amap[i]->b_data), b, 1);

	set_buffer_uptodate(sbi->vol_amap[i]);
	mark_buffer_dirty(sbi->vol_amap[i]);

	return 0;
}

/* WARN :
 * If the value of "clu" is 0, it means cluster 2 which is
 * the first cluster of cluster heap.
 */
void clr_alloc_bitmap(struct super_block *sb, unsigned int clu)
{
	int i, b;
	unsigned long long sector;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_mount_options *opts = &sbi->options;

	i = clu >> (sb->s_blocksize_bits + 3);
	b = clu & (unsigned int)((sb->s_blocksize << 3) - 1);

	sector = CLUS_TO_SECT(sbi, sbi->map_clu) + i;

	bitmap_clear((unsigned long *)(sbi->vol_amap[i]->b_data), b, 1);

	set_buffer_uptodate(sbi->vol_amap[i]);
	mark_buffer_dirty(sbi->vol_amap[i]);

	if (opts->discard) {
		int ret_discard;

		ret_discard = sb_issue_discard(sb, CLUS_TO_SECT(sbi, clu+2),
				(1 << sbi->sect_per_clus_bits), GFP_NOFS, 0);

		if (ret_discard == -EOPNOTSUPP) {
			exfat_msg(sb, KERN_ERR,
					"discard not supported by device, disabling");
			opts->discard = 0;
		}
	}
}

/* WARN :
 * If the value of "clu" is 0, it means cluster 2 which is
 * the first cluster of cluster heap.
 */
unsigned int test_alloc_bitmap(struct super_block *sb, unsigned int clu)
{
	unsigned int i, map_i, map_b;
	unsigned int clu_base, clu_free;
	unsigned char k, clu_mask;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	clu_base = (clu & ~(0x7)) + 2;
	clu_mask = (1 << (clu - clu_base + 2)) - 1;

	map_i = clu >> (sb->s_blocksize_bits + 3);
	map_b = (clu >> 3) & (unsigned int)(sb->s_blocksize - 1);

	for (i = 2; i < sbi->num_clusters; i += 8) {
		k = *(((unsigned char *) sbi->vol_amap[map_i]->b_data) + map_b);
		if (clu_mask > 0) {
			k |= clu_mask;
			clu_mask = 0;
		}
		if (k < 0xFF) {
			clu_free = clu_base + free_bit[k];
			if (clu_free < sbi->num_clusters)
				return clu_free;
		}
		clu_base += 8;

		if (((++map_b) >= (unsigned int)sb->s_blocksize) ||
				(clu_base >= sbi->num_clusters)) {
			if ((++map_i) >= sbi->map_sectors) {
				clu_base = 2;
				map_i = 0;
			}
			map_b = 0;
		}
	}

	return CLUS_EOF;
}

int exfat_count_used_clusters(struct super_block *sb, unsigned int *ret_count)
{
	unsigned int count = 0;
	unsigned int i, map_i, map_b;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int total_clus = sbi->num_clusters - 2;

	map_i = map_b = 0;

	for (i = 0; i < total_clus; i += 8) {
		unsigned char k = *(((unsigned char *)
					sbi->vol_amap[map_i]->b_data) + map_b);

		count += used_bit[k];
		if ((++map_b) >= (unsigned int)sb->s_blocksize) {
			map_i++;
			map_b = 0;
		}
	}

	/* FIXME : abnormal bitmap count should be handled as more smart */
	if (total_clus < count)
		count = total_clus;

	*ret_count = count;
	return 0;
}
