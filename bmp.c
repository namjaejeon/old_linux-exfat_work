// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/slab.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

/*
 *  Allocation Bitmap Management Functions
 */
int load_alloc_bmp(struct super_block *sb)
{
	//	int ret;
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
