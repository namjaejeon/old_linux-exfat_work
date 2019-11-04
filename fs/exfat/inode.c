// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/init.h>
#include <linux/buffer_head.h>
#include <linux/mpage.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/time.h>
#include <linux/writeback.h>
#include <linux/uio.h>
#include <linux/iversion.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

/* 2-level option flag */
#define BMAP_NOT_CREATE				0
#define BMAP_ADD_BLOCK				1
#define BMAP_ADD_CLUSTER			2
#define BLOCK_ADDED(bmap_ops)	(bmap_ops)

/* resize the file length */
static int __exfat_truncate(struct inode *inode, loff_t new_size)
{
	unsigned int num_clusters_new, num_clusters_da, num_clusters_phys;
	unsigned int last_clu = FREE_CLUSTER;
	struct exfat_chain clu;
	struct exfat_timestamp tm;
	struct exfat_dentry *ep, *ep2;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_entry_set_cache *es = NULL;
	int evict = (ei->dir.dir == DIR_DELETED) ? 1 : 0;

	/* check if the given file ID is opened */
	if ((ei->type != TYPE_FILE) && (ei->type != TYPE_DIR))
		return -EPERM;

	exfat_set_vol_flags(sb, VOL_DIRTY);

	/* Reserved count update */
	num_clusters_da =
		EXFAT_B_TO_CLU_ROUND_UP(EXFAT_I(inode)->i_size_aligned, sbi);
	num_clusters_new = EXFAT_B_TO_CLU_ROUND_UP(i_size_read(inode), sbi);
	num_clusters_phys =
		EXFAT_B_TO_CLU_ROUND_UP(EXFAT_I(inode)->i_size_ondisk, sbi);

	if ((num_clusters_da != num_clusters_phys) &&
			(num_clusters_new < num_clusters_da)) {
		/* Decrement reserved clusters
		 * n_reserved = num_clusters_da - max(new,phys)
		 */
		int n_reserved = (num_clusters_new > num_clusters_phys) ?
			(num_clusters_da - num_clusters_new) :
			(num_clusters_da - num_clusters_phys);

		sbi->reserved_clusters -= n_reserved;
		WARN_ON(sbi->reserved_clusters < 0);
	}

	clu.dir = ei->start_clu;
	clu.size = num_clusters_phys;
	clu.flags = ei->flags;

	if (new_size > 0) {
		/* Truncate FAT chain num_clusters after the first cluster
		 * num_clusters = min(new, phys);
		 */
		unsigned int num_clusters =
			(num_clusters_new < num_clusters_phys) ?
			num_clusters_new : num_clusters_phys;

		/* Follow FAT chain
		 * (defensive coding - works fine even with corrupted FAT table
		 */
		if (clu.flags == 0x03) {
			clu.dir += num_clusters;
			clu.size -= num_clusters;
		} else {
			while (num_clusters > 0) {
				last_clu = clu.dir;
				if (exfat_get_next_cluster(sb, &(clu.dir)))
					return -EIO;

				num_clusters--;
				clu.size--;
			}
		}
	} else if (new_size == 0) {
		ei->flags = 0x03;
		ei->start_clu = EOF_CLUSTER;
	}

	i_size_write(inode, new_size);

	if (ei->type == TYPE_FILE)
		ei->attr |= ATTR_ARCHIVE;

	/*
	 * clu.dir: free from
	 * clu.size: # of clusters to free (exFAT, 0x03 only), no fat_free if 0
	 * clu.flags: ei->flags (exFAT only)
	 */

	/* update the directory entry */
	if (!evict) {
		es = exfat_get_dentry_set(sb, &(ei->dir), ei->entry,
			ES_ALL_ENTRIES, &ep);
		if (!es)
			return -EIO;
		ep2 = ep + 1;

		exfat_set_entry_time(ep, exfat_tm_now(EXFAT_SB(sb), &tm),
			TM_MODIFY);
		ep->file_attr = cpu_to_le16(ei->attr);

		/* File size should be zero if there is no cluster allocated */
		if (ei->start_clu == EOF_CLUSTER)
			ep->stream_valid_size = ep->stream_size = 0;
		else {
			ep->stream_valid_size = cpu_to_le64(new_size);
			ep->stream_size = ep->stream_valid_size;
		}

		if (new_size == 0) {
			/* Any directory can not be truncated to zero */
			WARN_ON(ei->type != TYPE_FILE);

			ep2->stream_flags = 0x01;
			ep2->stream_start_clu = FREE_CLUSTER;
		}

		if (exfat_update_dir_chksum_with_entry_set(sb, es))
			return -EIO;
		exfat_release_dentry_set(es);

	}

	/* cut off from the FAT chain */
	if ((ei->flags == 0x01) && (last_clu != FREE_CLUSTER) &&
			(last_clu != EOF_CLUSTER)) {
		if (exfat_ent_set(sb, last_clu, EOF_CLUSTER))
			return -EIO;
	}

	/* invalidate cache and free the clusters */
	/* clear exfat cache */
	exfat_cache_inval_inode(inode);

	/* hint information */
	ei->hint_bmap.off = EOF_CLUSTER;
	ei->hint_bmap.clu = EOF_CLUSTER;
	if (ei->rwoffset > new_size)
		ei->rwoffset = new_size;

	/* hint_stat will be used if this is directory. */
	ei->hint_stat.eidx = 0;
	ei->hint_stat.clu = ei->start_clu;
	ei->hint_femp.eidx = EXFAT_HINT_NONE;

	/* free the clusters */
	if (exfat_free_cluster(sb, &clu))
		return -EIO;

	exfat_set_vol_flags(sb, VOL_CLEAN);

	return 0;
}

/* set the information of a given file
 * REMARK : This function does not need any file name on linux
 */
static int __exfat_write_inode(struct inode *inode, int sync)
{
	int ret = -EIO;
	unsigned long long on_disk_size;
	struct exfat_timestamp tm;
	struct exfat_dentry *ep, *ep2;
	struct exfat_entry_set_cache *es = NULL;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	unsigned char is_dir = (ei->type == TYPE_DIR) ? 1 : 0;
	struct exfat_dir_entry info;

	if (inode->i_ino == EXFAT_ROOT_INO)
		return 0;

	info.attr = exfat_make_attr(inode);
	info.size = i_size_read(inode);

	exfat_time_unix2fat(sbi, &inode->i_mtime, &info.modify_timestamp);
	exfat_time_unix2fat(sbi, &inode->i_ctime, &info.create_timestamp);
	exfat_time_unix2fat(sbi, &inode->i_atime, &info.access_timestamp);

	/* SKIP WRITING INODE :
	 * if the indoe is already unlinked,
	 * there is no need for updating inode
	 */
	if (ei->dir.dir == DIR_DELETED)
		return 0;

	if (is_dir && (ei->dir.dir == sbi->root_dir) && (ei->entry == -1))
		return 0;

	exfat_set_vol_flags(sb, VOL_DIRTY);

	/* get the directory entry of given file or directory */
	es = exfat_get_dentry_set(sb, &(ei->dir), ei->entry, ES_ALL_ENTRIES,
		&ep);
	if (!es)
		return -EIO;
	ep2 = ep + 1;

	ep->file_attr = cpu_to_le16(info.attr);

	/* set FILE_INFO structure using the acquired struct exfat_dentry */
	tm.sec  = info.create_timestamp.second;
	tm.min  = info.create_timestamp.minute;
	tm.hour = info.create_timestamp.hour;
	tm.day  = info.create_timestamp.day;
	tm.mon  = info.create_timestamp.month;
	tm.year = info.create_timestamp.year;
	exfat_set_entry_time(ep, &tm, TM_CREATE);

	tm.sec  = info.modify_timestamp.second;
	tm.min  = info.modify_timestamp.minute;
	tm.hour = info.modify_timestamp.hour;
	tm.day  = info.modify_timestamp.day;
	tm.mon  = info.modify_timestamp.month;
	tm.year = info.modify_timestamp.year;
	exfat_set_entry_time(ep, &tm, TM_MODIFY);

	/* File size should be zero if there is no cluster allocated */
	on_disk_size = info.size;

	if (ei->start_clu == EOF_CLUSTER)
		on_disk_size = 0;

	ep2->stream_valid_size = cpu_to_le64(on_disk_size);
	ep2->stream_size = ep2->stream_valid_size;

	es->sync = sync;
	ret = exfat_update_dir_chksum_with_entry_set(sb, es);
	exfat_release_dentry_set(es);
	return ret;
}

int exfat_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int ret;

	mutex_lock(&EXFAT_SB(inode->i_sb)->s_lock);
	ret = __exfat_write_inode(inode, wbc->sync_mode == WB_SYNC_ALL);
	mutex_unlock(&EXFAT_SB(inode->i_sb)->s_lock);

	return ret;
}

void exfat_sync_inode(struct inode *inode)
{
	lockdep_assert_held(&EXFAT_SB(inode->i_sb)->s_lock);
	__exfat_write_inode(inode, 1);
}

void exfat_truncate(struct inode *inode, loff_t size)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int blocksize = 1 << inode->i_blkbits;
	loff_t aligned_size;
	int err;

	mutex_lock(&sbi->s_lock);
	if (EXFAT_I(inode)->start_clu == 0) {
		/*
		 * Empty start_clu != ~0 (not allocated)
		 */
		exfat_fs_error(sb, "tried to truncate zeroed cluster.");
		goto out;
	}

	err = __exfat_truncate(inode, i_size_read(inode));
	if (err)
		goto out;

	inode->i_ctime = inode->i_mtime = current_time(inode);
	if (IS_DIRSYNC(inode))
		exfat_sync_inode(inode);
	else
		mark_inode_dirty(inode);

	inode->i_blocks = ((i_size_read(inode) + (sbi->cluster_size - 1)) &
			~(sbi->cluster_size - 1)) >> inode->i_blkbits;
out:
	aligned_size = i_size_read(inode);
	if (aligned_size & (blocksize - 1)) {
		aligned_size |= (blocksize - 1);
		aligned_size++;
	}

	if (EXFAT_I(inode)->i_size_ondisk > i_size_read(inode))
		EXFAT_I(inode)->i_size_ondisk = aligned_size;

	if (EXFAT_I(inode)->i_size_aligned > i_size_read(inode))
		EXFAT_I(inode)->i_size_aligned = aligned_size;
	mutex_unlock(&sbi->s_lock);
}

/*
 * Input: inode, (logical) clu_offset, target allocation area
 * Output: errcode, cluster number
 * *clu = (~0), if it's unable to allocate a new cluster
 */
static int __exfat_map_cluster(struct inode *inode, unsigned int clu_offset,
		unsigned int *clu, int create)
{
	int ret, modified = false;
	unsigned int last_clu;
	struct exfat_chain new_clu;
	struct exfat_dentry *ep;
	struct exfat_entry_set_cache *es = NULL;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	unsigned int local_clu_offset = clu_offset;
	int reserved_clusters = sbi->reserved_clusters;
	unsigned int num_to_be_allocated = 0, num_clusters = 0;

	ei->rwoffset = EXFAT_CLU_TO_B(clu_offset, sbi);

	if (EXFAT_I(inode)->i_size_ondisk > 0)
		num_clusters =
			EXFAT_B_TO_CLU_ROUND_UP(EXFAT_I(inode)->i_size_ondisk,
			sbi);

	if (clu_offset >= num_clusters)
		num_to_be_allocated = clu_offset - num_clusters + 1;

	if (!create && (num_to_be_allocated > 0)) {
		*clu = EOF_CLUSTER;
		return 0;
	}

	*clu = last_clu = ei->start_clu;

	/* XXX: Defensive code needed.
	 * what if i_size_ondisk != # of allocated clusters
	 */
	if (ei->flags == 0x03) {
		if ((clu_offset > 0) && (*clu != EOF_CLUSTER)) {
			last_clu += clu_offset - 1;

			if (clu_offset == num_clusters)
				*clu = EOF_CLUSTER;
			else
				*clu += clu_offset;
		}
	} else if (ei->type == TYPE_FILE) {
		unsigned int fclus = 0;
		int err = exfat_get_cluster(inode, clu_offset,
				&fclus, clu, &last_clu, 1);
		if (err)
			return -EIO;

		clu_offset -= fclus;
	} else {
		/* hint information */
		if ((clu_offset > 0) &&
			((ei->hint_bmap.off != EOF_CLUSTER) &&
			(ei->hint_bmap.off > 0)) &&
			(clu_offset >= ei->hint_bmap.off)) {
			clu_offset -= ei->hint_bmap.off;
			/* hint_bmap.clu should be valid */
			WARN_ON(ei->hint_bmap.clu < 2);
			*clu = ei->hint_bmap.clu;
		}

		while ((clu_offset > 0) && (*clu != EOF_CLUSTER)) {
			last_clu = *clu;
			if (exfat_get_next_cluster(sb, clu))
				return -EIO;
			clu_offset--;
		}
	}

	if (*clu == EOF_CLUSTER) {
		exfat_set_vol_flags(sb, VOL_DIRTY);

		new_clu.dir = (last_clu == EOF_CLUSTER) ?
				EOF_CLUSTER : last_clu + 1;
		new_clu.size = 0;
		new_clu.flags = ei->flags;

		/* allocate a cluster */
		if (num_to_be_allocated < 1) {
			/* Broken FAT (i_sze > allocated FAT) */
			exfat_fs_error(sb, "broken FAT chain.");
			return -EIO;
		}

		ret = exfat_alloc_cluster(sb, num_to_be_allocated, &new_clu);
		if (ret)
			return ret;

		if (new_clu.dir == EOF_CLUSTER || new_clu.dir == FREE_CLUSTER) {
			exfat_fs_error(sb,
				"bogus cluster new allocated (last_clu : %u, new_clu : %u)",
				last_clu, new_clu.dir);
			return -EIO;
		}

		/* append to the FAT chain */
		if (last_clu == EOF_CLUSTER) {
			if (new_clu.flags == 0x01)
				ei->flags = 0x01;
			ei->start_clu = new_clu.dir;
			modified = true;
		} else {
			if (new_clu.flags != ei->flags) {
				/* no-fat-chain bit is disabled,
				 * so fat-chain should be synced with alloc-bmp
				 */
				exfat_chain_cont_cluster(sb, ei->start_clu,
					num_clusters);
				ei->flags = 0x01;
				modified = true;
			}
			if (new_clu.flags == 0x01)
				if (exfat_ent_set(sb, last_clu, new_clu.dir))
					return -EIO;
		}

		num_clusters += num_to_be_allocated;
		*clu = new_clu.dir;

		if (ei->dir.dir != DIR_DELETED) {
			es = exfat_get_dentry_set(sb, &(ei->dir), ei->entry,
				ES_ALL_ENTRIES, &ep);
			if (!es)
				return -EIO;
			/* get stream entry */
			ep++;

			/* update directory entry */
			if (modified) {
				if (ep->stream_flags != ei->flags)
					ep->stream_flags = ei->flags;

				if (le32_to_cpu(ep->stream_start_clu) !=
						ei->start_clu)
					ep->stream_start_clu =
						cpu_to_le32(ei->start_clu);

				ep->stream_valid_size =
					cpu_to_le64(i_size_read(inode));
				ep->stream_size = ep->stream_valid_size;
			}

			if (exfat_update_dir_chksum_with_entry_set(sb, es))
				return -EIO;
			exfat_release_dentry_set(es);

		} /* end of if != DIR_DELETED */

		inode->i_blocks +=
			num_to_be_allocated << sbi->sect_per_clus_bits;

		/* Move *clu pointer along FAT chains (hole care)
		 * because the caller of this function expect *clu to be
		 * the last cluster.
		 * This only works when num_to_be_allocated >= 2,
		 * *clu = (the first cluster of the allocated chain) =>
		 * (the last cluster of ...)
		 */
		if (ei->flags == 0x03) {
			*clu += num_to_be_allocated - 1;
		} else {
			while (num_to_be_allocated > 1) {
				if (exfat_get_next_cluster(sb, clu))
					return -EIO;
				num_to_be_allocated--;
			}
		}

	}

	/* update reserved_clusters */
	sbi->reserved_clusters = reserved_clusters;

	/* hint information */
	ei->hint_bmap.off = local_clu_offset;
	ei->hint_bmap.clu = *clu;

	return 0;
}

static int exfat_bmap(struct inode *inode, sector_t sector, sector_t *phys,
		unsigned long *mapped_blocks, int *create)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	sector_t last_block;
	unsigned int cluster, clu_offset, sec_offset;
	int err = 0;

	*phys = 0;
	*mapped_blocks = 0;

	last_block = EXFAT_B_TO_BLK_ROUND_UP(i_size_read(inode), sb);
	if ((sector >= last_block) && (*create == BMAP_NOT_CREATE))
		return 0;

	/* Is this block already allocated? */
	clu_offset = sector >> sbi->sect_per_clus_bits;  /* cluster offset */

	err = __exfat_map_cluster(inode, clu_offset, &cluster,
		*create & BMAP_ADD_CLUSTER);
	if (err) {
		if (err != -ENOSPC)
			return -EIO;
		return err;
	}

	if (cluster != EOF_CLUSTER) {
		/* sector offset in cluster */
		sec_offset = sector & (sbi->sect_per_clus - 1);

		*phys = exfat_cluster_to_sector(sbi, cluster) + sec_offset;
		*mapped_blocks = sbi->sect_per_clus - sec_offset;
	}

	if (sector < last_block)
		*create = BMAP_NOT_CREATE;
			return 0;
}

static int exfat_get_block(struct inode *inode, sector_t iblock,
		struct buffer_head *bh_result, int create)
{
	struct super_block *sb = inode->i_sb;
	unsigned long max_blocks = bh_result->b_size >> inode->i_blkbits;
	int err = 0;
	unsigned long mapped_blocks;
	sector_t phys;
	loff_t pos;
	int bmap_create = create ? BMAP_ADD_CLUSTER : BMAP_NOT_CREATE;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	err = exfat_bmap(inode, iblock, &phys, &mapped_blocks, &bmap_create);
	if (err) {
		if (err != -ENOSPC)
			exfat_fs_error_ratelimit(sb,
				"failed to bmap (inode : %p iblock : %llu, err : %d)",
				inode, (unsigned long long)iblock, err);
		goto unlock_ret;
	}

	if (phys) {
		max_blocks = min(mapped_blocks, max_blocks);

		/* Treat newly added block / cluster */
		if (BLOCK_ADDED(bmap_create) || buffer_delay(bh_result)) {

			/* Update i_size_ondisk */
			pos = EXFAT_BLK_TO_B((iblock + 1), sb);
			if (EXFAT_I(inode)->i_size_ondisk < pos)
				EXFAT_I(inode)->i_size_ondisk = pos;

			if (BLOCK_ADDED(bmap_create)) {
				if (buffer_delay(bh_result) && (pos >
					EXFAT_I(inode)->i_size_aligned)) {
					exfat_fs_error(sb,
						"requested for bmap out of range(pos : (%llu) > i_size_aligned(%llu)\n",
						pos,
						EXFAT_I(inode)->i_size_aligned);
					err = -EIO;
					goto unlock_ret;
				}
				set_buffer_new(bh_result);

				/*
				 * adjust i_size_aligned if i_size_ondisk is
				 * bigger than it. (i.e. non-DA)
				 */
				if (EXFAT_I(inode)->i_size_ondisk >
					EXFAT_I(inode)->i_size_aligned) {
					EXFAT_I(inode)->i_size_aligned =
						EXFAT_I(inode)->i_size_ondisk;
				}
			}

			if (buffer_delay(bh_result))
				clear_buffer_delay(bh_result);
		}
		map_bh(bh_result, sb, phys);
	}

	bh_result->b_size = EXFAT_BLK_TO_B(max_blocks, sb);
unlock_ret:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return err;
}

static int exfat_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, exfat_get_block);
}

static int exfat_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned int nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, exfat_get_block);
}

static int exfat_writepage(struct page *page, struct writeback_control *wbc)
{
	return mpage_writepage(page, exfat_get_block, wbc);
}

static int exfat_writepages(struct address_space *mapping,
		struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, exfat_get_block);
}

static void exfat_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > i_size_read(inode)) {
		truncate_pagecache(inode, i_size_read(inode));
		exfat_truncate(inode, EXFAT_I(inode)->i_size_aligned);
	}
}

static int __exfat_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned int len, unsigned int flags,
		struct page **pagep, void **fsdata, get_block_t *get_block,
		loff_t *bytes)
{
	int ret;

	*pagep = NULL;
	ret = cont_write_begin(file, mapping, pos, len, flags, pagep, fsdata,
			get_block, bytes);

	if (ret < 0)
		exfat_write_failed(mapping, pos+len);

	return ret;
}

static int exfat_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned int len, unsigned int flags,
		struct page **pagep, void **fsdata)
{
	return __exfat_write_begin(file, mapping, pos, len, flags,
			pagep, fsdata, exfat_get_block,
			&EXFAT_I(mapping->host)->i_size_ondisk);
}

static int exfat_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned int len, unsigned int copied,
		struct page *pagep, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct exfat_inode_info *ei = EXFAT_I(inode);
	int err;

	err = generic_write_end(file, mapping, pos, len, copied, pagep, fsdata);

	if (EXFAT_I(inode)->i_size_aligned < i_size_read(inode)) {
		exfat_fs_error(inode->i_sb,
			"invalid size(size(%llu) > aligned(%llu)\n",
			i_size_read(inode), EXFAT_I(inode)->i_size_aligned);
		return -EIO;
	}

	if (err < len)
		exfat_write_failed(mapping, pos+len);

	if (!(err < 0) && !(ei->attr & ATTR_ARCHIVE)) {
		inode->i_mtime = inode->i_ctime = current_time(inode);
		ei->attr |= ATTR_ARCHIVE;
		mark_inode_dirty(inode);
	}

	return err;
}

static ssize_t exfat_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	struct address_space *mapping = iocb->ki_filp->f_mapping;
	struct inode *inode = mapping->host;
	loff_t size = iocb->ki_pos + iov_iter_count(iter);
	int rw = iov_iter_rw(iter);
	ssize_t ret;

	if (rw == WRITE) {
		/*
		 * FIXME: blockdev_direct_IO() doesn't use ->write_begin(),
		 * so we need to update the ->i_size_aligned to block boundary.
		 *
		 * But we must fill the remaining area or hole by nul for
		 * updating ->i_size_aligned
		 *
		 * Return 0, and fallback to normal buffered write.
		 */
		if (EXFAT_I(inode)->i_size_aligned < size)
			return 0;
	}

	/*
	 * Need to use the DIO_LOCKING for avoiding the race
	 * condition of exfat_get_block() and ->truncate().
	 */
	ret = blockdev_direct_IO(iocb, inode, iter, exfat_get_block);
	if (ret < 0 && (rw & WRITE))
		exfat_write_failed(mapping, size);
	return ret;
}

static sector_t exfat_aop_bmap(struct address_space *mapping, sector_t block)
{
	sector_t blocknr;

	/* exfat_get_cluster() assumes the requested blocknr isn't truncated. */
	down_read(&EXFAT_I(mapping->host)->truncate_lock);
	blocknr = generic_block_bmap(mapping, block, exfat_get_block);
	up_read(&EXFAT_I(mapping->host)->truncate_lock);
	return blocknr;
}

static const struct address_space_operations exfat_aops = {
	.readpage	= exfat_readpage,
	.readpages	= exfat_readpages,
	.writepage	= exfat_writepage,
	.writepages	= exfat_writepages,
	.write_begin	= exfat_write_begin,
	.write_end	= exfat_write_end,
	.direct_IO	= exfat_direct_IO,
	.bmap		= exfat_aop_bmap
};

static inline unsigned long exfat_hash(loff_t i_pos)
{
	return hash_32(i_pos, EXFAT_HASH_BITS);
}

void exfat_hash_inode(struct inode *inode, loff_t i_pos)
{
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	struct hlist_head *head = sbi->inode_hashtable + exfat_hash(i_pos);

	spin_lock(&sbi->inode_hash_lock);
	EXFAT_I(inode)->i_pos = i_pos;
	hlist_add_head(&EXFAT_I(inode)->i_hash_fat, head);
	spin_unlock(&sbi->inode_hash_lock);
}

void exfat_unhash_inode(struct inode *inode)
{
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);

	spin_lock(&sbi->inode_hash_lock);
	hlist_del_init(&EXFAT_I(inode)->i_hash_fat);
	EXFAT_I(inode)->i_pos = 0;
	spin_unlock(&sbi->inode_hash_lock);
}

struct inode *exfat_iget(struct super_block *sb, loff_t i_pos)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *info;
	struct hlist_head *head = sbi->inode_hashtable + exfat_hash(i_pos);
	struct inode *inode = NULL;

	spin_lock(&sbi->inode_hash_lock);
	hlist_for_each_entry(info, head, i_hash_fat) {
		WARN_ON(info->vfs_inode.i_sb != sb);

		if (i_pos != info->i_pos)
			continue;
		inode = igrab(&info->vfs_inode);
		if (inode)
			break;
	}
	spin_unlock(&sbi->inode_hash_lock);
	return inode;
}

/* doesn't deal with root inode */
static int exfat_fill_inode(struct inode *inode, struct exfat_dir_entry *info)
{
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	loff_t size = info->size;

	memcpy(&ei->dir, &info->dir, sizeof(struct exfat_chain));
	ei->entry = info->entry;
	ei->attr = info->attr;
	ei->start_clu = info->start_clu;
	ei->flags = info->flags;
	ei->type = info->type;

	ei->version = 0;
	ei->hint_stat.eidx = 0;
	ei->hint_stat.clu = info->start_clu;
	ei->hint_femp.eidx = EXFAT_HINT_NONE;
	ei->rwoffset = 0;
	ei->hint_bmap.off = EOF_CLUSTER;
	ei->i_pos = 0;

	inode->i_uid = sbi->options.fs_uid;
	inode->i_gid = sbi->options.fs_gid;
	inode_inc_iversion(inode);
	inode->i_generation = get_seconds();

	if (info->attr & ATTR_SUBDIR) { /* directory */
		inode->i_generation &= ~1;
		inode->i_mode = exfat_make_mode(sbi, info->attr, 0777);
		inode->i_op = &exfat_dir_inode_operations;
		inode->i_fop = &exfat_dir_operations;
		set_nlink(inode, info->num_subdirs);
	} else { /* regular file */
		inode->i_generation |= 1;
		inode->i_mode = exfat_make_mode(sbi, info->attr, 0777);
		inode->i_op = &exfat_file_inode_operations;
		inode->i_fop = &exfat_file_operations;
		inode->i_mapping->a_ops = &exfat_aops;
		inode->i_mapping->nrpages = 0;
	}

	i_size_write(inode, size);

	/* ondisk and aligned size should be aligned with block size */
	if (size & (inode->i_sb->s_blocksize - 1)) {
		size |= (inode->i_sb->s_blocksize - 1);
		size++;
	}

	ei->i_size_aligned = size;
	ei->i_size_ondisk = size;

	exfat_save_attr(inode, info->attr);

	inode->i_blocks = ((i_size_read(inode) + (sbi->cluster_size - 1))
		& ~(sbi->cluster_size - 1)) >> inode->i_blkbits;

	exfat_time_fat2unix(sbi, &inode->i_mtime, &info->modify_timestamp);
	exfat_time_fat2unix(sbi, &inode->i_ctime, &info->create_timestamp);
	exfat_time_fat2unix(sbi, &inode->i_atime, &info->access_timestamp);

	exfat_cache_init_inode(inode);

	return 0;
}

struct inode *exfat_build_inode(struct super_block *sb,
		struct exfat_dir_entry *info, loff_t i_pos)
{
	struct inode *inode;
	int err;

	inode = exfat_iget(sb, i_pos);
	if (inode)
		goto out;
	inode = new_inode(sb);
	if (!inode) {
		inode = ERR_PTR(-ENOMEM);
		goto out;
	}
	inode->i_ino = iunique(sb, EXFAT_ROOT_INO);
	inode_set_iversion(inode, 1);
	err = exfat_fill_inode(inode, info);
	if (err) {
		iput(inode);
		inode = ERR_PTR(err);
		goto out;
	}
	exfat_hash_inode(inode, i_pos);
	insert_inode_hash(inode);
out:
	return inode;
}

void exfat_evict_inode(struct inode *inode)
{
	truncate_inode_pages(&inode->i_data, 0);

	if (!inode->i_nlink) {
		i_size_write(inode, 0);
		mutex_lock(&EXFAT_SB(inode->i_sb)->s_lock);
		__exfat_truncate(inode, 0);
		mutex_unlock(&EXFAT_SB(inode->i_sb)->s_lock);
	}

	invalidate_inode_buffers(inode);
	clear_inode(inode);
	/* Volume lock is not required,
	 * because it is only called by evict_inode.
	 * If any other function can call it,
	 * you should check whether volume lock is needed or not.
	 */
	exfat_cache_inval_inode(inode);
	exfat_unhash_inode(inode);
}
