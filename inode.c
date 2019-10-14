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

static inline sector_t __exfat_bio_sector(struct bio *bio)
{
	return bio->bi_iter.bi_sector;
}

static inline void __exfat_set_bio_iterate(struct bio *bio, sector_t sector,
		unsigned int size, unsigned int idx, unsigned int done)
{
	struct bvec_iter *iter = &(bio->bi_iter);

	iter->bi_sector = sector;
	iter->bi_size = size;
	iter->bi_idx = idx;
	iter->bi_bvec_done = done;
}

static void __exfat_truncate_pagecache(struct inode *inode,
		loff_t to, loff_t newsize)
{
	truncate_pagecache(inode, newsize);
}

/* resize the file length */
int __exfat_truncate(struct inode *inode, unsigned long long old_size,
		unsigned long long new_size)
{
	unsigned int num_clusters_new, num_clusters_da, num_clusters_phys;
	unsigned int last_clu = CLUS_FREE;
	struct exfat_chain clu;
	struct exfat_timestamp tm;
	struct exfat_dentry *ep, *ep2;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);
	struct exfat_entry_set_cache *es = NULL;
	int evict = (fid->dir.dir == DIR_DELETED) ? 1 : 0;

	/* check if the given file ID is opened */
	if ((fid->type != TYPE_FILE) && (fid->type != TYPE_DIR))
		return -EPERM;

	/*
	 * There is no lock to protect fid->size.
	 * So, we should get old_size and use it.
	 */
	if (old_size <= new_size)
		return 0;

	exfat_set_vol_flags(sb, VOL_DIRTY);

	/* Reserved count update */
#define num_clusters(v) ((v) ?	\
	(unsigned int)(((v) - 1) >> sbi->cluster_size_bits) + 1 : 0)
	num_clusters_da = num_clusters(EXFAT_I(inode)->i_size_aligned);
	num_clusters_new = num_clusters(i_size_read(inode));
	num_clusters_phys = num_clusters(EXFAT_I(inode)->i_size_ondisk);

	/* num_clusters(i_size_old) should be equal to num_clusters_da */
	WARN_ON((num_clusters(old_size)) !=
		(num_clusters(EXFAT_I(inode)->i_size_aligned)));

	/* for debugging (FIXME: is okay on no-da case?) */
	WARN_ON(num_clusters_da < num_clusters_phys);

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

	clu.dir = fid->start_clu;
	clu.size = num_clusters_phys;
	clu.flags = fid->flags;

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
				if (get_next_clus_safe(sb, &(clu.dir)))
					return -EIO;

				num_clusters--;
				clu.size--;
			}
		}
	} else if (new_size == 0) {
		fid->flags = 0x03;
		fid->start_clu = CLUS_EOF;
	}
	fid->size = new_size;

	if (fid->type == TYPE_FILE)
		fid->attr |= ATTR_ARCHIVE;

	/*
	 * clu.dir: free from
	 * clu.size: # of clusters to free (exFAT, 0x03 only), no fat_free if 0
	 * clu.flags: fid->flags (exFAT only)
	 */

	/* (1) update the directory entry */
	if (!evict) {
		es = get_dentry_set_in_dir(sb, &(fid->dir), fid->entry,
			ES_ALL_ENTRIES, &ep);
		if (!es)
			return -EIO;
		ep2 = ep+1;

		exfat_set_entry_time(ep, tm_now(EXFAT_SB(sb), &tm), TM_MODIFY);
		exfat_set_entry_attr(ep, fid->attr);

		/* File size should be zero if there is no cluster allocated */
		if (IS_CLUS_EOF(fid->start_clu))
			exfat_set_entry_size(ep2, 0);
		else
			exfat_set_entry_size(ep2, new_size);

		if (new_size == 0) {
			/* Any directory can not be truncated to zero */
			WARN_ON(fid->type != TYPE_FILE);

			exfat_set_entry_flag(ep2, 0x01);
			exfat_set_entry_clu0(ep2, CLUS_FREE);
		}

		if (exfat_update_dir_chksum_with_entry_set(sb, es))
			return -EIO;
		exfat_release_dentry_set(es);

	} /* end of if(fid->dir.dir != DIR_DELETED) */

	/* (2) cut off from the FAT chain */
	if ((fid->flags == 0x01) &&
			(!IS_CLUS_FREE(last_clu)) && (!IS_CLUS_EOF(last_clu))) {
		if (exfat_ent_set(sb, last_clu, CLUS_EOF))
			return -EIO;
	}

	/* (3) invalidate cache and free the clusters */
	/* clear exfat cache */
	exfat_cache_inval_inode(inode);

	/* hint information */
	fid->hint_bmap.off = CLUS_EOF;
	fid->hint_bmap.clu = CLUS_EOF;
	if (fid->rwoffset > fid->size)
		fid->rwoffset = fid->size;

	/* hint_stat will be used if this is directory. */
	fid->hint_stat.eidx = 0;
	fid->hint_stat.clu = fid->start_clu;
	fid->hint_femp.eidx = -1;

	/* free the clusters */
	if (exfat_free_cluster(sb, &clu, evict))
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
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);
	unsigned char is_dir = (fid->type == TYPE_DIR) ? 1 : 0;
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
	if (fid->dir.dir == DIR_DELETED)
		return 0;

	if (is_dir && (fid->dir.dir == sbi->root_dir) && (fid->entry == -1))
		return 0;

	exfat_set_vol_flags(sb, VOL_DIRTY);

	/* get the directory entry of given file or directory */
	es = get_dentry_set_in_dir(sb, &(fid->dir), fid->entry, ES_ALL_ENTRIES,
		&ep);
	if (!es)
		return -EIO;
	ep2 = ep + 1;

	exfat_set_entry_attr(ep, info.attr);

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

	if (IS_CLUS_EOF(fid->start_clu))
		on_disk_size = 0;

	exfat_set_entry_size(ep2, on_disk_size);

	ret = exfat_update_dir_chksum_with_entry_set(sb, es);
	exfat_release_dentry_set(es);

	if (sync)
		sync_blockdev(sb->s_bdev);
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

int exfat_sync_inode(struct inode *inode)
{
	return __exfat_write_inode(inode, 1);
}

void exfat_truncate(struct inode *inode, loff_t old_size)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int blocksize = 1 << inode->i_blkbits;
	loff_t aligned_size;
	int err;

	mutex_lock(&sbi->s_lock);
	if (EXFAT_I(inode)->fid.start_clu == 0) {
		/*
		 * Empty start_clu != ~0 (not allocated)
		 */
		exfat_fs_error(sb, "tried to truncate zeroed cluster.");
		goto out;
	}

	err = __exfat_truncate(inode, old_size, i_size_read(inode));
	if (err)
		goto out;

	inode->i_ctime = inode->i_mtime = current_time(inode);
	if (IS_DIRSYNC(inode))
		(void) exfat_sync_inode(inode);
	else
		mark_inode_dirty(inode);

	inode->i_blocks = ((i_size_read(inode) + (sbi->cluster_size - 1)) &
			~((loff_t)sbi->cluster_size - 1)) >> inode->i_blkbits;
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
static int __exfat_map_clus(struct inode *inode, unsigned int clu_offset,
		unsigned int *clu, int dest)
{
	int ret, modified = false;
	unsigned int last_clu;
	struct exfat_chain new_clu;
	struct exfat_dentry *ep;
	struct exfat_entry_set_cache *es = NULL;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);
	unsigned int local_clu_offset = clu_offset;
	int reserved_clusters = sbi->reserved_clusters;
	unsigned int num_to_be_allocated = 0, num_clusters = 0;

	fid->rwoffset = (s64)(clu_offset) << sbi->cluster_size_bits;

	if (EXFAT_I(inode)->i_size_ondisk > 0)
		num_clusters = (unsigned int)
			((EXFAT_I(inode)->i_size_ondisk-1) >>
				sbi->cluster_size_bits) + 1;

	if (clu_offset >= num_clusters)
		num_to_be_allocated = clu_offset - num_clusters + 1;

	if ((dest == ALLOC_NOWHERE) && (num_to_be_allocated > 0)) {
		*clu = CLUS_EOF;
		return 0;
	}

	*clu = last_clu = fid->start_clu;

	/* XXX: Defensive code needed.
	 * what if i_size_ondisk != # of allocated clusters
	 */
	if (fid->flags == 0x03) {
		if ((clu_offset > 0) && (!IS_CLUS_EOF(*clu))) {
			last_clu += clu_offset - 1;

			if (clu_offset == num_clusters)
				*clu = CLUS_EOF;
			else
				*clu += clu_offset;
		}
	} else if (fid->type == TYPE_FILE) {
		unsigned int fclus = 0;
		int err = exfat_get_clus(inode, clu_offset,
				&fclus, clu, &last_clu, 1);
		if (err)
			return -EIO;

		clu_offset -= fclus;
	} else {
		/* hint information */
		if ((clu_offset > 0) &&
			((fid->hint_bmap.off != CLUS_EOF) &&
			(fid->hint_bmap.off > 0)) &&
			(clu_offset >= fid->hint_bmap.off)) {
			clu_offset -= fid->hint_bmap.off;
			/* hint_bmap.clu should be valid */
			WARN_ON(fid->hint_bmap.clu < 2);
			*clu = fid->hint_bmap.clu;
		}

		while ((clu_offset > 0) && (!IS_CLUS_EOF(*clu))) {
			last_clu = *clu;
			if (get_next_clus_safe(sb, clu))
				return -EIO;
			clu_offset--;
		}
	}

	if (IS_CLUS_EOF(*clu)) {
		exfat_set_vol_flags(sb, VOL_DIRTY);

		new_clu.dir = (IS_CLUS_EOF(last_clu)) ?
				CLUS_EOF : last_clu + 1;
		new_clu.size = 0;
		new_clu.flags = fid->flags;

		/* (1) allocate a cluster */
		if (num_to_be_allocated < 1) {
			/* Broken FAT (i_sze > allocated FAT) */
			exfat_fs_error(sb, "broken FAT chain.");
			return -EIO;
		}

		ret = exfat_alloc_cluster(sb, num_to_be_allocated, &new_clu,
			ALLOC_COLD);
		if (ret)
			return ret;

		if (IS_CLUS_EOF(new_clu.dir) || IS_CLUS_FREE(new_clu.dir)) {
			exfat_fs_error(sb,
				"bogus cluster new allocated (last_clu : %u, new_clu : %u)",
				last_clu, new_clu.dir);
			return -EIO;
		}

		/* (2) append to the FAT chain */
		if (IS_CLUS_EOF(last_clu)) {
			if (new_clu.flags == 0x01)
				fid->flags = 0x01;
			fid->start_clu = new_clu.dir;
			modified = true;
		} else {
			if (new_clu.flags != fid->flags) {
				/* no-fat-chain bit is disabled,
				 * so fat-chain should be synced with alloc-bmp
				 */
				exfat_chain_cont_cluster(sb, fid->start_clu,
					num_clusters);
				fid->flags = 0x01;
				modified = true;
			}
			if (new_clu.flags == 0x01)
				if (exfat_ent_set(sb, last_clu, new_clu.dir))
					return -EIO;
		}

		num_clusters += num_to_be_allocated;
		*clu = new_clu.dir;

		if (fid->dir.dir != DIR_DELETED) {
			es = get_dentry_set_in_dir(sb, &(fid->dir), fid->entry,
				ES_ALL_ENTRIES, &ep);
			if (!es)
				return -EIO;
			/* get stream entry */
			ep++;

			/* (3) update directory entry */
			if (modified) {
				if (exfat_get_entry_flag(ep) != fid->flags)
					exfat_set_entry_flag(ep, fid->flags);

				if (exfat_get_entry_clu0(ep) != fid->start_clu)
					exfat_set_entry_clu0(ep,
						fid->start_clu);

				exfat_set_entry_size(ep, fid->size);
			}

			if (exfat_update_dir_chksum_with_entry_set(sb, es))
				return -EIO;
			exfat_release_dentry_set(es);

		} /* end of if != DIR_DELETED */


		inode->i_blocks += num_to_be_allocated <<
			(sbi->cluster_size_bits - sb->s_blocksize_bits);

		/* (4) Move *clu pointer along FAT chains (hole care)
		 * because the caller of this function expect *clu to be
		 * the last cluster.
		 * This only works when num_to_be_allocated >= 2,
		 * *clu = (the first cluster of the allocated chain) =>
		 * (the last cluster of ...)
		 */
		if (fid->flags == 0x03) {
			*clu += num_to_be_allocated - 1;
		} else {
			while (num_to_be_allocated > 1) {
				if (get_next_clus_safe(sb, clu))
					return -EIO;
				num_to_be_allocated--;
			}
		}

	}

	/* update reserved_clusters */
	sbi->reserved_clusters = reserved_clusters;

	/* hint information */
	fid->hint_bmap.off = local_clu_offset;
	fid->hint_bmap.clu = *clu;

	return 0;
}

static int exfat_bmap(struct inode *inode, sector_t sector, sector_t *phys,
		unsigned long *mapped_blocks, int *create)
{
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	const unsigned long blocksize = sb->s_blocksize;
	const unsigned char blocksize_bits = sb->s_blocksize_bits;
	sector_t last_block;
	unsigned int cluster, clu_offset, sec_offset;
	int err = 0;

	*phys = 0;
	*mapped_blocks = 0;

	last_block = (i_size_read(inode) + (blocksize - 1)) >> blocksize_bits;
	if ((sector >= last_block) && (*create == BMAP_NOT_CREATE))
		return 0;

	/* Is this block already allocated? */
	clu_offset = sector >> sbi->sect_per_clus_bits;  /* cluster offset */

	EXFAT_I(inode)->fid.size = i_size_read(inode);

	if (*create & BMAP_ADD_CLUSTER)
		err = __exfat_map_clus(inode, clu_offset, &cluster, 1);
	else
		err = __exfat_map_clus(inode, clu_offset, &cluster,
			ALLOC_NOWHERE);

	if (err) {
		if (err != -ENOSPC)
			return -EIO;
		return err;
	}

	if (!IS_CLUS_EOF(cluster)) {
		/* sector offset in cluster */
		sec_offset = sector & (sbi->sect_per_clus - 1);

		*phys = CLUS_TO_SECT(sbi, cluster) + sec_offset;
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
				"failed to bmap (inode:%p iblock:%u, err:%d)",
				inode, (unsigned int)iblock, err);
		goto unlock_ret;
	}

	if (phys) {
		max_blocks = min(mapped_blocks, max_blocks);

		/* Treat newly added block / cluster */
		if (BLOCK_ADDED(bmap_create) || buffer_delay(bh_result)) {

			/* Update i_size_ondisk */
			pos = (iblock + 1) << sb->s_blocksize_bits;
			if (EXFAT_I(inode)->i_size_ondisk < pos)
				EXFAT_I(inode)->i_size_ondisk = pos;

			if (BLOCK_ADDED(bmap_create)) {
				if (buffer_delay(bh_result) && (pos >
					EXFAT_I(inode)->i_size_aligned)) {
					exfat_fs_error(sb,
						"requested for bmap out of range(pos:(%llu)>i_size_aligned(%llu)\n",
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

	bh_result->b_size = max_blocks << sb->s_blocksize_bits;
unlock_ret:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return err;
}

static int exfat_readpage(struct file *file, struct page *page)
{
	int ret;

	ret =  mpage_readpage(page, exfat_get_block);
	return ret;
}

static int exfat_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned int nr_pages)
{
	int ret;

	ret =  mpage_readpages(mapping, pages, nr_pages, exfat_get_block);
	return ret;
}

static void __exfat_writepage_end_io(struct bio *bio, int err)
{
	struct page *page = bio->bi_io_vec->bv_page;

	if (err) {
		SetPageError(page);
		mapping_set_error(page->mapping, err);
	}

	end_page_writeback(page);
	bio_put(bio);
}

static void exfat_writepage_end_io(struct bio *bio)
{
	__exfat_writepage_end_io(bio, blk_status_to_errno(bio->bi_status));
}

static inline void __exfat_submit_bio_write(struct bio *bio)
{
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	submit_bio(bio);
}

static inline void exfat_submit_fullpage_bio(struct block_device *bdev,
		sector_t sector, unsigned int length, struct page *page)
{
	/* Single page bio submit */
	struct bio *bio;

	WARN_ON((length > PAGE_SIZE) || (length == 0));

	/*
	 * If __GFP_WAIT is set, then bio_alloc will always be able to allocate
	 * a bio. This is due to the mempool guarantees. To make this work,
	 * callers must never allocate more than 1 bio at a time from this pool.
	 *
	 * #define GFP_NOIO	(__GFP_WAIT)
	 */
	bio = bio_alloc(GFP_NOIO, 1);

	bio_set_dev(bio, bdev);
	bio->bi_vcnt = 1;
	bio->bi_io_vec[0].bv_page = page;	/* Inline vec */
	bio->bi_io_vec[0].bv_len = length;	/* PAGE_SIZE */
	bio->bi_io_vec[0].bv_offset = 0;
	__exfat_set_bio_iterate(bio, sector, length, 0, 0);

	bio->bi_end_io = exfat_writepage_end_io;
	__exfat_submit_bio_write(bio);
}

static int exfat_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode * const inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	loff_t i_size = i_size_read(inode);
	const pgoff_t end_index = i_size >> PAGE_SHIFT;
	const unsigned int blocks_per_page = PAGE_SIZE >> inode->i_blkbits;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh, *head;
	sector_t block, block_0, last_phys;
	int ret;
	unsigned int nr_blocks_towrite = blocks_per_page;

	/* Don't distinguish 0-filled/clean block.
	 * Just write back the whole page
	 */
	if (sbi->cluster_size < PAGE_SIZE)
		goto confused;

	if (!PageUptodate(page))
		goto confused;

	if (page->index >= end_index) {
		/* last page or outside i_size */
		unsigned int offset = i_size & (PAGE_SIZE-1);

		/* If a truncation is in progress */
		if (page->index > end_index || !offset)
			goto confused;

		/* 0-fill after i_size */
		zero_user_segment(page, offset, PAGE_SIZE);
	}

	if (!page_has_buffers(page))
		goto confused;

	block = (sector_t)page->index << (PAGE_SHIFT - inode->i_blkbits);
	block_0 = block; /* first block */
	head = page_buffers(page);
	bh = head;

	last_phys = 0;
	do {
		WARN_ON(buffer_locked(bh));

		if (!buffer_dirty(bh) || !buffer_uptodate(bh)) {
			if (nr_blocks_towrite == blocks_per_page)
				nr_blocks_towrite =
					(unsigned int) (block - block_0);

			WARN_ON(nr_blocks_towrite >= blocks_per_page);

			// !uptodate but dirty??
			if (buffer_dirty(bh))
				goto confused;

			// Nothing to writeback in this block
			bh = bh->b_this_page;
			block++;
			continue;
		}

		if (nr_blocks_towrite != blocks_per_page)
			// Dirty -> Non-dirty -> Dirty again case
			goto confused;

		/* Map if needed */
		if (!buffer_mapped(bh) || buffer_delay(bh)) {
			WARN_ON(bh->b_size != (1 << (inode->i_blkbits)));
			ret = exfat_get_block(inode, block, bh, 1);
			if (ret)
				goto confused;

			if (buffer_new(bh)) {
				clear_buffer_new(bh);
				clean_bdev_aliases(bh->b_bdev, bh->b_blocknr,
					1);
			}
		}

		/* continuity check */
		if (((last_phys + 1) != bh->b_blocknr) && (last_phys != 0))
			goto confused;

		last_phys = bh->b_blocknr;
		bh = bh->b_this_page;
		block++;
	} while (bh != head);

	if (nr_blocks_towrite == 0)
		goto confused;

	/* Write-back */
	do {
		clear_buffer_dirty(bh);
		bh = bh->b_this_page;
	} while (bh != head);

	WARN_ON(PageWriteback(page));
	set_page_writeback(page);

	exfat_submit_fullpage_bio(head->b_bdev,
		head->b_blocknr << (sb->s_blocksize_bits - SECTOR_SIZE_BITS),
		nr_blocks_towrite << inode->i_blkbits, page);

	unlock_page(page);

	return 0;

confused:
	ret = block_write_full_page(page, exfat_get_block, wbc);
	return ret;
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
		__exfat_truncate_pagecache(inode, to, i_size_read(inode));
		exfat_truncate(inode, EXFAT_I(inode)->i_size_aligned);
	}
}

static int __exfat_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned int len,
		unsigned int flags, struct page **pagep,
		void **fsdata, get_block_t *get_block,
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
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);
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

	if (!(err < 0) && !(fid->attr & ATTR_ARCHIVE)) {
		inode->i_mtime = inode->i_ctime = current_time(inode);
		fid->attr |= ATTR_ARCHIVE;
		mark_inode_dirty(inode);
	}

	return err;
}

static inline ssize_t __exfat_blkdev_direct_IO(int unused, struct kiocb *iocb,
		struct inode *inode, void *iov_u, loff_t unused_1,
		unsigned long nr_segs)
{
	struct iov_iter *iter = (struct iov_iter *)iov_u;

	return blockdev_direct_IO(iocb, inode, iter, exfat_get_block);
}

static inline ssize_t __exfat_direct_IO(int rw, struct kiocb *iocb,
		struct inode *inode, void *iov_u, loff_t offset,
		loff_t count, unsigned long nr_segs)
{
	struct address_space *mapping = inode->i_mapping;
	loff_t size = offset + count;
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
	 * sdFAT need to use the DIO_LOCKING for avoiding the race
	 * condition of exfat_get_block() and ->truncate().
	 */
	ret = __exfat_blkdev_direct_IO(rw, iocb, inode, iov_u, offset, nr_segs);
	if (ret < 0 && (rw & WRITE))
		exfat_write_failed(mapping, size);

	return ret;
}

static ssize_t exfat_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	size_t count = iov_iter_count(iter);
	int rw = iov_iter_rw(iter);
	loff_t offset = iocb->ki_pos;

	return __exfat_direct_IO(rw, iocb, inode,
			(void *)iter, offset, count, 0 /* UNUSED */);
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
	.readpage    = exfat_readpage,
	.readpages   = exfat_readpages,
	.writepage   = exfat_writepage,
	.writepages  = exfat_writepages,
	.write_begin = exfat_write_begin,
	.write_end   = exfat_write_end,
	.direct_IO   = exfat_direct_IO,
	.bmap        = exfat_aop_bmap
};

static inline unsigned long exfat_hash(loff_t i_pos)
{
	return hash_32(i_pos, EXFAT_HASH_BITS);
}

void exfat_attach(struct inode *inode, loff_t i_pos)
{
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	struct hlist_head *head = sbi->inode_hashtable + exfat_hash(i_pos);

	spin_lock(&sbi->inode_hash_lock);
	EXFAT_I(inode)->i_pos = i_pos;
	hlist_add_head(&EXFAT_I(inode)->i_hash_fat, head);
	spin_unlock(&sbi->inode_hash_lock);
}

void exfat_detach(struct inode *inode)
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

static int __count_num_clusters(struct super_block *sb, struct exfat_chain *p_chain,
		unsigned int *ret_count)
{
	unsigned int i, count;
	unsigned int clu;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	if (!p_chain->dir || IS_CLUS_EOF(p_chain->dir)) {
		*ret_count = 0;
		return 0;
	}

	if (p_chain->flags == 0x03) {
		*ret_count = p_chain->size;
		return 0;
	}

	clu = p_chain->dir;
	count = 0;
	for (i = CLUS_BASE; i < sbi->num_clusters; i++) {
		count++;
		if (exfat_ent_get_safe(sb, clu, &clu))
			return -EIO;
		if (IS_CLUS_EOF(clu))
			break;
	}

	*ret_count = count;
	return 0;
}

struct exfat_dentry *exfat_get_dentry_in_dir(struct super_block *sb, struct exfat_chain *p_dir, int entry,
		unsigned long long *sector)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int dentries_per_page = PAGE_SIZE >> DENTRY_SIZE_BITS;
	int off;
	unsigned long long sec;
	unsigned char *buf;

	if (p_dir->dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "abnormal access to deleted dentry\n");
		WARN_ON(!sbi->prev_eio);
		return NULL;
	}

	if (exfat_find_location(sb, p_dir, entry, &sec, &off))
		return NULL;

	/* DIRECTORY READAHEAD :
	 * Try to read ahead per a page except root directory of fat12/16
	 */
	if ((!IS_CLUS_FREE(p_dir->dir)) &&
			!(entry & (dentries_per_page - 1)))
		dcache_readahead(sb, sec);

	buf = dcache_getblk(sb, sec);
	if (!buf)
		return NULL;

	if (sector)
		*sector = sec;
	return (struct exfat_dentry *)(buf + off);
}

#define EXFAT_MIN_SUBDIR    (2)
static int exfat_count_dos_name_entries(struct super_block *sb, struct exfat_chain *p_dir,
		unsigned int type, unsigned int *dotcnt)
{
	int i, count = 0;
	int dentries_per_clu;
	unsigned int entry_type;
	struct exfat_chain clu;
	struct exfat_dentry *ep;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	if (IS_CLUS_FREE(p_dir->dir)) /* FAT16 root_dir */
		dentries_per_clu = sbi->dentries_in_root;
	else
		dentries_per_clu = sbi->dentries_per_clu;

	clu.dir = p_dir->dir;
	clu.size = p_dir->size;
	clu.flags = p_dir->flags;

	if (dotcnt)
		*dotcnt = 0;

	while (!IS_CLUS_EOF(clu.dir)) {
		for (i = 0; i < dentries_per_clu; i++) {
			ep = exfat_get_dentry_in_dir(sb, &clu, i, NULL);
			if (!ep)
				return -EIO;

			entry_type = exfat_get_entry_type(ep);

			if (entry_type == TYPE_UNUSED)
				return count;
			if (!(type & TYPE_CRITICAL_PRI) &&
					!(type & TYPE_BENIGN_PRI))
				continue;

			if ((type != TYPE_ALL) && (type != entry_type))
				continue;

			count++;
		}

		/* FAT16 root_dir */
		if (IS_CLUS_FREE(p_dir->dir))
			break;

		if (clu.flags == 0x03) {
			if ((--clu.size) > 0)
				clu.dir++;
			else
				clu.dir = CLUS_EOF;
		} else {
			if (get_next_clus_safe(sb, &(clu.dir)))
				return -EIO;
		}
	}

	return count;
}

/*
 * Get the information of a given file
 * REMARK : This function does not need any file name on linux
 *
 * info.size means the value saved on disk.
 * But root directory doesn`t have real dentry,
 * so the size of root directory returns calculated one exceptively.
 */
int exfat_read_inode(struct inode *inode, struct exfat_dir_entry *info)
{
	int count;
	struct exfat_chain dir;
	struct exfat_timestamp tm;
	struct exfat_dentry *ep, *ep2;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);
	struct exfat_entry_set_cache *es = NULL;
	unsigned char is_dir = (fid->type == TYPE_DIR) ? 1 : 0;

	exfat_cache_init_inode(inode);

	/* if root directory */
	if (is_dir && (fid->dir.dir == sbi->root_dir) && (fid->entry == -1)) {
		info->attr = ATTR_SUBDIR;
		memset((s8 *) &info->create_timestamp, 0, sizeof(struct exfat_date_time));
		memset((s8 *) &info->modify_timestamp, 0, sizeof(struct exfat_date_time));
		memset((s8 *) &info->access_timestamp, 0, sizeof(struct exfat_date_time));

		dir.dir = sbi->root_dir;
		dir.flags = 0x01;
		dir.size = 0; /* UNUSED */

		/* FAT16 root_dir */
		if (IS_CLUS_FREE(sbi->root_dir)) {
			info->size = sbi->dentries_in_root << DENTRY_SIZE_BITS;
		} else {
			unsigned int num_clu;

			if (__count_num_clusters(sb, &dir, &num_clu))
				return -EIO;
			info->size = (unsigned long long)num_clu <<
				sbi->cluster_size_bits;
		}

		count = exfat_count_dos_name_entries(sb, &dir, TYPE_DIR, NULL);
		if (count < 0)
			return -EIO;
		info->num_subdirs = count;
		return 0;
	}

	/* get the directory entry of given file or directory */
	/* es should be released */
	es = get_dentry_set_in_dir(sb, &(fid->dir), fid->entry, ES_2_ENTRIES,
		&ep);
	if (!es)
		return -EIO;
	ep2 = ep + 1;

	/* set FILE_INFO structure using the acquired struct exfat_dentry */
	info->attr = exfat_get_entry_attr(ep);

	exfat_get_entry_time(ep, &tm, TM_CREATE);
	info->create_timestamp.year = tm.year;
	info->create_timestamp.month = tm.mon;
	info->create_timestamp.day = tm.day;
	info->create_timestamp.hour = tm.hour;
	info->create_timestamp.minute = tm.min;
	info->create_timestamp.second = tm.sec;
	info->create_timestamp.milli_second = 0;

	exfat_get_entry_time(ep, &tm, TM_MODIFY);
	info->modify_timestamp.year = tm.year;
	info->modify_timestamp.month = tm.mon;
	info->modify_timestamp.day = tm.day;
	info->modify_timestamp.hour = tm.hour;
	info->modify_timestamp.minute = tm.min;
	info->modify_timestamp.second = tm.sec;
	info->modify_timestamp.milli_second = 0;

	memset((s8 *) &info->access_timestamp, 0, sizeof(struct exfat_date_time));

	info->num_subdirs = 0;
	info->size = exfat_get_entry_size(ep2);

	exfat_release_dentry_set(es);

	if (is_dir) {
		unsigned int dotcnt = 0;

		dir.dir = fid->start_clu;
		dir.flags = fid->flags;
		dir.size = fid->size >> sbi->cluster_size_bits;
		count = exfat_count_dos_name_entries(sb, &dir, TYPE_DIR, &dotcnt);
		if (count < 0)
			return -EIO;

		count += EXFAT_MIN_SUBDIR;
		info->num_subdirs = count;
	}
	return 0;
}

/* doesn't deal with root inode */
static int exfat_fill_inode(struct inode *inode, const struct exfat_file_id *fid)
{
	struct exfat_sb_info *sbi = EXFAT_SB(inode->i_sb);
	struct exfat_dir_entry info;
	unsigned long long size = fid->size;

	memcpy(&(EXFAT_I(inode)->fid), fid, sizeof(struct exfat_file_id));

	EXFAT_I(inode)->i_pos = 0;
	EXFAT_I(inode)->target = NULL;
	inode->i_uid = sbi->options.fs_uid;
	inode->i_gid = sbi->options.fs_gid;
	inode_inc_iversion(inode);
	inode->i_generation = get_seconds();

	if (exfat_read_inode(inode, &info) < 0)
		return -EIO;

	if (info.attr & ATTR_SUBDIR) { /* directory */
		inode->i_generation &= ~1;
		inode->i_mode = exfat_make_mode(sbi, info.attr, 0777);
		inode->i_op = &exfat_dir_inode_operations;
		inode->i_fop = &exfat_dir_operations;

		set_nlink(inode, info.num_subdirs);
	} else if (info.attr & ATTR_SYMLINK) { /* symbolic link */
		inode->i_op = &exfat_symlink_inode_operations;
		inode->i_generation |= 1;
		inode->i_mode = exfat_make_mode(sbi, info.attr, 0777);
	} else { /* regular file */
		inode->i_generation |= 1;
		inode->i_mode = exfat_make_mode(sbi, info.attr, 0777);
		inode->i_op = &exfat_file_inode_operations;
		inode->i_fop = &exfat_file_operations;
		inode->i_mapping->a_ops = &exfat_aops;

		inode->i_mapping->nrpages = 0;

	}

	/*
	 * Use fid->size instead of info.size
	 * because info.size means the value saved on disk
	 */
	i_size_write(inode, size);

	/* ondisk and aligned size should be aligned with block size */
	if (size & (inode->i_sb->s_blocksize - 1)) {
		size |= (inode->i_sb->s_blocksize - 1);
		size++;
	}

	EXFAT_I(inode)->i_size_aligned = size;
	EXFAT_I(inode)->i_size_ondisk = size;

	exfat_save_attr(inode, info.attr);

	inode->i_blocks = ((i_size_read(inode) + (sbi->cluster_size - 1))
		& ~((loff_t)sbi->cluster_size - 1)) >> inode->i_blkbits;

	exfat_time_fat2unix(sbi, &inode->i_mtime, &info.modify_timestamp);
	exfat_time_fat2unix(sbi, &inode->i_ctime, &info.create_timestamp);
	exfat_time_fat2unix(sbi, &inode->i_atime, &info.access_timestamp);

	return 0;
}

struct inode *exfat_build_inode(struct super_block *sb,
		const struct exfat_file_id *fid, loff_t i_pos)
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
	err = exfat_fill_inode(inode, fid);
	if (err) {
		iput(inode);
		inode = ERR_PTR(err);
		goto out;
	}
	exfat_attach(inode, i_pos);
	insert_inode_hash(inode);
out:
	return inode;
}

void exfat_evict_inode(struct inode *inode)
{
	truncate_inode_pages(&inode->i_data, 0);

	if (!inode->i_nlink) {
		loff_t old_size = i_size_read(inode);

		i_size_write(inode, 0);
		EXFAT_I(inode)->fid.size = old_size;
		mutex_lock(&EXFAT_SB(inode->i_sb)->s_lock);
		__exfat_truncate(inode, old_size, 0);
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
	exfat_detach(inode);
}
