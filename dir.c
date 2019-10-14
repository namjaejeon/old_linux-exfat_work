// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/slab.h>
#include <linux/bio.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

/* skip iterating emit_dots when dir is empty */
#define ITER_POS_FILLED_DOTS    (2)

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

void get_uniname_from_dos_entry(struct super_block *sb, struct exfat_dos_dentry *ep,
		struct exfat_uni_name *p_uniname, unsigned char mode)
{
	struct exfat_dos_name dos_name;

	if (mode == 0x0)
		dos_name.name_case = 0x0;
	else
		dos_name.name_case = ep->lcase;

	memcpy(dos_name.name, ep->name, DOS_NAME_LENGTH);
	nls_sfn_to_uni16s(sb, &dos_name, p_uniname);
}

/* read a directory entry from the opened directory */
int ___readdir(struct inode *inode, struct exfat_dir_entry *dir_entry)
{
	int i;
	int dentries_per_clu, dentries_per_clu_bits = 0;
	unsigned int type, clu_offset;
	unsigned long long sector;
	struct exfat_chain dir, clu;
	struct exfat_uni_name uni_name;
	struct exfat_timestamp tm;
	struct exfat_dentry *ep;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);
	unsigned int dentry = (unsigned int)(fid->rwoffset & 0xFFFFFFFF);

	/* check if the given file ID is opened */
	if (fid->type != TYPE_DIR)
		return -EPERM;

	if (fid->entry == -1) {
		dir.dir = sbi->root_dir;
		dir.size = 0; /* just initialize, but will not use */
		dir.flags = 0x01;
	} else {
		dir.dir = fid->start_clu;
		dir.size = fid->size >> sbi->cluster_size_bits;
		dir.flags = fid->flags;
	}

	if (IS_CLUS_FREE(dir.dir)) { /* FAT16 root_dir */
		dentries_per_clu = sbi->dentries_in_root;

		/* Prevent readdir over directory size */
		if (dentry >= dentries_per_clu) {
			clu.dir = CLUS_EOF;
		} else {
			clu.dir = dir.dir;
			clu.size = dir.size;
			clu.flags = dir.flags;
		}
	} else {
		dentries_per_clu = sbi->dentries_per_clu;
		dentries_per_clu_bits = ilog2(dentries_per_clu);

		clu_offset = dentry >> dentries_per_clu_bits;
		clu.dir = dir.dir;
		clu.size = dir.size;
		clu.flags = dir.flags;

		if (clu.flags == 0x03) {
			clu.dir += clu_offset;
			clu.size -= clu_offset;
		} else {
			/* hint_information */
			if ((clu_offset > 0) &&
				((fid->hint_bmap.off != CLUS_EOF) &&
				(fid->hint_bmap.off > 0)) &&
				(clu_offset >= fid->hint_bmap.off)) {
				clu_offset -= fid->hint_bmap.off;
				clu.dir = fid->hint_bmap.clu;
			}

			while (clu_offset > 0) {
				if (get_next_clus_safe(sb, &(clu.dir)))
					return -EIO;

				clu_offset--;
			}
		}
	}

	while (!IS_CLUS_EOF(clu.dir)) {
		if (IS_CLUS_FREE(dir.dir)) /* FAT16 root_dir */
			i = dentry % dentries_per_clu;
		else
			i = dentry & (dentries_per_clu-1);

		for ( ; i < dentries_per_clu; i++, dentry++) {
			ep = get_dentry_in_dir(sb, &clu, i, &sector);
			if (!ep)
				return -EIO;

			type = exfat_get_entry_type(ep);

			if (type == TYPE_UNUSED)
				break;

			if ((type != TYPE_FILE) && (type != TYPE_DIR))
				continue;

			dcache_lock(sb, sector);
			dir_entry->attr = exfat_get_entry_attr(ep);

			exfat_get_entry_time(ep, &tm, TM_CREATE);
			dir_entry->create_timestamp.year = tm.year;
			dir_entry->create_timestamp.month = tm.mon;
			dir_entry->create_timestamp.day = tm.day;
			dir_entry->create_timestamp.hour = tm.hour;
			dir_entry->create_timestamp.minute = tm.min;
			dir_entry->create_timestamp.second = tm.sec;
			dir_entry->create_timestamp.milli_second = 0;

			exfat_get_entry_time(ep, &tm, TM_MODIFY);
			dir_entry->modify_timestamp.year = tm.year;
			dir_entry->modify_timestamp.month = tm.mon;
			dir_entry->modify_timestamp.day = tm.day;
			dir_entry->modify_timestamp.hour = tm.hour;
			dir_entry->modify_timestamp.minute = tm.min;
			dir_entry->modify_timestamp.second = tm.sec;
			dir_entry->modify_timestamp.milli_second = 0;

			memset((s8 *) &dir_entry->access_timestamp, 0,
				sizeof(struct exfat_date_time));

			*(uni_name.name) = 0x0;
			exfat_get_uniname_from_ext_entry(sb, &dir, dentry,
				uni_name.name);
			if (*(uni_name.name) == 0x0)
				get_uniname_from_dos_entry(sb,
					(struct exfat_dos_dentry *) ep, &uni_name, 0x1);
			nls_uni16s_to_vfsname(sb, &uni_name,
				dir_entry->namebuf.lfn,
				dir_entry->namebuf.lfnbuf_len);
			dcache_unlock(sb, sector);

			ep = get_dentry_in_dir(sb, &clu, i+1, NULL);
			if (!ep)
				return -EIO;
			dir_entry->size = exfat_get_entry_size(ep);

			/*
			 * Update hint information :
			 * fat16 root directory does not need it.
			 */
			if (!IS_CLUS_FREE(dir.dir)) {
				fid->hint_bmap.off =
					dentry >> dentries_per_clu_bits;
				fid->hint_bmap.clu = clu.dir;
			}

			fid->rwoffset = (s64) ++dentry;
			return 0;
		}

		/* fat16 root directory */
		if (IS_CLUS_FREE(dir.dir))
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

	dir_entry->namebuf.lfn[0] = '\0';

	fid->rwoffset = (s64)dentry;

	return 0;
}

static void exfat_init_namebuf(struct exfat_dentry_namebuf *nb)
{
	nb->lfn = NULL;
	nb->sfn = NULL;
	nb->lfnbuf_len = 0;
	nb->sfnbuf_len = 0;
}

static int exfat_alloc_namebuf(struct exfat_dentry_namebuf *nb)
{
	nb->lfn = __getname();
	if (!nb->lfn)
		return -ENOMEM;
	nb->sfn = nb->lfn + MAX_VFSNAME_BUF_SIZE;
	nb->lfnbuf_len = MAX_VFSNAME_BUF_SIZE;
	nb->sfnbuf_len = MAX_VFSNAME_BUF_SIZE;
	return 0;
}

static void exfat_free_namebuf(struct exfat_dentry_namebuf *nb)
{
	if (!nb->lfn)
		return;

	__putname(nb->lfn);
	exfat_init_namebuf(nb);
}

//instead of exfat_readdir
static int exfat_iterate(struct file *filp, struct dir_context *ctx)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct exfat_dir_entry de;
	struct exfat_dentry_namebuf *nb = &(de.namebuf);
	unsigned long inum;
	loff_t cpos;
	int err = 0, fake_offset = 0;

	exfat_init_namebuf(nb);
	mutex_lock(&EXFAT_SB(sb)->s_lock);

	cpos = ctx->pos;
	if (!dir_emit_dots(filp, ctx))
		goto out;

	if (ctx->pos == ITER_POS_FILLED_DOTS) {
		cpos = 0;
		fake_offset = 1;
	}

	if (cpos & (DENTRY_SIZE - 1)) {
		err = -ENOENT;
		goto out;
	}

	/* name buffer should be allocated before use */
	err = exfat_alloc_namebuf(nb);
	if (err)
		goto out;
get_new:
	EXFAT_I(inode)->fid.size = i_size_read(inode);
	EXFAT_I(inode)->fid.rwoffset = cpos >> DENTRY_SIZE_BITS;

	if (cpos >= EXFAT_I(inode)->fid.size)
		goto end_of_dir;

	err = ___readdir(inode, &de);
	if (err) {
		// at least we tried to read a sector
		// move cpos to next sector position (should be aligned)
		if (err == -EIO) {
			cpos += 1 << (sb->s_blocksize_bits);
			cpos &= ~((unsigned int)sb->s_blocksize-1);
		}

		err = -EIO;
		goto end_of_dir;
	}

	cpos = EXFAT_I(inode)->fid.rwoffset << DENTRY_SIZE_BITS;

	if (!nb->lfn[0])
		goto end_of_dir;

	if (!memcmp(nb->sfn, DOS_CUR_DIR_NAME, DOS_NAME_LENGTH)) {
		inum = inode->i_ino;
	} else if (!memcmp(nb->sfn, DOS_PAR_DIR_NAME, DOS_NAME_LENGTH)) {
		inum = parent_ino(filp->f_path.dentry);
	} else {
		loff_t i_pos = ((loff_t) EXFAT_I(inode)->fid.start_clu << 32) |
			((EXFAT_I(inode)->fid.rwoffset-1) & 0xffffffff);
		struct inode *tmp = exfat_iget(sb, i_pos);

		if (tmp) {
			inum = tmp->i_ino;
			iput(tmp);
		} else {
			inum = iunique(sb, EXFAT_ROOT_INO);
		}
	}

	/*
	 * Before calling dir_emit(), sb_lock should be released.
	 * Because page fault can occur in dir_emit() when the size
	 * of buffer given from user is larger than one page size.
	 */
	if (!dir_emit(ctx, nb->lfn, strlen(nb->lfn), inum,
			(de.attr & ATTR_SUBDIR) ? DT_DIR : DT_REG))
		goto out_unlocked;
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	ctx->pos = cpos;
	goto get_new;

end_of_dir:
	if (!cpos && fake_offset)
		cpos = ITER_POS_FILLED_DOTS;
	ctx->pos = cpos;
out:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
out_unlocked:
	/*
	 * To improve performance, free namebuf after unlock sb_lock.
	 * If namebuf is not allocated, this function do nothing
	 */
	exfat_free_namebuf(nb);
	return err;
}

const struct file_operations exfat_dir_operations = {
		.llseek     = generic_file_llseek,
		.read       = generic_read_dir,
		.iterate    = exfat_iterate,
		.fsync      = exfat_file_fsync,
};

