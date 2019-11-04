// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/slab.h>
#include <linux/bio.h>
#include <linux/buffer_head.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

void exfat_update_bh(struct super_block *sb, struct buffer_head *bh, int sync)
{
	WRITE_ONCE(EXFAT_SB(sb)->s_dirt, true);
	set_buffer_uptodate(bh);
	mark_buffer_dirty(bh);

	if (sync)
		sync_dirty_buffer(bh);
}

/* read a directory entry from the opened directory */
static int exfat_readdir(struct inode *inode, struct exfat_dir_entry *dir_entry)
{
	int i;
	int dentries_per_clu, dentries_per_clu_bits = 0;
	unsigned int type, clu_offset;
	sector_t sector;
	struct exfat_chain dir, clu;
	struct exfat_uni_name uni_name;
	struct exfat_timestamp tm;
	struct exfat_dentry *ep;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	unsigned int dentry = ei->rwoffset & 0xFFFFFFFF;
	struct buffer_head *bh;

	/* check if the given file ID is opened */
	if (ei->type != TYPE_DIR)
		return -EPERM;

	if (ei->entry == -1) {
		dir.dir = sbi->root_dir;
		dir.size = 0; /* just initialize, but will not use */
		dir.flags = 0x01;
	} else {
		dir.dir = ei->start_clu;
		dir.size = EXFAT_B_TO_CLU(i_size_read(inode), sbi);
		dir.flags = ei->flags;
	}

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
		if ((clu_offset > 0) && ((ei->hint_bmap.off != EOF_CLUSTER) &&
			(ei->hint_bmap.off > 0)) &&
			(clu_offset >= ei->hint_bmap.off)) {
			clu_offset -= ei->hint_bmap.off;
			clu.dir = ei->hint_bmap.clu;
		}

		while (clu_offset > 0) {
			if (exfat_get_next_cluster(sb, &(clu.dir)))
				return -EIO;

			clu_offset--;
		}
	}

	while (clu.dir != EOF_CLUSTER) {
		i = dentry & (dentries_per_clu - 1);

		for ( ; i < dentries_per_clu; i++, dentry++) {
			ep = exfat_get_dentry(sb, &clu, i, &bh, &sector);
			if (!ep)
				return -EIO;

			type = exfat_get_entry_type(ep);

			if (type == TYPE_UNUSED) {
				brelse(bh);
				break;
			}

			if ((type != TYPE_FILE) && (type != TYPE_DIR)) {
				brelse(bh);
				continue;
			}

			dir_entry->attr = le16_to_cpu(ep->file_attr);

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

			memset(&dir_entry->access_timestamp, 0,
				sizeof(struct exfat_date_time));

			*(uni_name.name) = 0x0;
			exfat_get_uniname_from_ext_entry(sb, &dir, dentry,
				uni_name.name);
			exfat_nls_uni16s_to_vfsname(sb, &uni_name,
				dir_entry->namebuf.lfn,
				dir_entry->namebuf.lfnbuf_len);
			brelse(bh);

			ep = exfat_get_dentry(sb, &clu, i + 1, &bh, NULL);
			if (!ep)
				return -EIO;
			dir_entry->size = le64_to_cpu(ep->stream_valid_size);
			brelse(bh);

			ei->hint_bmap.off = dentry >> dentries_per_clu_bits;
			ei->hint_bmap.clu = clu.dir;

			ei->rwoffset = ++dentry;
			return 0;
		}

		if (clu.flags == 0x03) {
			if ((--clu.size) > 0)
				clu.dir++;
			else
				clu.dir = EOF_CLUSTER;
		} else {
			if (exfat_get_next_cluster(sb, &(clu.dir)))
				return -EIO;
		}
	}

	dir_entry->namebuf.lfn[0] = '\0';
	ei->rwoffset = dentry;
	return 0;
}

static void exfat_init_namebuf(struct exfat_dentry_namebuf *nb)
{
	nb->lfn = NULL;
	nb->sfn = NULL;
	nb->lfnbuf_len = 0;
}

static int exfat_alloc_namebuf(struct exfat_dentry_namebuf *nb)
{
	nb->lfn = __getname();
	if (!nb->lfn)
		return -ENOMEM;
	nb->sfn = nb->lfn + MAX_VFSNAME_BUF_SIZE;
	nb->lfnbuf_len = MAX_VFSNAME_BUF_SIZE;
	return 0;
}

static void exfat_free_namebuf(struct exfat_dentry_namebuf *nb)
{
	if (!nb->lfn)
		return;

	__putname(nb->lfn);
	exfat_init_namebuf(nb);
}

/* skip iterating emit_dots when dir is empty */
#define ITER_POS_FILLED_DOTS    (2)
static int exfat_iterate(struct file *filp, struct dir_context *ctx)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct exfat_dir_entry de;
	struct exfat_dentry_namebuf *nb = &(de.namebuf);
	struct exfat_inode_info *ei = EXFAT_I(inode);
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
	ei->rwoffset = EXFAT_B_TO_DEN(cpos);

	if (cpos >= i_size_read(inode))
		goto end_of_dir;

	err = exfat_readdir(inode, &de);
	if (err) {
		// at least we tried to read a sector
		// move cpos to next sector position (should be aligned)
		if (err == -EIO) {
			cpos += 1 << (sb->s_blocksize_bits);
			cpos &= ~(sb->s_blocksize - 1);
		}

		err = -EIO;
		goto end_of_dir;
	}

	cpos = EXFAT_DEN_TO_B(ei->rwoffset);

	if (!nb->lfn[0])
		goto end_of_dir;

	if (!memcmp(nb->sfn, DOS_CUR_DIR_NAME, DOS_NAME_LENGTH)) {
		inum = inode->i_ino;
	} else if (!memcmp(nb->sfn, DOS_PAR_DIR_NAME, DOS_NAME_LENGTH)) {
		inum = parent_ino(filp->f_path.dentry);
	} else {
		loff_t i_pos = ((loff_t)ei->start_clu << 32) |
			((ei->rwoffset - 1) & 0xffffffff);
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
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= exfat_iterate,
	.fsync		= generic_file_fsync,
};

int exfat_alloc_new_dir(struct inode *inode, struct exfat_chain *clu)
{
	int ret;
	struct super_block *sb = inode->i_sb;

	clu->dir = EOF_CLUSTER;
	clu->size = 0;
	clu->flags = 0x03;

	ret = exfat_alloc_cluster(sb, 1, clu);
	if (ret)
		return ret;

	return exfat_clear_cluster(inode, clu->dir);
}

static int exfat_calc_num_entries(struct exfat_uni_name *p_uniname)
{
	int len;

	len = p_uniname->name_len;
	if (len == 0)
		return 0;

	/* 1 file entry + 1 stream entry + name entries */
	return((len - 1) / 15 + 3);
}

/* input  : dir, uni_name
 * output : num_of_entry
 */
int exfat_get_num_entries(struct exfat_uni_name *p_uniname)
{
	int num_entries;

	num_entries = exfat_calc_num_entries(p_uniname);
	if (num_entries == 0)
		return -EINVAL;

	return num_entries;
}

unsigned int exfat_get_entry_type(struct exfat_dentry *ep)
{
	if (ep->type == EXFAT_UNUSED)
		return TYPE_UNUSED;
	if (IS_EXFAT_DELETED(ep->type))
		return TYPE_DELETED;
	if (ep->type == EXFAT_INVAL)
		return TYPE_INVALID;
	if (ep->type < 0xA0) {
		if (ep->type == EXFAT_BITMAP)
			return TYPE_BITMAP;
		if (ep->type == EXFAT_UPCASE)
			return TYPE_UPCASE;
		if (ep->type == EXFAT_VOLUME)
			return TYPE_VOLUME;
		if (ep->type == EXFAT_FILE) {
			if (le16_to_cpu(ep->file_attr) & ATTR_SUBDIR)
				return TYPE_DIR;
			return TYPE_FILE;
		}
		return TYPE_CRITICAL_PRI;
	}
	if (ep->type < 0xC0) {
		if (ep->type == EXFAT_GUID)
			return TYPE_GUID;
		if (ep->type == EXFAT_PADDING)
			return TYPE_PADDING;
		if (ep->type == EXFAT_ACLTAB)
			return TYPE_ACLTAB;
		return TYPE_BENIGN_PRI;
	}
	if (ep->type < 0xE0) {
		if (ep->type == EXFAT_STREAM)
			return TYPE_STREAM;
		if (ep->type == EXFAT_NAME)
			return TYPE_EXTEND;
		if (ep->type == EXFAT_ACL)
			return TYPE_ACL;
		return TYPE_CRITICAL_SEC;
	}
	return TYPE_BENIGN_SEC;
}

static void exfat_set_entry_type(struct exfat_dentry *ep, unsigned int type)
{
	if (type == TYPE_UNUSED) {
		ep->type = EXFAT_UNUSED;
	} else if (type == TYPE_DELETED) {
		ep->type &= EXFAT_DELETE;
	} else if (type == TYPE_STREAM) {
		ep->type = EXFAT_STREAM;
	} else if (type == TYPE_EXTEND) {
		ep->type = EXFAT_NAME;
	} else if (type == TYPE_BITMAP) {
		ep->type = EXFAT_BITMAP;
	} else if (type == TYPE_UPCASE) {
		ep->type = EXFAT_UPCASE;
	} else if (type == TYPE_VOLUME) {
		ep->type = EXFAT_VOLUME;
	} else if (type == TYPE_DIR) {
		ep->type = EXFAT_FILE;
		ep->file_attr = ATTR_SUBDIR_LE;
	} else if (type == TYPE_FILE) {
		ep->type = EXFAT_FILE;
		ep->file_attr = ATTR_ARCHIVE_LE;
	}
}

void exfat_get_entry_time(struct exfat_dentry *ep, struct exfat_timestamp *tp,
		unsigned char mode)
{
	unsigned short t = 0x00, d = 0x21;

	switch (mode) {
	case TM_CREATE:
		t = le16_to_cpu(ep->file_create_time);
		d = le16_to_cpu(ep->file_create_date);
		break;
	case TM_MODIFY:
		t = le16_to_cpu(ep->file_modify_time);
		d = le16_to_cpu(ep->file_modify_date);
		break;
	case TM_ACCESS:
		t = le16_to_cpu(ep->file_access_time);
		d = le16_to_cpu(ep->file_access_date);
		break;
	}

	tp->sec  = (t & 0x001F) << 1;
	tp->min  = (t >> 5) & 0x003F;
	tp->hour = (t >> 11);
	tp->day  = (d & 0x001F);
	tp->mon  = (d >> 5) & 0x000F;
	tp->year = (d >> 9);
}

void exfat_set_entry_time(struct exfat_dentry *ep,
		struct exfat_timestamp *tp, unsigned char mode)
{
	unsigned short t, d;

	t = (tp->hour << 11) | (tp->min << 5) | (tp->sec >> 1);
	d = (tp->year <<  9) | (tp->mon << 5) |  tp->day;

	switch (mode) {
	case TM_CREATE:
		ep->file_create_time = cpu_to_le16(t);
		ep->file_create_date = cpu_to_le16(d);
		break;
	case TM_MODIFY:
		ep->file_modify_time = cpu_to_le16(t);
		ep->file_modify_date = cpu_to_le16(d);
		break;
	case TM_ACCESS:
		ep->file_access_time = cpu_to_le16(t);
		ep->file_access_date = cpu_to_le16(d);
		break;
	}
}

static void exfat_init_file_entry(struct super_block *sb,
		struct exfat_dentry *ep, unsigned int type)
{
	struct exfat_timestamp tm, *tp;

	exfat_set_entry_type(ep, type);

	tp = exfat_tm_now(EXFAT_SB(sb), &tm);
	exfat_set_entry_time(ep, tp, TM_CREATE);
	exfat_set_entry_time(ep, tp, TM_MODIFY);
	exfat_set_entry_time(ep, tp, TM_ACCESS);
	ep->file_create_time_ms = 0;
	ep->file_modify_time_ms = 0;
	ep->file_access_time_ms = 0;
}

static void exfat_init_stream_entry(struct exfat_dentry *ep,
		unsigned char flags, unsigned int start_clu,
		unsigned long long size)
{
	exfat_set_entry_type(ep, TYPE_STREAM);
	ep->stream_flags = flags;
	ep->stream_start_clu = cpu_to_le32(start_clu);
	ep->stream_valid_size = cpu_to_le64(size);
	ep->stream_size = cpu_to_le64(size);
}

static void exfat_init_name_entry(struct exfat_dentry *ep,
		unsigned short *uniname)
{
	int i;

	exfat_set_entry_type(ep, TYPE_EXTEND);
	ep->name_flags = 0x0;

	for (i = 0; i < 15; i++) {
		ep->name_unicode[i] = cpu_to_le16(*uniname);
		if (*uniname == 0x0)
			break;
		uniname++;
	}
}

int exfat_init_dir_entry(struct super_block *sb, struct exfat_chain *p_dir,
		int entry, unsigned int type, unsigned int start_clu,
		unsigned long long size)
{
	sector_t sector;
	unsigned char flags;
	struct exfat_dentry *ep;
	struct buffer_head *bh;

	flags = (type == TYPE_FILE) ? 0x01 : 0x03;

	/*
	 * we cannot use exfat_get_dentry_set here because file ep is not
	 * initialized yet.
	 */
	ep = exfat_get_dentry(sb, p_dir, entry, &bh, &sector);
	if (!ep)
		return -EIO;

	exfat_init_file_entry(sb, ep, type);
	exfat_update_bh(sb, bh, 0);
	brelse(bh);

	ep = exfat_get_dentry(sb, p_dir, entry + 1, &bh, &sector);
	if (!ep)
		return -EIO;

	exfat_init_stream_entry(ep, flags, start_clu, size);
	exfat_update_bh(sb, bh, 0);
	brelse(bh);

	return 0;
}

int update_dir_chksum(struct super_block *sb, struct exfat_chain *p_dir,
		int entry)
{
	int ret = 0;
	int i, num_entries;
	sector_t sector;
	unsigned short chksum;
	struct exfat_dentry *ep, *fep;
	struct buffer_head *fbh, *bh;

	fep = exfat_get_dentry(sb, p_dir, entry, &fbh, &sector);
	if (!fep)
		return -EIO;

	num_entries = fep->file_num_ext + 1;
	chksum = exfat_calc_chksum_2byte(fep, DENTRY_SIZE, 0, CS_DIR_ENTRY);

	for (i = 1; i < num_entries; i++) {
		ep = exfat_get_dentry(sb, p_dir, entry + i, &bh, NULL);
		if (!ep) {
			ret = -EIO;
			goto out_unlock;
		}
		chksum = exfat_calc_chksum_2byte(ep, DENTRY_SIZE, chksum,
				CS_DEFAULT);
		brelse(bh);
	}

	fep->file_checksum = cpu_to_le16(chksum);
	exfat_update_bh(sb, fbh, 0);
out_unlock:
	brelse(fbh);
	return ret;
}

int exfat_init_ext_entry(struct super_block *sb, struct exfat_chain *p_dir,
		int entry, int num_entries, struct exfat_uni_name *p_uniname)
{
	int i;
	sector_t sector;
	unsigned short *uniname = p_uniname->name;
	struct exfat_dentry *ep;
	struct buffer_head *bh;

	ep = exfat_get_dentry(sb, p_dir, entry, &bh, &sector);
	if (!ep)
		return -EIO;

	ep->file_num_ext = (unsigned char)(num_entries - 1);
	exfat_update_bh(sb, bh, 0);
	brelse(bh);

	ep = exfat_get_dentry(sb, p_dir, entry + 1, &bh, &sector);
	if (!ep)
		return -EIO;

	ep->stream_name_len = p_uniname->name_len;
	ep->stream_name_hash = cpu_to_le16(p_uniname->name_hash);
	exfat_update_bh(sb, bh, 0);
	brelse(bh);

	for (i = 2; i < num_entries; i++) {
		ep = exfat_get_dentry(sb, p_dir, entry + i, &bh, &sector);
		if (!ep)
			return -EIO;

		exfat_init_name_entry(ep, uniname);
		exfat_update_bh(sb, bh, 0);
		brelse(bh);
		uniname += 15;
	}

	update_dir_chksum(sb, p_dir, entry);
	return 0;
}

int exfat_remove_entries(struct super_block *sb, struct exfat_chain *p_dir,
		int entry, int order, int num_entries)
{
	int i;
	sector_t sector;
	struct exfat_dentry *ep;
	struct buffer_head *bh;

	for (i = order; i < num_entries; i++) {
		ep = exfat_get_dentry(sb, p_dir, entry + i, &bh, &sector);
		if (!ep)
			return -EIO;

		exfat_set_entry_type(ep, TYPE_DELETED);
		exfat_update_bh(sb, bh, 0);
		brelse(bh);
	}

	return 0;
}

/* write back all entries in entry set */
static int exfat_write_partial_entries_in_entry_set(struct super_block *sb,
		struct exfat_entry_set_cache *es, sector_t sec,
		unsigned int off, unsigned int count)
{
	int num_entries;
	unsigned int buf_off = (off - es->offset);
	unsigned int remaining_byte_in_sector, copy_entries;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int clu;
	unsigned char *esbuf = (unsigned char *)&(es->__buf);
	int sync = es->sync;
	struct buffer_head *bh;

	num_entries = count;

	while (num_entries) {
		/* write per sector base */
		remaining_byte_in_sector = (1 << sb->s_blocksize_bits) - off;
		copy_entries = min_t(int,
			EXFAT_B_TO_DEN(remaining_byte_in_sector),
			num_entries);
		bh = sb_bread(sb, sec);
		if (!bh)
			goto err_out;
		memcpy(bh->b_data + off, esbuf + buf_off,
				EXFAT_DEN_TO_B(copy_entries));
		exfat_update_bh(sb, bh, sync);
		brelse(bh);
		num_entries -= copy_entries;

		if (num_entries) {
			// get next sector
			if (exfat_is_last_sector_in_cluster(sbi, sec)) {
				clu = exfat_sector_to_cluster(sbi, sec);
				if (es->alloc_flag == 0x03)
					clu++;
				else if (exfat_get_next_cluster(sb, &clu))
					goto err_out;
				sec = exfat_cluster_to_sector(sbi, clu);
			} else {
				sec++;
			}
			off = 0;
			buf_off += EXFAT_DEN_TO_B(copy_entries);
		}
	}

	return 0;
err_out:
	return -EIO;
}

int exfat_update_dir_chksum_with_entry_set(struct super_block *sb,
		struct exfat_entry_set_cache *es)
{
	struct exfat_dentry *ep;
	unsigned short chksum = 0;
	int chksum_type = CS_DIR_ENTRY, i;

	ep = (struct exfat_dentry *)&(es->__buf);
	for (i = 0; i < es->num_entries; i++) {
		chksum = exfat_calc_chksum_2byte((void *) ep, DENTRY_SIZE,
			chksum, chksum_type);
		ep++;
		chksum_type = CS_DEFAULT;
	}

	ep = (struct exfat_dentry *)&(es->__buf);
	ep->file_checksum = cpu_to_le16(chksum);
	return exfat_write_partial_entries_in_entry_set(sb, es, es->sector,
			es->offset, es->num_entries);
}

static int exfat_walk_fat_chain(struct super_block *sb,
		struct exfat_chain *p_dir, unsigned int byte_offset,
		unsigned int *clu)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int clu_offset;
	unsigned int cur_clu;

	clu_offset = EXFAT_B_TO_CLU(byte_offset, sbi);
	cur_clu = p_dir->dir;

	if (p_dir->flags == 0x03) {
		cur_clu += clu_offset;
	} else {
		while (clu_offset > 0) {
			if (exfat_get_next_cluster(sb, &cur_clu))
				return -EIO;
			if (cur_clu == EOF_CLUSTER) {
				exfat_fs_error(sb,
					"invalid dentry access beyond EOF (clu : %u, eidx : %d)",
					p_dir->dir,
					EXFAT_B_TO_DEN(byte_offset));
				return -EIO;
			}
			clu_offset--;
		}
	}

	*clu = cur_clu;
	return 0;
}

int exfat_find_location(struct super_block *sb, struct exfat_chain *p_dir,
		int entry, sector_t *sector, int *offset)
{
	int ret;
	unsigned int off, clu = 0;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	off = EXFAT_DEN_TO_B(entry);

	ret = exfat_walk_fat_chain(sb, p_dir, off, &clu);
	if (ret)
		return ret;

	/* byte offset in cluster */
	off = EXFAT_CLU_OFFSET(off, sbi);

	/* byte offset in sector    */
	*offset = EXFAT_BLK_OFFSET(off, sb);

	/* sector offset in cluster */
	*sector = EXFAT_B_TO_BLK(off, sb);
	*sector += exfat_cluster_to_sector(sbi, clu);
	return 0;
}

#define EXFAT_MAX_RA_SIZE     (128*1024)
static int exfat_dir_readahead(struct super_block *sb, sector_t sec)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;
	unsigned int max_ra_count = EXFAT_MAX_RA_SIZE >> sb->s_blocksize_bits;
	unsigned int page_ra_count = PAGE_SIZE >> sb->s_blocksize_bits;
	unsigned int adj_ra_count = max(sbi->sect_per_clus, page_ra_count);
	unsigned int ra_count = min(adj_ra_count, max_ra_count);

	/* Read-ahead is not required */
	if (sbi->sect_per_clus == 1)
		return 0;

	if (sec < sbi->data_start_sector) {
		exfat_msg(sb, KERN_ERR,
			"requested sector is invalid(sect:%llu, root:%llu)",
			sec, sbi->data_start_sector);
		return -EIO;
	}

	/* Not sector aligned with ra_count, resize ra_count to page size */
	if ((sec - sbi->data_start_sector) & (ra_count - 1))
		ra_count = page_ra_count;

	bh = sb_find_get_block(sb, sec);
	if (!bh || !buffer_uptodate(bh)) {
		unsigned int i;

		for (i = 0; i < ra_count; i++)
			sb_breadahead(sb, (sector_t)(sec + i));
	}
	brelse(bh);
	return 0;
}

struct exfat_dentry *exfat_get_dentry(struct super_block *sb,
		struct exfat_chain *p_dir, int entry, struct buffer_head **bh,
		sector_t *sector)
{
	unsigned int dentries_per_page = EXFAT_B_TO_DEN(PAGE_SIZE);
	int off;
	sector_t sec;

	if (p_dir->dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "abnormal access to deleted dentry\n");
		return NULL;
	}

	if (exfat_find_location(sb, p_dir, entry, &sec, &off))
		return NULL;

	if ((p_dir->dir != FREE_CLUSTER) &&
			!(entry & (dentries_per_page - 1)))
		exfat_dir_readahead(sb, sec);

	*bh = sb_bread(sb, sec);
	if (!*bh)
		return NULL;

	if (sector)
		*sector = sec;
	return (struct exfat_dentry *)((*bh)->b_data + off);
}

/* returns a set of dentries for a file or dir.
 * Note that this is a copy (dump) of dentries so that user should
 * call write_entry_set() to apply changes made in this entry set
 * to the real device.
 * in:
 *   sb+p_dir+entry: indicates a file/dir
 *   type:  specifies how many dentries should be included.
 * out:
 *   file_ep: will point the first dentry(= file dentry) on success
 * return:
 *   pointer of entry set on success,
 *   NULL on failure.
 */
#define ES_MODE_STARTED				0
#define ES_MODE_GET_FILE_ENTRY			1
#define ES_MODE_GET_STRM_ENTRY			2
#define ES_MODE_GET_NAME_ENTRY			3
#define ES_MODE_GET_CRITICAL_SEC_ENTRY		4
struct exfat_entry_set_cache *exfat_get_dentry_set(struct super_block *sb,
		struct exfat_chain *p_dir, int entry, unsigned int type,
		struct exfat_dentry **file_ep)
{
	int ret;
	unsigned int off, byte_offset, clu = 0;
	unsigned int entry_type;
	sector_t sec;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_entry_set_cache *es = NULL;
	struct exfat_dentry *ep, *pos;
	unsigned char num_entries;
	int mode = ES_MODE_STARTED;
	struct buffer_head *bh;

	/* FIXME : is available in error case? */
	if (p_dir->dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "access to deleted dentry\n");
		return NULL;
	}

	byte_offset = EXFAT_DEN_TO_B(entry);
	ret = exfat_walk_fat_chain(sb, p_dir, byte_offset, &clu);
	if (ret)
		return NULL;

	/* byte offset in cluster */
	byte_offset = EXFAT_CLU_OFFSET(byte_offset, sbi);

	/* byte offset in sector */
	off = EXFAT_BLK_OFFSET(byte_offset, sb);

	/* sector offset in cluster */
	sec = EXFAT_B_TO_BLK(byte_offset, sb);
	sec += exfat_cluster_to_sector(sbi, clu);

	bh = sb_bread(sb, sec);
	if (!bh)
		goto err_out;

	ep = (struct exfat_dentry *)(bh->b_data + off);
	entry_type = exfat_get_entry_type(ep);

	if ((entry_type != TYPE_FILE)
			&& (entry_type != TYPE_DIR))
		goto err_out;

	if (type == ES_ALL_ENTRIES)
		num_entries = ep->file_num_ext + 1;
	else
		num_entries = type;

	es = kmalloc((offsetof(struct exfat_entry_set_cache, __buf) +
		(num_entries) * sizeof(struct exfat_dentry)), GFP_KERNEL);
	if (!es)
		goto err_out;

	es->num_entries = num_entries;
	es->sector = sec;
	es->offset = off;
	es->alloc_flag = p_dir->flags;
	es->sync = 0;

	pos = (struct exfat_dentry *)&(es->__buf);

	while (num_entries) {
		// instead of copying whole sector, we will check every entry.
		// this will provide minimum stablity and consistency.
		entry_type = exfat_get_entry_type(ep);

		if ((entry_type == TYPE_UNUSED) ||
				(entry_type == TYPE_DELETED))
			goto err_out;

		switch (mode) {
		case ES_MODE_STARTED:
			if  ((entry_type == TYPE_FILE) ||
					(entry_type == TYPE_DIR))
				mode = ES_MODE_GET_FILE_ENTRY;
			else
				goto err_out;
			break;
		case ES_MODE_GET_FILE_ENTRY:
			if (entry_type == TYPE_STREAM)
				mode = ES_MODE_GET_STRM_ENTRY;
			else
				goto err_out;
			break;
		case ES_MODE_GET_STRM_ENTRY:
			if (entry_type == TYPE_EXTEND)
				mode = ES_MODE_GET_NAME_ENTRY;
			else
				goto err_out;
			break;
		case ES_MODE_GET_NAME_ENTRY:
			if (entry_type == TYPE_EXTEND)
				break;
			else if (entry_type == TYPE_STREAM)
				goto err_out;
			else if (entry_type & TYPE_CRITICAL_SEC)
				mode = ES_MODE_GET_CRITICAL_SEC_ENTRY;
			else
				goto err_out;
			break;
		case ES_MODE_GET_CRITICAL_SEC_ENTRY:
			if ((entry_type == TYPE_EXTEND) ||
					(entry_type == TYPE_STREAM))
				goto err_out;
			else if ((entry_type & TYPE_CRITICAL_SEC) !=
					TYPE_CRITICAL_SEC)
				goto err_out;
			break;
		}

		/* copy dentry */
		memcpy(pos, ep, sizeof(struct exfat_dentry));

		if (--num_entries == 0)
			break;

		if (((off + DENTRY_SIZE) &
			(sb->s_blocksize - 1)) <
			(off & (sb->s_blocksize - 1))) {
			// get the next sector
			if (exfat_is_last_sector_in_cluster(sbi, sec)) {
				if (es->alloc_flag == 0x03)
					clu++;
				else if (exfat_get_next_cluster(sb, &clu))
					goto err_out;
				sec = exfat_cluster_to_sector(sbi, clu);
			} else {
				sec++;
			}

			brelse(bh);
			bh = sb_bread(sb, sec);
			if (!bh)
				goto err_out;
			off = 0;
			ep = (struct exfat_dentry *)(bh->b_data);
		} else {
			ep++;
			off += DENTRY_SIZE;
		}
		pos++;
	}

	if (file_ep)
		*file_ep = (struct exfat_dentry *)&(es->__buf);
	brelse(bh);

	return es;
err_out:
	exfat_release_dentry_set(es);
	brelse(bh);
	return NULL;
}

void exfat_release_dentry_set(struct exfat_entry_set_cache *es)
{
	kfree(es);
}

static int exfat_extract_uni_name(struct exfat_dentry *ep,
		unsigned short *uniname)
{
	int i, len = 0;

	for (i = 0; i < 15; i++) {
		*uniname = le16_to_cpu(ep->name_unicode[i]);
		if (*uniname == 0x0)
			return len;
		uniname++;
		len++;
	}

	*uniname = 0x0;
	return len;

}

#define DIRENT_STEP_FILE	(0)
#define DIRENT_STEP_STRM	(1)
#define DIRENT_STEP_NAME	(2)
#define DIRENT_STEP_SECD	(3)

/* return values of exfat_find_dir_entry()
 * >= 0 : return dir entiry position with the name in dir
 * -EEXIST : (root dir, ".") it is the root dir itself
 * -ENOENT : entry with the name does not exist
 * -EIO    : I/O error
 */
int exfat_find_dir_entry(struct super_block *sb, struct exfat_inode_info *ei,
		struct exfat_chain *p_dir, struct exfat_uni_name *p_uniname,
		int num_entries, unsigned int type)
{
	int i, rewind = 0, dentry = 0, end_eidx = 0, num_ext = 0, len;
	int order, step, name_len;
	int dentries_per_clu, num_empty = 0;
	unsigned int entry_type;
	unsigned short entry_uniname[16], *uniname = NULL, unichar;
	struct exfat_chain clu;
	struct exfat_dentry *ep;
	struct exfat_hint *hint_stat = &ei->hint_stat;
	struct exfat_hint_femp candi_empty;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;

	dentries_per_clu = sbi->dentries_per_clu;

	clu.dir = p_dir->dir;
	clu.size = p_dir->size;
	clu.flags = p_dir->flags;

	if (hint_stat->eidx) {
		clu.dir = hint_stat->clu;
		dentry = hint_stat->eidx;
		end_eidx = dentry;
	}

	candi_empty.eidx = EXFAT_HINT_NONE;
rewind:
	order = 0;
	step = DIRENT_STEP_FILE;
	while (clu.dir != EOF_CLUSTER) {
		i = dentry & (dentries_per_clu - 1);
		for (; i < dentries_per_clu; i++, dentry++) {
			if (rewind && (dentry == end_eidx))
				goto not_found;

			ep = exfat_get_dentry(sb, &clu, i, &bh, NULL);
			if (!ep)
				return -EIO;

			entry_type = exfat_get_entry_type(ep);
			brelse(bh);

			if ((entry_type == TYPE_UNUSED) ||
					(entry_type == TYPE_DELETED)) {
				step = DIRENT_STEP_FILE;

				num_empty++;
				if (candi_empty.eidx == EXFAT_HINT_NONE &&
						num_empty == 1) {
					candi_empty.cur.dir = clu.dir;
					candi_empty.cur.size = clu.size;
					candi_empty.cur.flags = clu.flags;
				}

				if (candi_empty.eidx == EXFAT_HINT_NONE &&
						num_empty >= num_entries) {
					candi_empty.eidx =
						dentry - (num_empty - 1);
					WARN_ON(candi_empty.eidx < 0);
					candi_empty.count = num_empty;

					if (ei->hint_femp.eidx ==
							EXFAT_HINT_NONE ||
						(candi_empty.eidx <=
							 ei->hint_femp.eidx)) {
						memcpy(&ei->hint_femp,
							&candi_empty,
							sizeof(candi_empty));
					}
				}

				if (entry_type == TYPE_UNUSED)
					goto not_found;
				continue;
			}

			num_empty = 0;
			candi_empty.eidx = EXFAT_HINT_NONE;

			if ((entry_type == TYPE_FILE) ||
				(entry_type == TYPE_DIR)) {
				step = DIRENT_STEP_FILE;
				if ((type == TYPE_ALL) ||
					(type == entry_type)) {
					num_ext = ep->file_num_ext;
					step = DIRENT_STEP_STRM;
				}
				continue;
			}

			if (entry_type == TYPE_STREAM) {
				if (step != DIRENT_STEP_STRM) {
					step = DIRENT_STEP_FILE;
					continue;
				}
				step = DIRENT_STEP_FILE;
				if ((p_uniname->name_hash ==
					le16_to_cpu(ep->stream_name_hash)) &&
					(p_uniname->name_len ==
						 ep->stream_name_len)) {
					step = DIRENT_STEP_NAME;
					order = 1;
					name_len = 0;
				}
				continue;
			}

			if (entry_type == TYPE_EXTEND) {
				if (step != DIRENT_STEP_NAME) {
					step = DIRENT_STEP_FILE;
					continue;
				}

				if ((++order) == 2)
					uniname = p_uniname->name;
				else
					uniname += 15;

				len = exfat_extract_uni_name(
						ep, entry_uniname);
				name_len += len;

				unichar = *(uniname+len);
				*(uniname+len) = 0x0;

				if (exfat_nls_cmp_uniname(sb, uniname,
							entry_uniname)) {
					step = DIRENT_STEP_FILE;
				} else if (name_len == p_uniname->name_len) {
					if (order == num_ext)
						goto found;
					step = DIRENT_STEP_SECD;
				}

				*(uniname+len) = unichar;
				continue;
			}

			if (entry_type &
					(TYPE_CRITICAL_SEC | TYPE_BENIGN_SEC)) {
				if (step == DIRENT_STEP_SECD) {
					if (++order == num_ext)
						goto found;
					continue;
				}
			}
			step = DIRENT_STEP_FILE;
		}

		if (clu.flags == 0x03) {
			if ((--clu.size) > 0)
				clu.dir++;
			else
				clu.dir = EOF_CLUSTER;
		} else {
			if (exfat_get_next_cluster(sb, &clu.dir))
				return -EIO;
		}
	}

not_found:
	/* we started at not 0 index,so we should try to find target
	 * from 0 index to the index we started at.
	 */
	if (!rewind && end_eidx) {
		rewind = 1;
		dentry = 0;
		clu.dir = p_dir->dir;
		/* reset empty hint */
		num_empty = 0;
		candi_empty.eidx = EXFAT_HINT_NONE;
		goto rewind;
	}

	/* initialized hint_stat */
	hint_stat->clu = p_dir->dir;
	hint_stat->eidx = 0;
	return -ENOENT;

found:
	/* next dentry we'll find is out of this cluster */
	if (!((dentry + 1) & (dentries_per_clu - 1))) {
		int ret = 0;

		if (clu.flags == 0x03) {
			if ((--clu.size) > 0)
				clu.dir++;
			else
				clu.dir = EOF_CLUSTER;
		} else {
			ret = exfat_get_next_cluster(sb, &clu.dir);
		}

		if (ret || clu.dir != EOF_CLUSTER) {
			/* just initialized hint_stat */
			hint_stat->clu = p_dir->dir;
			hint_stat->eidx = 0;
			return (dentry - num_ext);
		}
	}

	hint_stat->clu = clu.dir;
	hint_stat->eidx = dentry + 1;
	return (dentry - num_ext);
}

/* returns -EIO on error */
int exfat_count_ext_entries(struct super_block *sb, struct exfat_chain *p_dir,
		int entry, struct exfat_dentry *ep)
{
	int i, count = 0;
	unsigned int type;
	struct exfat_dentry *ext_ep;
	struct buffer_head *bh;

	for (i = 0, entry++; i < ep->file_num_ext; i++, entry++) {
		ext_ep = exfat_get_dentry(sb, p_dir, entry, &bh, NULL);
		if (!ext_ep)
			return -EIO;

		type = exfat_get_entry_type(ext_ep);
		brelse(bh);
		if ((type == TYPE_EXTEND) || (type == TYPE_STREAM))
			count++;
		else
			return count;
	}

	return count;
}

void exfat_get_uniname_from_ext_entry(struct super_block *sb,
		struct exfat_chain *p_dir, int entry, unsigned short *uniname)
{
	int i;
	struct exfat_dentry *ep;
	struct exfat_entry_set_cache *es;

	es = exfat_get_dentry_set(sb, p_dir, entry, ES_ALL_ENTRIES, &ep);
	if (!es)
		return;

	if (es->num_entries < 3)
		goto out;

	ep += 2;

	/*
	 * First entry  : file entry
	 * Second entry : stream-extension entry
	 * Third entry  : first file-name entry
	 * So, the index of first file-name dentry should start from 2.
	 */
	for (i = 2; i < es->num_entries; i++, ep++) {
		/* end of name entry */
		if (exfat_get_entry_type(ep) != TYPE_EXTEND)
			goto out;

		exfat_extract_uni_name(ep, uniname);
		uniname += 15;
	}

out:
	exfat_release_dentry_set(es);
}

int exfat_count_dir_entries(struct super_block *sb, struct exfat_chain *p_dir)
{
	int i, count = 0;
	int dentries_per_clu;
	unsigned int entry_type;
	struct exfat_chain clu;
	struct exfat_dentry *ep;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;

	dentries_per_clu = sbi->dentries_per_clu;

	clu.dir = p_dir->dir;
	clu.size = p_dir->size;
	clu.flags = p_dir->flags;

	while (clu.dir != EOF_CLUSTER) {
		for (i = 0; i < dentries_per_clu; i++) {
			ep = exfat_get_dentry(sb, &clu, i, &bh, NULL);
			if (!ep)
				return -EIO;

			entry_type = exfat_get_entry_type(ep);
			brelse(bh);

			if (entry_type == TYPE_UNUSED)
				return count;
			if (entry_type != TYPE_DIR)
				continue;
			count++;
		}

		if (clu.flags == 0x03) {
			if ((--clu.size) > 0)
				clu.dir++;
			else
				clu.dir = EOF_CLUSTER;
		} else {
			if (exfat_get_next_cluster(sb, &(clu.dir)))
				return -EIO;
		}
	}

	return count;
}

static inline void exfat_wait_bhs(struct buffer_head **bhs, int nr_bhs)
{
	int i;

	for (i = 0; i < nr_bhs; i++)
		write_dirty_buffer(bhs[i], WRITE);
}

static inline int exfat_sync_bhs(struct buffer_head **bhs, int nr_bhs)
{
	int i, err = 0;

	for (i = 0; i < nr_bhs; i++) {
		wait_on_buffer(bhs[i]);
		if (!err && !buffer_uptodate(bhs[i]))
			err = -EIO;
	}
	return err;
}

int exfat_zeroed_cluster(struct super_block *sb,
		sector_t blknr, unsigned int num_secs)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bhs[MAX_BUF_PER_PAGE];
	int nr_bhs = MAX_BUF_PER_PAGE;
	sector_t last_blknr = blknr + num_secs;
	int err, i, n;

	if (((blknr + num_secs) > sbi->num_sectors) && (sbi->num_sectors > 0)) {
		exfat_fs_error_ratelimit(sb,
			"%s: out of range(sect:%llu len:%u)",
			__func__, blknr, num_secs);
		return -EIO;
	}

	/* Zeroing the unused blocks on this cluster */
	n = 0;
	while (blknr < last_blknr) {
		bhs[n] = sb_getblk(sb, (sector_t)blknr);
		if (!bhs[n]) {
			err = -ENOMEM;
			goto error;
		}
		memset(bhs[n]->b_data, 0, sb->s_blocksize);
		exfat_update_bh(sb, bhs[n], 0);

		n++;
		blknr++;

		if (blknr == last_blknr)
			break;

		if (n == nr_bhs) {
			exfat_wait_bhs(bhs, n);

			for (i = 0; i < n; i++)
				brelse(bhs[i]);
			n = 0;
		}
	}
	exfat_wait_bhs(bhs, n);

	err = exfat_sync_bhs(bhs, n);
	if (err)
		goto error;

	for (i = 0; i < n; i++)
		brelse(bhs[i]);

	return 0;

error:
	exfat_msg(sb, KERN_ERR, "failed zeroed sect %llu\n", blknr);
	for (i = 0; i < n; i++)
		bforget(bhs[i]);

	return err;
}
