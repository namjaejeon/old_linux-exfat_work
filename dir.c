// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/slab.h>
#include <linux/bio.h>
#include <linux/buffer_head.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

static void exfat_get_uniname_from_dos_entry(struct super_block *sb, struct exfat_dos_dentry *ep,
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
static int exfat_readdir(struct inode *inode, struct exfat_dir_entry *dir_entry)
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
		if ((clu_offset > 0) && ((fid->hint_bmap.off != CLUS_EOF) &&
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

	while (!IS_CLUS_EOF(clu.dir)) {
		i = dentry & (dentries_per_clu-1);

		for ( ; i < dentries_per_clu; i++, dentry++) {
			ep = exfat_get_dentry(sb, &clu, i, &sector);
			if (!ep)
				return -EIO;

			type = exfat_get_entry_type(ep);

			if (type == TYPE_UNUSED)
				break;

			if ((type != TYPE_FILE) && (type != TYPE_DIR))
				continue;

			exfat_lock_dcache(sb, sector);
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

			memset((char *) &dir_entry->access_timestamp, 0,
				sizeof(struct exfat_date_time));

			*(uni_name.name) = 0x0;
			exfat_get_uniname_from_ext_entry(sb, &dir, dentry,
				uni_name.name);
			if (*(uni_name.name) == 0x0)
				exfat_get_uniname_from_dos_entry(sb,
					(struct exfat_dos_dentry *) ep, &uni_name, 0x1);
			nls_uni16s_to_vfsname(sb, &uni_name,
				dir_entry->namebuf.lfn,
				dir_entry->namebuf.lfnbuf_len);
			exfat_unlock_dcache(sb, sector);

			ep = exfat_get_dentry(sb, &clu, i+1, NULL);
			if (!ep)
				return -EIO;
			dir_entry->size = exfat_get_entry_size(ep);

			fid->hint_bmap.off = dentry >> dentries_per_clu_bits;
			fid->hint_bmap.clu = clu.dir;

			fid->rwoffset = (s64) ++dentry;
			return 0;
		}

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

/* skip iterating emit_dots when dir is empty */
#define ITER_POS_FILLED_DOTS    (2)
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

	err = exfat_readdir(inode, &de);
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

int exfat_create_dir(struct inode *inode, struct exfat_chain *p_dir,
		struct exfat_uni_name *p_uniname, struct exfat_file_id *fid)
{
	int dentry, num_entries;
	unsigned long long ret;
	unsigned long long size;
	struct exfat_chain clu;
	struct exfat_dos_name dos_name;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	ret = exfat_get_num_entries_and_dos_name(sb, p_dir, p_uniname, &num_entries,
			&dos_name, 0);
	if (ret)
		return ret;

	/* exfat_find_empty_entry must be called before alloc_cluster */
	dentry = exfat_find_empty_entry(inode, p_dir, num_entries);
	if (dentry < 0)
		return dentry; /* -EIO or -ENOSPC */

	clu.dir = CLUS_EOF;
	clu.size = 0;
	clu.flags = 0x03;

	/* (0) Check if there are reserved clusters up to max. */
	if ((sbi->used_clusters + sbi->reserved_clusters) >=
			(sbi->num_clusters - CLUS_BASE))
		return -ENOSPC;

	/* (1) allocate a cluster */
	ret = exfat_alloc_cluster(sb, 1, &clu, ALLOC_HOT);
	if (ret)
		return ret;

	ret = exfat_clear_cluster(inode, clu.dir);
	if (ret)
		return ret;

	size = sbi->cluster_size;

	/* (2) update the directory entry */
	/* make sub-dir entry in parent directory */
	ret = exfat_init_dir_entry(sb, p_dir, dentry, TYPE_DIR, clu.dir, size);
	if (ret)
		return ret;

	ret = exfat_init_ext_entry(sb, p_dir, dentry, num_entries, p_uniname,
			&dos_name);
	if (ret)
		return ret;

	fid->dir.dir = p_dir->dir;
	fid->dir.size = p_dir->size;
	fid->dir.flags = p_dir->flags;
	fid->entry = dentry;

	fid->attr = ATTR_SUBDIR;
	fid->flags = 0x03;
	fid->size = size;
	fid->start_clu = clu.dir;

	fid->type = TYPE_DIR;
	fid->rwoffset = 0;
	fid->hint_bmap.off = CLUS_EOF;

	/* hint_stat will be used if this is directory. */
	fid->version = 0;
	fid->hint_stat.eidx = 0;
	fid->hint_stat.clu = fid->start_clu;
	fid->hint_femp.eidx = -1;

	return 0;
}

static int exfat_calc_num_entries(struct exfat_uni_name *p_uniname)
{
	int len;

	len = p_uniname->name_len;
	if (len == 0)
		return 0;

	/* 1 file entry + 1 stream entry + name entries */
	return((len-1) / 15 + 3);
}

/* input  : dir, uni_name
 * output : num_of_entry, dos_name(format : aaaaaa~1.bbb)
 */
int exfat_get_num_entries_and_dos_name(struct super_block *sb, struct exfat_chain *p_dir,
                struct exfat_uni_name *p_uniname, int *entries,
                struct exfat_dos_name *p_dosname, int lookup)
{
        int num_entries;

        /* Init null char. */
        p_dosname->name[0] = '\0';

        num_entries = exfat_calc_num_entries(p_uniname);
        if (num_entries == 0)
                return -EINVAL;

        *entries = num_entries;
        return 0;
}


unsigned int exfat_get_entry_type(struct exfat_dentry *p_entry)
{
	struct exfat_file_dentry *ep = (struct exfat_file_dentry *) p_entry;

	if (ep->type == EXFAT_UNUSED)
		return TYPE_UNUSED;
	if (ep->type < 0x80)
		return TYPE_DELETED;
	if (ep->type == 0x80)
		return TYPE_INVALID;
	if (ep->type < 0xA0) {
		if (ep->type == 0x81)
			return TYPE_BITMAP;
		if (ep->type == 0x82)
			return TYPE_UPCASE;
		if (ep->type == 0x83)
			return TYPE_VOLUME;
		if (ep->type == 0x85) {
			if (le16_to_cpu(ep->attr) & ATTR_SUBDIR)
				return TYPE_DIR;
			return TYPE_FILE;
		}
		return TYPE_CRITICAL_PRI;
	}
	if (ep->type < 0xC0) {
		if (ep->type == 0xA0)
			return TYPE_GUID;
		if (ep->type == 0xA1)
			return TYPE_PADDING;
		if (ep->type == 0xA2)
			return TYPE_ACLTAB;
		return TYPE_BENIGN_PRI;
	}
	if (ep->type < 0xE0) {
		if (ep->type == 0xC0)
			return TYPE_STREAM;
		if (ep->type == 0xC1)
			return TYPE_EXTEND;
		if (ep->type == 0xC2)
			return TYPE_ACL;
		return TYPE_CRITICAL_SEC;
	}
	return TYPE_BENIGN_SEC;
}

static void exfat_set_entry_type(struct exfat_dentry *p_entry, unsigned int type)
{
	struct exfat_file_dentry *ep = (struct exfat_file_dentry *) p_entry;

	if (type == TYPE_UNUSED) {
		ep->type = 0x0;
	} else if (type == TYPE_DELETED) {
		ep->type &= ~0x80;
	} else if (type == TYPE_STREAM) {
		ep->type = 0xC0;
	} else if (type == TYPE_EXTEND) {
		ep->type = 0xC1;
	} else if (type == TYPE_BITMAP) {
		ep->type = 0x81;
	} else if (type == TYPE_UPCASE) {
		ep->type = 0x82;
	} else if (type == TYPE_VOLUME) {
		ep->type = 0x83;
	} else if (type == TYPE_DIR) {
		ep->type = 0x85;
		ep->attr = cpu_to_le16(ATTR_SUBDIR);
	} else if (type == TYPE_FILE) {
		ep->type = 0x85;
		ep->attr = cpu_to_le16(ATTR_ARCHIVE);
	} else if (type == TYPE_SYMLINK) {
		ep->type = 0x85;
		ep->attr = cpu_to_le16(ATTR_ARCHIVE | ATTR_SYMLINK);
	}
}

unsigned int exfat_get_entry_attr(struct exfat_dentry *p_entry)
{
	struct exfat_file_dentry *ep = (struct exfat_file_dentry *)p_entry;

	return (unsigned int)le16_to_cpu(ep->attr);
}

void exfat_set_entry_attr(struct exfat_dentry *p_entry, unsigned int attr)
{
	struct exfat_file_dentry *ep = (struct exfat_file_dentry *)p_entry;

	ep->attr = cpu_to_le16((unsigned short) attr);
}

unsigned char exfat_get_entry_flag(struct exfat_dentry *p_entry)
{
	struct exfat_strm_dentry *ep = (struct exfat_strm_dentry *)p_entry;

	return ep->flags;
}

void exfat_set_entry_flag(struct exfat_dentry *p_entry, unsigned char flags)
{
	struct exfat_strm_dentry *ep = (struct exfat_strm_dentry *)p_entry;

	ep->flags = flags;
}

unsigned int exfat_get_entry_clu0(struct exfat_dentry *p_entry)
{
	struct exfat_strm_dentry *ep = (struct exfat_strm_dentry *)p_entry;

	return (unsigned int)le32_to_cpu(ep->start_clu);
}

void exfat_set_entry_clu0(struct exfat_dentry *p_entry, unsigned int start_clu)
{
	struct exfat_strm_dentry *ep = (struct exfat_strm_dentry *)p_entry;

	ep->start_clu = cpu_to_le32(start_clu);
}

unsigned long long exfat_get_entry_size(struct exfat_dentry *p_entry)
{
	struct exfat_strm_dentry *ep = (struct exfat_strm_dentry *)p_entry;

	return le64_to_cpu(ep->valid_size);
}

void exfat_set_entry_size(struct exfat_dentry *p_entry, unsigned long long size)
{
	struct exfat_strm_dentry *ep = (struct exfat_strm_dentry *)p_entry;

	ep->valid_size = cpu_to_le64(size);
	ep->size = cpu_to_le64(size);
}

void exfat_get_entry_time(struct exfat_dentry *p_entry, struct exfat_timestamp *tp,
		unsigned char mode)
{
	unsigned short t = 0x00, d = 0x21;
	struct exfat_file_dentry *ep = (struct exfat_file_dentry *)p_entry;

	switch (mode) {
		case TM_CREATE:
			t = le16_to_cpu(ep->create_time);
			d = le16_to_cpu(ep->create_date);
			break;
		case TM_MODIFY:
			t = le16_to_cpu(ep->modify_time);
			d = le16_to_cpu(ep->modify_date);
			break;
		case TM_ACCESS:
			t = le16_to_cpu(ep->access_time);
			d = le16_to_cpu(ep->access_date);
			break;
	}

	tp->sec  = (t & 0x001F) << 1;
	tp->min  = (t >> 5) & 0x003F;
	tp->hour = (t >> 11);
	tp->day  = (d & 0x001F);
	tp->mon  = (d >> 5) & 0x000F;
	tp->year = (d >> 9);
}

void exfat_set_entry_time(struct exfat_dentry *p_entry, struct exfat_timestamp *tp,
		unsigned char mode)
{
	unsigned short t, d;
	struct exfat_file_dentry *ep = (struct exfat_file_dentry *)p_entry;

	t = (tp->hour << 11) | (tp->min << 5) | (tp->sec >> 1);
	d = (tp->year <<  9) | (tp->mon << 5) |  tp->day;

	switch (mode) {
		case TM_CREATE:
			ep->create_time = cpu_to_le16(t);
			ep->create_date = cpu_to_le16(d);
			break;
		case TM_MODIFY:
			ep->modify_time = cpu_to_le16(t);
			ep->modify_date = cpu_to_le16(d);
			break;
		case TM_ACCESS:
			ep->access_time = cpu_to_le16(t);
			ep->access_date = cpu_to_le16(d);
			break;
	}
}

static void exfat_init_file_entry(struct super_block *sb, struct exfat_file_dentry *ep,
		unsigned int type)
{
	struct exfat_timestamp tm, *tp;

	exfat_set_entry_type((struct exfat_dentry *) ep, type);

	tp = tm_now(EXFAT_SB(sb), &tm);
	exfat_set_entry_time((struct exfat_dentry *) ep, tp, TM_CREATE);
	exfat_set_entry_time((struct exfat_dentry *) ep, tp, TM_MODIFY);
	exfat_set_entry_time((struct exfat_dentry *) ep, tp, TM_ACCESS);
	ep->create_time_ms = 0;
	ep->modify_time_ms = 0;
	ep->access_time_ms = 0;
}

static void exfat_init_strm_entry(struct exfat_strm_dentry *ep, unsigned char flags,
		unsigned int start_clu, unsigned long long size)
{
	exfat_set_entry_type((struct exfat_dentry *) ep, TYPE_STREAM);
	ep->flags = flags;
	ep->start_clu = cpu_to_le32(start_clu);
	ep->valid_size = cpu_to_le64(size);
	ep->size = cpu_to_le64(size);
}

static void exfat_init_name_entry(struct exfat_name_dentry *ep, unsigned short *uniname)
{
	int i;

	exfat_set_entry_type((struct exfat_dentry *) ep, TYPE_EXTEND);
	ep->flags = 0x0;

	for (i = 0; i < 15; i++) {
		ep->unicode_0_14[i] = cpu_to_le16(*uniname);
		if (*uniname == 0x0)
			break;
		uniname++;
	}
}

int exfat_init_dir_entry(struct super_block *sb, struct exfat_chain *p_dir, int entry,
		unsigned int type, unsigned int start_clu, unsigned long long size)
{
	unsigned long long sector;
	unsigned char flags;
	struct exfat_file_dentry *file_ep;
	struct exfat_strm_dentry *strm_ep;

	flags = (type == TYPE_FILE) ? 0x01 : 0x03;

	/*
	 * we cannot use exfat_get_dentry_set here because file ep is not
	 * initialized yet.
	 */
	file_ep = (struct exfat_file_dentry *)exfat_get_dentry(sb, p_dir, entry,
			&sector);
	if (!file_ep)
		return -EIO;

	strm_ep = (struct exfat_strm_dentry *)exfat_get_dentry(sb, p_dir, entry+1,
			&sector);
	if (!strm_ep)
		return -EIO;

	exfat_init_file_entry(sb, file_ep, type);
	if (exfat_update_dcache(sb, sector))
		return -EIO;

	exfat_init_strm_entry(strm_ep, flags, start_clu, size);
	if (exfat_update_dcache(sb, sector))
		return -EIO;

	return 0;
}

int update_dir_chksum(struct super_block *sb, struct exfat_chain *p_dir, int entry)
{
	int ret = -EIO;
	int i, num_entries;
	unsigned long long sector;
	unsigned short chksum;
	struct exfat_file_dentry *file_ep;
	struct exfat_dentry *ep;

	file_ep = (struct exfat_file_dentry *)exfat_get_dentry(sb, p_dir, entry,
			&sector);
	if (!file_ep)
		return -EIO;

	exfat_lock_dcache(sb, sector);

	num_entries = (int) file_ep->num_ext + 1;
	chksum = calc_chksum_2byte((void *) file_ep, DENTRY_SIZE, 0,
			CS_DIR_ENTRY);

	for (i = 1; i < num_entries; i++) {
		ep = exfat_get_dentry(sb, p_dir, entry+i, NULL);
		if (!ep)
			goto out_unlock;

		chksum = calc_chksum_2byte((void *) ep, DENTRY_SIZE, chksum,
				CS_DEFAULT);
	}

	file_ep->checksum = cpu_to_le16(chksum);
	ret = exfat_update_dcache(sb, sector);
out_unlock:
	exfat_unlock_dcache(sb, sector);
	return ret;
}

int exfat_init_ext_entry(struct super_block *sb, struct exfat_chain *p_dir, int entry,
		int num_entries, struct exfat_uni_name *p_uniname, struct exfat_dos_name *p_dosname)
{
	int i;
	unsigned long long sector;
	unsigned short *uniname = p_uniname->name;
	struct exfat_file_dentry *file_ep;
	struct exfat_strm_dentry *strm_ep;
	struct exfat_name_dentry *name_ep;

	file_ep = (struct exfat_file_dentry *)exfat_get_dentry(sb, p_dir, entry,
			&sector);
	if (!file_ep)
		return -EIO;

	file_ep->num_ext = (unsigned char)(num_entries - 1);
	exfat_update_dcache(sb, sector);

	strm_ep = (struct exfat_strm_dentry *)exfat_get_dentry(sb, p_dir, entry+1,
			&sector);
	if (!strm_ep)
		return -EIO;

	strm_ep->name_len = p_uniname->name_len;
	strm_ep->name_hash = cpu_to_le16(p_uniname->name_hash);
	exfat_update_dcache(sb, sector);

	for (i = 2; i < num_entries; i++) {
		name_ep = (struct exfat_name_dentry *)exfat_get_dentry(sb, p_dir, entry+i,
				&sector);
		if (!name_ep)
			return -EIO;

		exfat_init_name_entry(name_ep, uniname);
		exfat_update_dcache(sb, sector);
		uniname += 15;
	}

	update_dir_chksum(sb, p_dir, entry);
	return 0;
}

int exfat_delete_dir_entry(struct super_block *sb, struct exfat_chain *p_dir, int entry,
		int order, int num_entries)
{
	int i;
	unsigned long long sector;
	struct exfat_dentry *ep;

	for (i = order; i < num_entries; i++) {
		ep = exfat_get_dentry(sb, p_dir, entry+i, &sector);
		if (!ep)
			return -EIO;

		exfat_set_entry_type(ep, TYPE_DELETED);
		if (exfat_update_dcache(sb, sector))
			return -EIO;
	}

	return 0;
}

/* write back all entries in entry set */
static int exfat_write_partial_entries_in_entry_set(struct super_block *sb,
		struct exfat_entry_set_cache *es, unsigned long long sec,
		unsigned int off, unsigned int count)
{
	int num_entries;
	unsigned int buf_off = (off - es->offset);
	unsigned int remaining_byte_in_sector, copy_entries;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int clu;
	unsigned char *buf, *esbuf = (unsigned char *)&(es->__buf);

	num_entries = count;

	while (num_entries) {
		/* write per sector base */
		remaining_byte_in_sector = (1 << sb->s_blocksize_bits) - off;
		copy_entries = min((int)(remaining_byte_in_sector >>
					DENTRY_SIZE_BITS), num_entries);
		buf = exfat_dcache_getblk(sb, sec);
		if (!buf)
			goto err_out;
		memcpy(buf + off, esbuf + buf_off,
				copy_entries << DENTRY_SIZE_BITS);
		exfat_update_dcache(sb, sec);
		num_entries -= copy_entries;

		if (num_entries) {
			// get next sector
			if (IS_LAST_SECT_IN_CLUS(sbi, sec)) {
				clu = SECT_TO_CLUS(sbi, sec);
				if (es->alloc_flag == 0x03)
					clu++;
				else if (get_next_clus_safe(sb, &clu))
					goto err_out;
				sec = CLUS_TO_SECT(sbi, clu);
			} else {
				sec++;
			}
			off = 0;
			buf_off += copy_entries << DENTRY_SIZE_BITS;
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
		chksum = calc_chksum_2byte((void *) ep, DENTRY_SIZE, chksum,
				chksum_type);
		ep++;
		chksum_type = CS_DEFAULT;
	}

	ep = (struct exfat_dentry *)&(es->__buf);
	((struct exfat_file_dentry *)ep)->checksum = cpu_to_le16(chksum);
	return exfat_write_partial_entries_in_entry_set(sb, es, es->sector,
			es->offset, es->num_entries);
}

static int exfat_walk_fat_chain(struct super_block *sb, struct exfat_chain *p_dir,
		unsigned int byte_offset, unsigned int *clu)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned int clu_offset;
	unsigned int cur_clu;

	clu_offset = byte_offset >> sbi->cluster_size_bits;
	cur_clu = p_dir->dir;

	if (p_dir->flags == 0x03) {
		cur_clu += clu_offset;
	} else {
		while (clu_offset > 0) {
			if (get_next_clus_safe(sb, &cur_clu))
				return -EIO;
			if (IS_CLUS_EOF(cur_clu)) {
				exfat_fs_error(sb,
						"invalid dentry access beyond EOF (clu : %u, eidx : %d)",
						p_dir->dir,
						byte_offset >> DENTRY_SIZE_BITS);
				return -EIO;
			}
			clu_offset--;
		}
	}

	if (clu)
		*clu = cur_clu;
	return 0;
}

int exfat_find_location(struct super_block *sb, struct exfat_chain *p_dir, int entry,
		unsigned long long *sector, int *offset)
{
	int ret;
	unsigned int off, clu = 0;
	unsigned int blksize_mask = (unsigned int)(sb->s_blocksize - 1);
	unsigned char blksize_bits = sb->s_blocksize_bits;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	off = entry << DENTRY_SIZE_BITS;

	ret = exfat_walk_fat_chain(sb, p_dir, off, &clu);
	if (ret)
		return ret;

	/* byte offset in cluster */
	off &= (sbi->cluster_size - 1);

	/* byte offset in sector    */
	*offset = off & blksize_mask;

	/* sector offset in cluster */
	*sector = off >> blksize_bits;
	*sector += CLUS_TO_SECT(sbi, clu);
	return 0;
}

struct exfat_dentry *exfat_get_dentry(struct super_block *sb,
	struct exfat_chain *p_dir, int entry, unsigned long long *sector)
{
	unsigned int dentries_per_page = PAGE_SIZE >> DENTRY_SIZE_BITS;
	int off;
	unsigned long long sec;
	unsigned char *buf;

	if (p_dir->dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "abnormal access to deleted dentry\n");
		return NULL;
	}

	if (exfat_find_location(sb, p_dir, entry, &sec, &off))
		return NULL;

	/* DIRECTORY READAHEAD :
	 * Try to read ahead per a page except root directory of fat12/16
	 */
	if ((!IS_CLUS_FREE(p_dir->dir)) &&
			!(entry & (dentries_per_page - 1)))
		exfat_dcache_readahead(sb, sec);

	buf = exfat_dcache_getblk(sb, sec);
	if (!buf)
		return NULL;

	if (sector)
		*sector = sec;
	return (struct exfat_dentry *)(buf + off);
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
	unsigned long long sec;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_entry_set_cache *es = NULL;
	struct exfat_dentry *ep, *pos;
	unsigned char *buf;
	unsigned char num_entries;
	int mode = ES_MODE_STARTED;

	/* FIXME : is available in error case? */
	if (p_dir->dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "access to deleted dentry\n");
		return NULL;
	}

	byte_offset = entry << DENTRY_SIZE_BITS;
	ret = exfat_walk_fat_chain(sb, p_dir, byte_offset, &clu);
	if (ret)
		return NULL;

	/* byte offset in cluster */
	byte_offset &= sbi->cluster_size - 1;

	/* byte offset in sector */
	off = byte_offset & (unsigned int)(sb->s_blocksize - 1);

	/* sector offset in cluster */
	sec = byte_offset >> (sb->s_blocksize_bits);
	sec += CLUS_TO_SECT(sbi, clu);

	buf = exfat_dcache_getblk(sb, sec);
	if (!buf)
		goto err_out;

	ep = (struct exfat_dentry *)(buf + off);
	entry_type = exfat_get_entry_type(ep);

	if ((entry_type != TYPE_FILE)
			&& (entry_type != TYPE_DIR))
		goto err_out;

	if (type == ES_ALL_ENTRIES)
		num_entries = ((struct exfat_file_dentry *)ep)->num_ext + 1;
	else
		num_entries = type;

	es = kmalloc((offsetof(struct exfat_entry_set_cache, __buf) + (num_entries) *
				sizeof(struct exfat_dentry)), GFP_KERNEL);
	if (!es)
		goto err_out;

	es->num_entries = num_entries;
	es->sector = sec;
	es->offset = off;
	es->alloc_flag = p_dir->flags;

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
			(unsigned int)(sb->s_blocksize - 1)) <
			(off & (unsigned int)(sb->s_blocksize - 1))) {
			// get the next sector
			if (IS_LAST_SECT_IN_CLUS(sbi, sec)) {
				if (es->alloc_flag == 0x03)
					clu++;
				else if (get_next_clus_safe(sb, &clu))
					goto err_out;
				sec = CLUS_TO_SECT(sbi, clu);
			} else {
				sec++;
			}
			buf = exfat_dcache_getblk(sb, sec);
			if (!buf)
				goto err_out;
			off = 0;
			ep = (struct exfat_dentry *)(buf);
		} else {
			ep++;
			off += DENTRY_SIZE;
		}
		pos++;
	}

	if (file_ep)
		*file_ep = (struct exfat_dentry *)&(es->__buf);

	return es;
err_out:
	kfree(es);
	es = NULL;
	return NULL;
}

void exfat_release_dentry_set(struct exfat_entry_set_cache *es)
{
	kfree(es);
	es = NULL;
}

static int exfat_extract_uni_name_from_name_entry(struct exfat_name_dentry *ep,
		unsigned short *uniname, int order)
{
	int i, len = 0;

	for (i = 0; i < 15; i++) {
		*uniname = le16_to_cpu(ep->unicode_0_14[i]);
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
int exfat_find_dir_entry(struct super_block *sb, struct exfat_file_id *fid,
		struct exfat_chain *p_dir, struct exfat_uni_name *p_uniname, int num_entries,
		struct exfat_dos_name *unused, unsigned int type)
{
	int i, rewind = 0, dentry = 0, end_eidx = 0, num_ext = 0, len;
	int order, step, name_len;
	int dentries_per_clu, num_empty = 0;
	unsigned int entry_type;
	unsigned short entry_uniname[16], *uniname = NULL, unichar;
	struct exfat_chain clu;
	struct exfat_dentry *ep;
	struct exfat_hint *hint_stat = &fid->hint_stat;
	struct exfat_hint_femp candi_empty;
	struct exfat_file_dentry *file_ep;
	struct exfat_strm_dentry *strm_ep;
	struct exfat_name_dentry *name_ep;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	dentries_per_clu = sbi->dentries_per_clu;

	clu.dir = p_dir->dir;
	clu.size = p_dir->size;
	clu.flags = p_dir->flags;

	if (hint_stat->eidx) {
		clu.dir = hint_stat->clu;
		dentry = hint_stat->eidx;
		end_eidx = dentry;
	}

	candi_empty.eidx = -1;
rewind:
	order = 0;
	step = DIRENT_STEP_FILE;
	while (!IS_CLUS_EOF(clu.dir)) {
		i = dentry & (dentries_per_clu - 1);
		for (; i < dentries_per_clu; i++, dentry++) {
			if (rewind && (dentry == end_eidx))
				goto not_found;

			ep = exfat_get_dentry(sb, &clu, i, NULL);
			if (!ep)
				return -EIO;

			entry_type = exfat_get_entry_type(ep);

			if ((entry_type == TYPE_UNUSED) ||
					(entry_type == TYPE_DELETED)) {
				step = DIRENT_STEP_FILE;

				num_empty++;
				if (candi_empty.eidx == -1) {
					if (num_empty == 1) {
						candi_empty.cur.dir = clu.dir;
						candi_empty.cur.size = clu.size;
						candi_empty.cur.flags =
							clu.flags;
					}

					if (num_empty >= num_entries) {
						candi_empty.eidx = dentry -
							(num_empty - 1);
						WARN_ON(candi_empty.eidx < 0);
						candi_empty.count = num_empty;

						if (fid->hint_femp.eidx == -1 ||
								(candi_empty.eidx <=
								 fid->hint_femp.eidx)) {
							memcpy(&fid->hint_femp,
									&candi_empty,
									sizeof(struct exfat_hint_femp));
						}
					}
				}

				if (entry_type == TYPE_UNUSED)
					goto not_found;
				continue;
			}

			num_empty = 0;
			candi_empty.eidx = -1;

			if ((entry_type == TYPE_FILE) ||
					(entry_type == TYPE_DIR)) {
				step = DIRENT_STEP_FILE;
				if ((type == TYPE_ALL) ||
						(type == entry_type)) {
					file_ep = (struct exfat_file_dentry *) ep;
					num_ext = file_ep->num_ext;
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
				strm_ep = (struct exfat_strm_dentry *) ep;
				if ((p_uniname->name_hash ==
							le16_to_cpu(strm_ep->name_hash)) &&
						(p_uniname->name_len ==
						 strm_ep->name_len)) {
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
				name_ep = (struct exfat_name_dentry *) ep;

				if ((++order) == 2)
					uniname = p_uniname->name;
				else
					uniname += 15;

				len = exfat_extract_uni_name_from_name_entry(
						name_ep, entry_uniname, order);
				name_len += len;

				unichar = *(uniname+len);
				*(uniname+len) = 0x0;

				if (nls_cmp_uniname(sb, uniname,
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
				clu.dir = CLUS_EOF;
		} else {
			if (get_next_clus_safe(sb, &clu.dir))
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
		candi_empty.eidx = -1;
		goto rewind;
	}

	/* initialized hint_stat */
	hint_stat->clu = p_dir->dir;
	hint_stat->eidx = 0;
	return -ENOENT;

found:
	/* next dentry we'll find is out of this cluster */
	if (!((dentry + 1) & (dentries_per_clu-1))) {
		int ret = 0;

		if (clu.flags == 0x03) {
			if ((--clu.size) > 0)
				clu.dir++;
			else
				clu.dir = CLUS_EOF;
		} else {
			ret = get_next_clus_safe(sb, &clu.dir);
		}

		if (ret || IS_CLUS_EOF(clu.dir)) {
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
int exfat_count_ext_entries(struct super_block *sb, struct exfat_chain *p_dir, int entry,
		struct exfat_dentry *p_entry)
{
	int i, count = 0;
	unsigned int type;
	struct exfat_file_dentry *file_ep = (struct exfat_file_dentry *) p_entry;
	struct exfat_dentry *ext_ep;

	for (i = 0, entry++; i < file_ep->num_ext; i++, entry++) {
		ext_ep = exfat_get_dentry(sb, p_dir, entry, NULL);
		if (!ext_ep)
			return -EIO;

		type = exfat_get_entry_type(ext_ep);
		if ((type == TYPE_EXTEND) || (type == TYPE_STREAM))
			count++;
		else
			return count;
	}

	return count;
}

/*
 *  Name Conversion Functions
 */
void exfat_get_uniname_from_ext_entry(struct super_block *sb, struct exfat_chain *p_dir,
		int entry, unsigned short *uniname)
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

		exfat_extract_uni_name_from_name_entry((struct exfat_name_dentry *)ep,
				uniname, i);
		uniname += 15;
	}

out:
	exfat_release_dentry_set(es);
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
		unsigned long long blknr, unsigned long long num_secs)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bhs[MAX_BUF_PER_PAGE];
	int nr_bhs = MAX_BUF_PER_PAGE;
	unsigned long long last_blknr = blknr + num_secs;
	int err, i, n;

	if (((blknr + num_secs) > sbi->num_sectors) && (sbi->num_sectors > 0)) {
		exfat_fs_error_ratelimit(sb, "%s: out of range(sect:%llu len:%llu)",
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
		set_buffer_uptodate(bhs[n]);
		mark_buffer_dirty(bhs[n]);

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
