// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/slab.h>
#include <asm/unaligned.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

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
	 * we cannot use exfat_get_dentry_set_in_dir here because file ep is not
	 * initialized yet.
	 */
	file_ep = (struct exfat_file_dentry *)exfat_get_dentry_in_dir(sb, p_dir, entry,
		&sector);
	if (!file_ep)
		return -EIO;

	strm_ep = (struct exfat_strm_dentry *)exfat_get_dentry_in_dir(sb, p_dir, entry+1,
		&sector);
	if (!strm_ep)
		return -EIO;

	exfat_init_file_entry(sb, file_ep, type);
	if (dcache_modify(sb, sector))
		return -EIO;

	exfat_init_strm_entry(strm_ep, flags, start_clu, size);
	if (dcache_modify(sb, sector))
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

	file_ep = (struct exfat_file_dentry *)exfat_get_dentry_in_dir(sb, p_dir, entry,
		&sector);
	if (!file_ep)
		return -EIO;

	dcache_lock(sb, sector);

	num_entries = (int) file_ep->num_ext + 1;
	chksum = calc_chksum_2byte((void *) file_ep, DENTRY_SIZE, 0,
		CS_DIR_ENTRY);

	for (i = 1; i < num_entries; i++) {
		ep = exfat_get_dentry_in_dir(sb, p_dir, entry+i, NULL);
		if (!ep)
			goto out_unlock;

		chksum = calc_chksum_2byte((void *) ep, DENTRY_SIZE, chksum,
			CS_DEFAULT);
	}

	file_ep->checksum = cpu_to_le16(chksum);
	ret = dcache_modify(sb, sector);
out_unlock:
	dcache_unlock(sb, sector);
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

	file_ep = (struct exfat_file_dentry *)exfat_get_dentry_in_dir(sb, p_dir, entry,
		&sector);
	if (!file_ep)
		return -EIO;

	file_ep->num_ext = (unsigned char)(num_entries - 1);
	dcache_modify(sb, sector);

	strm_ep = (struct exfat_strm_dentry *)exfat_get_dentry_in_dir(sb, p_dir, entry+1,
		&sector);
	if (!strm_ep)
		return -EIO;

	strm_ep->name_len = p_uniname->name_len;
	strm_ep->name_hash = cpu_to_le16(p_uniname->name_hash);
	dcache_modify(sb, sector);

	for (i = 2; i < num_entries; i++) {
		name_ep = (struct exfat_name_dentry *)exfat_get_dentry_in_dir(sb, p_dir, entry+i,
			&sector);
		if (!name_ep)
			return -EIO;

		exfat_init_name_entry(name_ep, uniname);
		dcache_modify(sb, sector);
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
		ep = exfat_get_dentry_in_dir(sb, p_dir, entry+i, &sector);
		if (!ep)
			return -EIO;

		exfat_set_entry_type(ep, TYPE_DELETED);
		if (dcache_modify(sb, sector))
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
		buf = dcache_getblk(sb, sec);
		if (!buf)
			goto err_out;
		memcpy(buf + off, esbuf + buf_off,
			copy_entries << DENTRY_SIZE_BITS);
		dcache_modify(sb, sec);
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

	/* FAT16 root_dir */
	if (IS_CLUS_FREE(p_dir->dir)) {
		*offset = off & blksize_mask;
		*sector = off >> blksize_bits;
		*sector += sbi->root_start_sector;
		return 0;
	}

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
struct exfat_entry_set_cache *exfat_get_dentry_set_in_dir(struct super_block *sb,
	struct exfat_chain *p_dir, int entry, unsigned int type, struct exfat_dentry **file_ep)
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
		WARN_ON(!sbi->prev_eio);
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

	buf = dcache_getblk(sb, sec);
	if (!buf)
		goto err_out;

	ep = (struct exfat_dentry *)(buf + off);
	entry_type = exfat_get_entry_type(ep);

	if ((entry_type != TYPE_FILE)
			&& (entry_type != TYPE_DIR))
		goto err_out;

	if (type == ES_ALL_ENTRIES)
		num_entries = ((struct exfat_file_dentry *)ep)->num_ext+1;
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

	pos = (struct exfat_dentry *) &(es->__buf);

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
			buf = dcache_getblk(sb, sec);
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

	/*
	 * REMARK:
	 * DOT and DOTDOT are handled by VFS layer
	 */

	if (IS_CLUS_FREE(p_dir->dir))
		return -EIO;

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

			ep = exfat_get_dentry_in_dir(sb, &clu, i, NULL);
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
		ext_ep = exfat_get_dentry_in_dir(sb, p_dir, entry, NULL);
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

	es = exfat_get_dentry_set_in_dir(sb, p_dir, entry, ES_ALL_ENTRIES, &ep);
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

int exfat_calc_num_entries(struct exfat_uni_name *p_uniname)
{
	int len;

	len = p_uniname->name_len;
	if (len == 0)
		return 0;

	/* 1 file entry + 1 stream entry + name entries */
	return((len-1) / 15 + 3);
}

static int exfat_check_max_dentries(struct exfat_file_id *fid)
{
	if ((fid->size >> DENTRY_SIZE_BITS) >= MAX_EXFAT_DENTRIES) {
		/*
		 * exFAT spec allows a dir to grow upto 8388608(256MB)
		 * dentries
		 */
		return -ENOSPC;
	}
	return 0;
}

int exfat_chain_cont_cluster(struct super_block *sb, unsigned int chain,
		unsigned int len)
{
	if (!len)
		return 0;

	while (len > 1) {
		if (exfat_ent_set(sb, chain, chain+1))
			return -EIO;
		chain++;
		len--;
	}

	if (exfat_ent_set(sb, chain, CLUS_EOF))
		return -EIO;
	return 0;
}

int exfat_free_cluster(struct super_block *sb, struct exfat_chain *p_chain, int do_relse)
{
	int ret = -EIO;
	unsigned int num_clusters = 0;
	unsigned int clu;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	int i;
	unsigned long long sector;

	/* invalid cluster number */
	if (IS_CLUS_FREE(p_chain->dir) || IS_CLUS_EOF(p_chain->dir))
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

	set_sb_dirty(sb);
	clu = p_chain->dir;

	if (p_chain->flags == 0x03) {
		do {
			if (do_relse) {
				sector = CLUS_TO_SECT(sbi, clu);
				for (i = 0; i < sbi->sect_per_clus; i++) {
					if (dcache_release(sb, sector+i) ==
							-EIO)
						goto out;
				}
			}

			exfat_clr_alloc_bitmap(sb, clu-2);
			clu++;

			num_clusters++;
		} while (num_clusters < p_chain->size);
	} else {
		do {
			if (do_relse) {
				sector = CLUS_TO_SECT(sbi, clu);
				for (i = 0; i < sbi->sect_per_clus; i++) {
					if (dcache_release(sb, sector+i) ==
							-EIO)
						goto out;
				}
			}

			exfat_clr_alloc_bitmap(sb, (clu - CLUS_BASE));

			if (get_next_clus_safe(sb, &clu))
				goto out;

			num_clusters++;
		} while (!IS_CLUS_EOF(clu));
	}

	/* success */
	ret = 0;
out:

	sbi->used_clusters -= num_clusters;
	return ret;
}

/* used only in search empty_slot() */
#define CNT_UNUSED_NOHIT        (-1)
#define CNT_UNUSED_HIT          (-2)
/* search EMPTY CONTINUOUS "num_entries" entries */
static int exfat_search_empty_slot(struct super_block *sb, struct exfat_hint_femp *hint_femp,
		struct exfat_chain *p_dir, int num_entries)
{
	int i, dentry, num_empty = 0;
	int dentries_per_clu;
	unsigned int type;
	struct exfat_chain clu;
	struct exfat_dentry *ep;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	if (IS_CLUS_FREE(p_dir->dir)) /* FAT16 root_dir */
		dentries_per_clu = sbi->dentries_in_root;
	else
		dentries_per_clu = sbi->dentries_per_clu;

	WARN_ON(-1 > hint_femp->eidx);

	if (hint_femp->eidx != -1) {
		clu.dir = hint_femp->cur.dir;
		clu.size = hint_femp->cur.size;
		clu.flags = hint_femp->cur.flags;

		dentry = hint_femp->eidx;

		if (num_entries <= hint_femp->count) {
			hint_femp->eidx = -1;
			return dentry;
		}
	} else {
		clu.dir = p_dir->dir;
		clu.size = p_dir->size;
		clu.flags = p_dir->flags;

		dentry = 0;
	}

	while (!IS_CLUS_EOF(clu.dir)) {
		/* FAT16 root_dir */
		if (IS_CLUS_FREE(p_dir->dir))
			i = dentry % dentries_per_clu;
		else
			i = dentry & (dentries_per_clu-1);

		for ( ; i < dentries_per_clu; i++, dentry++) {
			ep = exfat_get_dentry_in_dir(sb, &clu, i, NULL);
			if (!ep)
				return -EIO;

			type = exfat_get_entry_type(ep);

			if ((type == TYPE_UNUSED) || (type == TYPE_DELETED)) {
				num_empty++;
				if (hint_femp->eidx == -1) {
					hint_femp->eidx = dentry;
					hint_femp->count = CNT_UNUSED_NOHIT;

					hint_femp->cur.dir = clu.dir;
					hint_femp->cur.size = clu.size;
					hint_femp->cur.flags = clu.flags;
				}

				if ((type == TYPE_UNUSED) &&
					(hint_femp->count != CNT_UNUSED_HIT)) {
					hint_femp->count = CNT_UNUSED_HIT;
				}
			} else {
				if ((hint_femp->eidx != -1) &&
					(hint_femp->count == CNT_UNUSED_HIT)) {
					/* unused empty group means
					 * an empty group which includes
					 * unused dentry
					 */
					exfat_fs_error(sb,
						"found bogus dentry(%d) beyond unused empty group(%d) (start_clu : %u, cur_clu : %u)",
						dentry, hint_femp->eidx,
						p_dir->dir, clu.dir);
					return -EIO;
				}

				num_empty = 0;
				hint_femp->eidx = -1;
			}

			if (num_empty >= num_entries) {
				/* found and invalidate hint_femp */
				hint_femp->eidx = -1;
				return (dentry - (num_entries-1));
			}
		}

		if (IS_CLUS_FREE(p_dir->dir))
			break; /* FAT16 root_dir */

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

	return -ENOSPC;
}

static int exfat_find_last_cluster(struct super_block *sb, struct exfat_chain *p_chain,
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
		if (exfat_ent_get_safe(sb, clu, &next))
			return -EIO;
	} while (!IS_CLUS_EOF(next));

	if (p_chain->size != count) {
		exfat_fs_error(sb,
			"bogus directory size (clus : ondisk(%d) != counted(%d))",
			p_chain->size, count);
		return -EIO;
	}

	*ret_clu = clu;
	return 0;
}

/*
 *  Cluster Management Functions
 */
int exfat_clear_cluster(struct inode *inode, unsigned int clu)
{
	unsigned long long s, n;
	struct super_block *sb = inode->i_sb;
	unsigned int sect_size = (unsigned int)sb->s_blocksize;
	int ret = 0;
	struct buffer_head *tmp_bh = NULL;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	if (IS_CLUS_FREE(clu)) { /* FAT16 root_dir */
		s = sbi->root_start_sector;
		n = sbi->data_start_sector;
	} else {
		s = CLUS_TO_SECT(sbi, clu);
		n = s + sbi->sect_per_clus;
	}

	if (IS_DIRSYNC(inode)) {
		ret = write_msect_zero(sb, s,
			(unsigned long long)sbi->sect_per_clus);
		if (ret != -EAGAIN)
			return ret;
	}

	/* Trying buffered zero writes
	 * if it doesn't have DIRSYNC or write_msect_zero() returned -EAGAIN
	 */
	for ( ; s < n; s++) {
		tmp_bh = sb_getblk(sb, s);
		if (!tmp_bh)
			goto out;

		memset((unsigned char *)tmp_bh->b_data, 0x0, sect_size);
		set_buffer_uptodate(tmp_bh);
		mark_buffer_dirty(tmp_bh);
	}
out:
	brelse(tmp_bh);
	return ret;
}

/* find empty directory entry.
 * if there isn't any empty slot, expand cluster chain.
 */
int exfat_find_empty_entry(struct inode *inode, struct exfat_chain *p_dir, int num_entries)
{
	int dentry;
	unsigned int ret, last_clu;
	unsigned long long sector;
	unsigned long long size = 0;
	struct exfat_chain clu;
	struct exfat_dentry *ep = NULL;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);
	struct exfat_hint_femp hint_femp;

	hint_femp.eidx = -1;

	WARN_ON(-1 > fid->hint_femp.eidx);

	if (fid->hint_femp.eidx != -1) {
		memcpy(&hint_femp, &fid->hint_femp, sizeof(struct exfat_hint_femp));
		fid->hint_femp.eidx = -1;
	}

	/* FAT16 root_dir */
	if (IS_CLUS_FREE(p_dir->dir))
		return exfat_search_empty_slot(sb, &hint_femp, p_dir, num_entries);

	while ((dentry = exfat_search_empty_slot(sb, &hint_femp, p_dir,
			num_entries)) < 0) {
		if (dentry == -EIO)
			break;

		if (exfat_check_max_dentries(fid))
			return -ENOSPC;

		/* we trust p_dir->size regardless of FAT type */
		if (exfat_find_last_cluster(sb, p_dir, &last_clu))
			return -EIO;

		/*
		 * Allocate new cluster to this directory
		 */
		clu.dir = last_clu + 1;
		clu.size = 0; /* UNUSED */
		clu.flags = p_dir->flags;

		/* (0) check if there are reserved clusters.
		 * (reference comments of create_dir.
		 */
		if (!IS_CLUS_EOF(sbi->used_clusters) &&
			((sbi->used_clusters + sbi->reserved_clusters) >=
				(sbi->num_clusters - 2)))
			return -ENOSPC;

		/* (1) allocate a cluster */
		ret = exfat_alloc_cluster(sb, 1, &clu, ALLOC_HOT);
		if (ret)
			return ret;

		if (exfat_clear_cluster(inode, clu.dir))
			return -EIO;

		/* (2) append to the FAT chain */
		if (clu.flags != p_dir->flags) {
			/* no-fat-chain bit is disabled,
			 * so fat-chain should be synced with alloc-bmp
			 */
			exfat_chain_cont_cluster(sb, p_dir->dir, p_dir->size);
			p_dir->flags = 0x01;
			hint_femp.cur.flags = 0x01;
		}

		if (clu.flags == 0x01)
			if (exfat_ent_set(sb, last_clu, clu.dir))
				return -EIO;

		if (hint_femp.eidx == -1) {
			/* the special case that new dentry
			 * should be allocated from the start of new cluster
			 */
			hint_femp.eidx = (int)(p_dir->size <<
				(sbi->cluster_size_bits - DENTRY_SIZE_BITS));
			hint_femp.count = sbi->dentries_per_clu;

			hint_femp.cur.dir = clu.dir;
			hint_femp.cur.size = 0;
			hint_femp.cur.flags = clu.flags;
		}
		hint_femp.cur.size++;
		p_dir->size++;
		size = (p_dir->size << sbi->cluster_size_bits);

		/* (3) update the directory entry */
		if (p_dir->dir != sbi->root_dir) {
			ep = exfat_get_dentry_in_dir(sb,
					&(fid->dir), fid->entry + 1, &sector);
			if (!ep)
				return -EIO;
			exfat_set_entry_size(ep, size);
			exfat_set_entry_flag(ep, p_dir->flags);
			if (dcache_modify(sb, sector))
				return -EIO;

			if (update_dir_chksum(sb, &(fid->dir), fid->entry))
				return -EIO;
		}

		/* directory inode should be updated in here */
		i_size_write(inode, (loff_t)size);
		EXFAT_I(inode)->i_size_ondisk += sbi->cluster_size;
		EXFAT_I(inode)->i_size_aligned += sbi->cluster_size;
		EXFAT_I(inode)->fid.size = size;
		EXFAT_I(inode)->fid.flags = p_dir->flags;
		inode->i_blocks += 1 << (sbi->cluster_size_bits -
				sb->s_blocksize_bits);
	}

	return dentry;
}

int exfat_alloc_cluster(struct super_block *sb, unsigned int num_alloc,
		struct exfat_chain *p_chain, int dest)
{
	int ret = -ENOSPC;
	unsigned int num_clusters = 0, total_cnt;
	unsigned int hint_clu, new_clu, last_clu = CLUS_EOF;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	total_cnt = sbi->num_clusters - CLUS_BASE;

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
	if (IS_CLUS_EOF(hint_clu)) {
		if (sbi->clu_srch_ptr < CLUS_BASE) {
			exfat_msg(sb, KERN_ERR,
				"sbi->clu_srch_ptr is invalid (%u)\n",
				sbi->clu_srch_ptr);
			sbi->clu_srch_ptr = CLUS_BASE;
		}

		hint_clu = exfat_test_alloc_bitmap(sb, sbi->clu_srch_ptr - CLUS_BASE);
		if (IS_CLUS_EOF(hint_clu))
			return -ENOSPC;
	}

	/* check cluster validation */
	if ((hint_clu < CLUS_BASE) && (hint_clu >= sbi->num_clusters)) {
		exfat_msg(sb, KERN_ERR, "hint_cluster is invalid (%u)\n",
			hint_clu);
		hint_clu = CLUS_BASE;
		if (p_chain->flags == 0x03) {
			if (exfat_chain_cont_cluster(sb, p_chain->dir,
					num_clusters))
				return -EIO;
			p_chain->flags = 0x01;
		}
	}

	set_sb_dirty(sb);

	p_chain->dir = CLUS_EOF;

	while ((new_clu = exfat_test_alloc_bitmap(sb, hint_clu - CLUS_BASE)) !=
			CLUS_EOF) {
		if ((new_clu != hint_clu) && (p_chain->flags == 0x03)) {
			if (exfat_chain_cont_cluster(sb, p_chain->dir,
					num_clusters)) {
				ret = -EIO;
				goto error;
			}
			p_chain->flags = 0x01;
		}

		/* update allocation bitmap */
		if (exfat_set_alloc_bitmap(sb, new_clu - CLUS_BASE)) {
			ret = -EIO;
			goto error;
		}

		num_clusters++;

		/* update FAT table */
		if (p_chain->flags == 0x01) {
			if (exfat_ent_set(sb, new_clu, CLUS_EOF)) {
				ret = -EIO;
				goto error;
			}
		}

		if (IS_CLUS_EOF(p_chain->dir)) {
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
			hint_clu = CLUS_BASE;

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
		exfat_free_cluster(sb, p_chain, 0);
	return ret;
}

static int __exfat_ent_get(struct super_block *sb, unsigned int loc,
		unsigned int *content)
{
	unsigned int off, _content;
	unsigned long long sec;
	unsigned char *fat_sector;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	sec = sbi->FAT1_start_sector + (loc >> (sb->s_blocksize_bits-2));
	off = (loc << 2) & (unsigned int)(sb->s_blocksize - 1);

	fat_sector = fcache_getblk(sb, sec);
	if (!fat_sector)
		return -EIO;

	_content = le32_to_cpu(*(__le32 *)(&fat_sector[off]));

	/* remap reserved clusters to simplify code */
	if (_content >= CLUSTER_32(0xFFFFFFF8))
		_content = CLUS_EOF;

	*content = CLUSTER_32(_content);
	return 0;
}

int exfat_ent_set(struct super_block *sb, unsigned int loc,
		unsigned int content)
{
	unsigned int off;
	unsigned long long sec;
	unsigned char *fat_sector;
	__le32 *fat_entry;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	sec = sbi->FAT1_start_sector + (loc >> (sb->s_blocksize_bits-2));
	off = (loc << 2) & (unsigned int)(sb->s_blocksize - 1);

	fat_sector = fcache_getblk(sb, sec);
	if (!fat_sector)
		return -EIO;

	fat_entry = (__le32 *)&(fat_sector[off]);
	*fat_entry = cpu_to_le32(content);

	return fcache_modify(sb, sec);
}

static inline bool is_reserved_clus(unsigned int clus)
{
	if (IS_CLUS_FREE(clus))
		return true;
	if (IS_CLUS_EOF(clus))
		return true;
	if (IS_CLUS_BAD(clus))
		return true;
	return false;
}

static inline bool is_valid_clus(struct exfat_sb_info *sbi, unsigned int clus)
{
	if (clus < CLUS_BASE || sbi->num_clusters <= clus)
		return false;
	return true;
}

int exfat_ent_get(struct super_block *sb, unsigned int loc,
	unsigned int *content)
{
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	int err;

	if (!is_valid_clus(sbi, loc)) {
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

	if (!is_reserved_clus(*content) && !is_valid_clus(sbi, *content)) {
		exfat_fs_error(sb,
			"invalid access to FAT (entry 0x%08x) bogus content (0x%08x)",
			loc, *content);
		return -EIO;
	}

	return 0;
}

int exfat_ent_get_safe(struct super_block *sb, unsigned int loc,
		unsigned int *content)
{
	int err = exfat_ent_get(sb, loc, content);

	if (err)
		return err;

	if (IS_CLUS_FREE(*content)) {
		exfat_fs_error(sb,
			"invalid access to FAT free cluster (entry 0x%08x)",
			loc);
		return -EIO;
	}

	if (IS_CLUS_BAD(*content)) {
		exfat_fs_error(sb,
			"invalid access to FAT bad cluster (entry 0x%08x)",
			loc);
		return -EIO;
	}

	return 0;
}
