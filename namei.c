// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/iversion.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/buffer_head.h>
#include <linux/nls.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

static inline unsigned long exfat_d_version(struct dentry *dentry)
{
	return (unsigned long) dentry->d_fsdata;
}

static inline void exfat_d_version_set(struct dentry *dentry,
		unsigned long version)
{
	dentry->d_fsdata = (void *) version;
}

/*
 * If new entry was created in the parent, it could create the 8.3
 * alias (the shortname of logname).  So, the parent may have the
 * negative-dentry which matches the created 8.3 alias.
 *
 * If it happened, the negative dentry isn't actually negative
 * anymore.  So, drop it.
 */
static int __exfat_revalidate_common(struct dentry *dentry)
{
	int ret = 1;

	spin_lock(&dentry->d_lock);
	if (!inode_eq_iversion(d_inode(dentry->d_parent),
			exfat_d_version(dentry)))
		ret = 0;
	spin_unlock(&dentry->d_lock);
	return ret;
}

static int __exfat_revalidate(struct dentry *dentry)
{
	/* This is not negative dentry. Always valid. */
	if (d_really_is_positive(dentry))
		return 1;
	return __exfat_revalidate_common(dentry);
}

static int __exfat_revalidate_ci(struct dentry *dentry, unsigned int flags)
{
	/*
	 * This is not negative dentry. Always valid.
	 *
	 * Note, rename() to existing directory entry will have ->d_inode,
	 * and will use existing name which isn't specified name by user.
	 *
	 * We may be able to drop this positive dentry here. But dropping
	 * positive dentry isn't good idea. So it's unsupported like
	 * rename("filename", "FILENAME") for now.
	 */
	if (d_really_is_positive(dentry))
		return 1;
	/*
	 * Drop the negative dentry, in order to make sure to use the
	 * case sensitive name which is specified by user if this is
	 * for creation.
	 */
	if (flags & (LOOKUP_CREATE | LOOKUP_RENAME_TARGET))
		return 0;
	return __exfat_revalidate_common(dentry);
}


/* returns the length of a struct qstr, ignoring trailing dots */
static unsigned int __exfat_striptail_len(unsigned int len, const char *name)
{
	while (len && name[len - 1] == '.')
		len--;
	return len;
}

static unsigned int exfat_striptail_len(const struct qstr *qstr)
{
	return __exfat_striptail_len(qstr->len, qstr->name);
}

static inline unsigned int __exfat_full_name_hash(const struct dentry *dentry,
		const char *name, unsigned int len)
{
	return full_name_hash(dentry, name, len);
}

static inline unsigned long __exfat_init_name_hash(const struct dentry *dentry)
{
	return init_name_hash(dentry);
}

/*
 * Compute the hash for the exfat name corresponding to the dentry.
 * Note: if the name is invalid, we leave the hash code unchanged so
 * that the existing dentry can be used. The exfat fs routines will
 * return ENOENT or EINVAL as appropriate.
 */
static int exfat_d_hash(const struct dentry *dentry, struct qstr *qstr)
{
	unsigned int len = exfat_striptail_len(qstr);

	qstr->hash = __exfat_full_name_hash(dentry, qstr->name, len);
	return 0;
}

/*
 * Compute the hash for the exfat name corresponding to the dentry.
 * Note: if the name is invalid, we leave the hash code unchanged so
 * that the existing dentry can be used. The exfat fs routines will
 * return ENOENT or EINVAL as appropriate.
 */
static int exfat_d_hashi(const struct dentry *dentry, struct qstr *qstr)
{
	struct nls_table *t = EXFAT_SB(dentry->d_sb)->nls_io;
	const unsigned char *name;
	unsigned int len;
	unsigned long hash;

	name = qstr->name;
	len = exfat_striptail_len(qstr);

	hash = __exfat_init_name_hash(dentry);
	while (len--)
		hash = partial_name_hash(nls_tolower(t, *name++), hash);
	qstr->hash = end_name_hash(hash);

	return 0;
}

/*
 * Case sensitive compare of two exfat names.
 */
static int exfat_cmp(const struct dentry *dentry, unsigned int len,
		const char *str, const struct qstr *name)
{
	unsigned int alen, blen;

	/* A filename cannot end in '.' or we treat it like it has none */
	alen = exfat_striptail_len(name);
	blen = __exfat_striptail_len(len, str);
	if (alen == blen) {
		if (strncmp(name->name, str, alen) == 0)
			return 0;
	}
	return 1;
}

/*
 * Case insensitive compare of two exfat names.
 */
static int exfat_cmpi(const struct dentry *dentry, unsigned int len,
		const char *str, const struct qstr *name)
{
	struct nls_table *t = EXFAT_SB(dentry->d_sb)->nls_io;
	unsigned int alen, blen;

	/* A filename cannot end in '.' or we treat it like it has none */
	alen = exfat_striptail_len(name);
	blen = __exfat_striptail_len(len, str);
	if (alen == blen) {
		if (nls_strnicmp(t, name->name, str, alen) == 0)
			return 0;
	}
	return 1;
}

static int exfat_revalidate(struct dentry *dentry, unsigned int flags)
{
	if (flags & LOOKUP_RCU)
		return -ECHILD;

	return __exfat_revalidate(dentry);
}

static int exfat_revalidate_ci(struct dentry *dentry, unsigned int flags)
{
	if (flags & LOOKUP_RCU)
		return -ECHILD;

	return __exfat_revalidate_ci(dentry, flags);
}

const struct dentry_operations exfat_dentry_ops = {
	.d_revalidate	= exfat_revalidate,
	.d_hash		= exfat_d_hash,
	.d_compare	= exfat_cmp,
};

const struct dentry_operations exfat_ci_dentry_ops = {
	.d_revalidate	= exfat_revalidate_ci,
	.d_hash		= exfat_d_hashi,
	.d_compare	= exfat_cmpi,
};

/* used only in search empty_slot() */
#define CNT_UNUSED_NOHIT        (-1)
#define CNT_UNUSED_HIT          (-2)
/* search EMPTY CONTINUOUS "num_entries" entries */
static int exfat_search_empty_slot(struct super_block *sb,
		struct exfat_hint_femp *hint_femp, struct exfat_chain *p_dir,
		int num_entries)
{
	int i, dentry, num_empty = 0;
	int dentries_per_clu;
	unsigned int type;
	struct exfat_chain clu;
	struct exfat_dentry *ep;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;

	dentries_per_clu = sbi->dentries_per_clu;

	if (hint_femp->eidx != EXFAT_HINT_NONE) {
		clu.dir = hint_femp->cur.dir;
		clu.size = hint_femp->cur.size;
		clu.flags = hint_femp->cur.flags;

		dentry = hint_femp->eidx;

		if (num_entries <= hint_femp->count) {
			hint_femp->eidx = EXFAT_HINT_NONE;
			return dentry;
		}
	} else {
		clu.dir = p_dir->dir;
		clu.size = p_dir->size;
		clu.flags = p_dir->flags;

		dentry = 0;
	}

	while (!IS_CLUS_EOF(clu.dir)) {
		i = dentry & (dentries_per_clu - 1);

		for (; i < dentries_per_clu; i++, dentry++) {
			ep = exfat_get_dentry(sb, &clu, i, &bh, NULL);
			if (!ep)
				return -EIO;

			type = exfat_get_entry_type(ep);
			brelse(bh);

			if ((type == TYPE_UNUSED) || (type == TYPE_DELETED)) {
				num_empty++;
				if (hint_femp->eidx == EXFAT_HINT_NONE) {
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
				if ((hint_femp->eidx != EXFAT_HINT_NONE) &&
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
				hint_femp->eidx = EXFAT_HINT_NONE;
			}

			if (num_empty >= num_entries) {
				/* found and invalidate hint_femp */
				hint_femp->eidx = EXFAT_HINT_NONE;
				return (dentry - (num_entries - 1));
			}
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

	return -ENOSPC;
}

static int exfat_check_max_dentries(struct inode *inode)
{
	if ((i_size_read(inode) >> DENTRY_SIZE_BITS) >= MAX_EXFAT_DENTRIES) {
		/*
		 * exFAT spec allows a dir to grow upto 8388608(256MB)
		 * dentries
		 */
		return -ENOSPC;
	}
	return 0;
}

/* find empty directory entry.
 * if there isn't any empty slot, expand cluster chain.
 */
int exfat_find_empty_entry(struct inode *inode, struct exfat_chain *p_dir,
		int num_entries)
{
	int dentry;
	unsigned int ret, last_clu;
	unsigned long long sector;
	loff_t size = 0;
	struct exfat_chain clu;
	struct exfat_dentry *ep = NULL;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_hint_femp hint_femp;

	hint_femp.eidx = EXFAT_HINT_NONE;

	if (ei->hint_femp.eidx != EXFAT_HINT_NONE) {
		memcpy(&hint_femp, &ei->hint_femp,
				sizeof(struct exfat_hint_femp));
		ei->hint_femp.eidx = EXFAT_HINT_NONE;
	}

	while ((dentry = exfat_search_empty_slot(sb, &hint_femp, p_dir,
					num_entries)) < 0) {
		if (dentry == -EIO)
			break;

		if (exfat_check_max_dentries(inode))
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

		/* allocate a cluster */
		ret = exfat_alloc_cluster(sb, 1, &clu);
		if (ret)
			return ret;

		if (exfat_clear_cluster(inode, clu.dir))
			return -EIO;

		/* append to the FAT chain */
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

		if (hint_femp.eidx == EXFAT_HINT_NONE) {
			/* the special case that new dentry
			 * should be allocated from the start of new cluster
			 */
			hint_femp.eidx = p_dir->size <<
				(sbi->cluster_size_bits - DENTRY_SIZE_BITS);
			hint_femp.count = sbi->dentries_per_clu;

			hint_femp.cur.dir = clu.dir;
			hint_femp.cur.size = 0;
			hint_femp.cur.flags = clu.flags;
		}
		hint_femp.cur.size++;
		p_dir->size++;
		size = (p_dir->size << sbi->cluster_size_bits);

		/* update the directory entry */
		if (p_dir->dir != sbi->root_dir) {
			struct buffer_head *bh;

			ep = exfat_get_dentry(sb,
				&(ei->dir), ei->entry + 1, &bh, &sector);
			if (!ep)
				return -EIO;
			exfat_set_entry_size(ep, size);
			exfat_set_entry_flag(ep, p_dir->flags);
			exfat_update_bh(sb, bh, 0);
			brelse(bh);
			if (update_dir_chksum(sb, &(ei->dir), ei->entry))
				return -EIO;
		}

		/* directory inode should be updated in here */
		i_size_write(inode, size);
		EXFAT_I(inode)->i_size_ondisk += sbi->cluster_size;
		EXFAT_I(inode)->i_size_aligned += sbi->cluster_size;
		EXFAT_I(inode)->flags = p_dir->flags;
		inode->i_blocks += 1 << (sbi->cluster_size_bits -
				sb->s_blocksize_bits);
	}

	return dentry;
}

/*
 * Name Resolution Functions :
 * Zero if it was successful; otherwise nonzero.
 */
static int __exfat_resolve_path(struct inode *inode, const unsigned char *path,
		struct exfat_chain *p_dir, struct exfat_uni_name *p_uniname,
		int lookup)
{
	int namelen;
	int lossy = NLS_NAME_NO_LOSSY;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);

	/* DOT and DOTDOT are handled by VFS layer */

	/* strip all trailing spaces */
	/* DO NOTHING : Is needed? */

	/* strip all trailing periods */
	namelen = __exfat_striptail_len(strlen(path), path);
	if (!namelen)
		return -ENOENT;

	/* the limitation of linux? */
	if (strlen(path) > (MAX_NAME_LENGTH * MAX_CHARSET_SIZE))
		return -ENAMETOOLONG;

	/*
	 * strip all leading spaces :
	 * "MS windows 7" supports leading spaces.
	 * So we should skip this preprocessing for compatibility.
	 */

	/* file name conversion :
	 * If lookup case, we allow bad-name for compatibility.
	 */
	namelen = nls_vfsname_to_uni16s(sb, path, namelen, p_uniname, &lossy);
	if (namelen < 0)
		return namelen; /* return error value */

	if ((lossy && !lookup) || !namelen)
		return -EINVAL;

	p_dir->dir = ei->start_clu;
	p_dir->size = i_size_read(inode) >> sbi->cluster_size_bits;
	p_dir->flags = ei->flags;

	return 0;
}

static inline int exfat_resolve_path(struct inode *inode,
		const unsigned char *path, struct exfat_chain *dir,
		struct exfat_uni_name *uni)
{
	return __exfat_resolve_path(inode, path, dir, uni, 0);
}

static inline int exfat_resolve_path_for_lookup(struct inode *inode,
		const unsigned char *path, struct exfat_chain *dir,
		struct exfat_uni_name *uni)
{
	return __exfat_resolve_path(inode, path, dir, uni, 1);
}

static inline loff_t exfat_make_i_pos(struct exfat_dir_entry *info)
{
	return ((loff_t) info->dir.dir << 32) | (info->entry & 0xffffffff);
}

static int exfat_add_entry(struct inode *inode, const char *path,
		struct exfat_chain *p_dir, unsigned int type,
		unsigned char mode, struct exfat_dir_entry *info)
{
	int ret, dentry, num_entries;
	struct exfat_dos_name dos_name;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_uni_name uniname;
	struct exfat_chain clu;
	int clu_size = 0;
	unsigned int start_clu = CLUS_FREE;

	ret = exfat_resolve_path(inode, path, p_dir, &uniname);
	if (ret)
		goto out;

	ret = exfat_get_num_entries_and_dos_name(sb, p_dir, &uniname,
			&num_entries, &dos_name, 0);
	if (ret)
		goto out;

	/* exfat_find_empty_entry must be called before alloc_cluster() */
	dentry = exfat_find_empty_entry(inode, p_dir, num_entries);
	if (dentry < 0) {
		ret = dentry; /* -EIO or -ENOSPC */
		goto out;
	}

	if (type == TYPE_DIR) {
		ret = exfat_alloc_new_dir(inode, &clu);
		if (ret)
			goto out;
		clu_size = sbi->cluster_size;
		start_clu = clu.dir;
	}

	/* update the directory entry */
	/* fill the dos name directory entry information of the created file.
	 * the first cluster is not determined yet. (0)
	 */
	ret = exfat_init_dir_entry(sb, p_dir, dentry, type | mode,
		start_clu, clu_size);
	if (ret)
		goto out;

	ret = exfat_init_ext_entry(sb, p_dir, dentry, num_entries, &uniname,
		&dos_name);
	if (ret)
		goto out;

	memcpy(&info->dir, p_dir, sizeof(struct exfat_chain));
	info->entry = dentry;

	if (type == TYPE_FILE) {
		info->attr = ATTR_ARCHIVE | mode;
		info->start_clu = CLUS_EOF;
		info->size = 0;
	} else {
		info->attr = ATTR_SUBDIR | mode;
		info->start_clu = start_clu;
		info->size = clu_size;
	}
	info->flags = 0x03;
	info->type = type;
	memset(&info->create_timestamp, 0,
			sizeof(struct exfat_date_time));
	memset(&info->modify_timestamp, 0,
			sizeof(struct exfat_date_time));
	memset(&info->access_timestamp, 0,
			sizeof(struct exfat_date_time));

out:
	return ret;
}

static int exfat_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct exfat_chain cdir;
	struct exfat_dir_entry info;
	loff_t i_pos;
	int err;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	exfat_set_vol_flags(sb, VOL_DIRTY);
	err = exfat_add_entry(dir, dentry->d_name.name, &cdir, TYPE_FILE,
		FM_REGULAR, &info);
	exfat_set_vol_flags(sb, VOL_CLEAN);
	if (err)
		goto out;

	inode_inc_iversion(dir);
	dir->i_ctime = dir->i_mtime = dir->i_atime = current_time(dir);
	if (IS_DIRSYNC(dir))
		(void) exfat_sync_inode(dir);
	else
		mark_inode_dirty(dir);

	i_pos = exfat_make_i_pos(&info);
	inode = exfat_build_inode(sb, &info, i_pos);
	if (IS_ERR(inode))
		goto out;

	inode_inc_iversion(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	d_instantiate(dentry, inode);
out:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return err;
}

#define EXFAT_MIN_SUBDIR	(2)
/* lookup a file */
static int exfat_find(struct inode *dir, struct qstr *qname,
		struct exfat_dir_entry *info)
{
	int ret, dentry, num_entries;
	struct exfat_chain cdir;
	struct exfat_uni_name uni_name;
	struct exfat_dos_name dos_name;
	struct exfat_dentry *ep, *ep2;
	struct exfat_entry_set_cache *es = NULL;
	struct super_block *sb = dir->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(dir);
	struct exfat_timestamp tm;

	if (qname->len == 0)
		return -ENOENT;

	/* check the validity of directory name in the given pathname */
	ret = exfat_resolve_path_for_lookup(dir, qname->name, &cdir, &uni_name);
	if (ret)
		return ret;

	ret = exfat_get_num_entries_and_dos_name(sb, &cdir, &uni_name,
			&num_entries, &dos_name, 1);
	if (ret)
		return ret;

	/* check the validation of hint_stat and initialize it if required */
	if (ei->version != (inode_peek_iversion_raw(dir) & 0xffffffff)) {
		ei->hint_stat.clu = cdir.dir;
		ei->hint_stat.eidx = 0;
		ei->version = (inode_peek_iversion_raw(dir) & 0xffffffff);
		ei->hint_femp.eidx = EXFAT_HINT_NONE;
	}

	/* search the file name for directories */
	dentry = exfat_find_dir_entry(sb, ei, &cdir, &uni_name,
			num_entries, &dos_name, TYPE_ALL);

	if ((dentry < 0) && (dentry != -EEXIST))
		return dentry; /* -error value */

	memcpy(&info->dir, &cdir.dir, sizeof(struct exfat_chain));
	info->entry = dentry;

	/* root directory itself */
	if (unlikely(dentry == -EEXIST)) {
		info->type = TYPE_DIR;
		info->attr = ATTR_SUBDIR;
		info->flags = 0x01;
		info->size = 0;
		info->start_clu = sbi->root_dir;
		memset(&info->create_timestamp, 0,
				sizeof(struct exfat_date_time));
		memset(&info->modify_timestamp, 0,
				sizeof(struct exfat_date_time));
		memset(&info->access_timestamp, 0,
				sizeof(struct exfat_date_time));

		cdir.dir = sbi->root_dir;
		cdir.flags = 0x01;
		cdir.size = 0;
		info->num_subdirs = exfat_count_dos_name_entries(sb, &cdir,
			TYPE_DIR, NULL);
		if (info->num_subdirs < 0)
			return -EIO;
	} else {
		es = exfat_get_dentry_set(sb, &cdir, dentry, ES_2_ENTRIES, &ep);
		if (!es)
			return -EIO;
		ep2 = ep + 1;

		info->type = exfat_get_entry_type(ep);
		info->attr = exfat_get_entry_attr(ep);
		info->size = exfat_get_entry_size(ep2);
		if ((info->type == TYPE_FILE) && (info->size == 0)) {
			info->flags = 0x03;
			info->start_clu = CLUS_EOF;
		} else {
			info->flags = exfat_get_entry_flag(ep2);
			info->start_clu = exfat_get_entry_clu0(ep2);
		}

		if (IS_CLUS_FREE(ei->start_clu)) {
			exfat_fs_error(sb,
				"non-zero size file starts with zero cluster (size : %llu, p_dir : %u, entry : 0x%08x)",
				i_size_read(dir), ei->dir.dir, ei->entry);
			return -EIO;
		}

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

		memset(&info->access_timestamp, 0,
				sizeof(struct exfat_date_time));

		exfat_release_dentry_set(es);
		info->num_subdirs = 0;
		if (info->type == TYPE_DIR) {
			unsigned int dotcnt = 0;

			cdir.dir = info->start_clu;
			cdir.flags = info->flags;
			cdir.size = info->size >> sbi->cluster_size_bits;
			info->num_subdirs = exfat_count_dos_name_entries(sb,
				&cdir, TYPE_DIR, &dotcnt);
			if (info->num_subdirs < 0)
				return -EIO;

			info->num_subdirs += EXFAT_MIN_SUBDIR;
		}
	}

	return 0;
}

static int exfat_d_anon_disconn(struct dentry *dentry)
{
	return IS_ROOT(dentry) && (dentry->d_flags & DCACHE_DISCONNECTED);
}

/* read data from a opened file */
static int exfat_read_link(struct inode *inode, char *buffer)
{
	int ret = 0;
	int offset, sec_offset;
	unsigned int clu_offset;
	unsigned int clu;
	unsigned long long logsector, oneblkread, read_bytes;
	struct buffer_head *bh = NULL;
	struct super_block *sb = inode->i_sb;
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	loff_t size = i_size_read(inode);

	/* check if the given file ID is opened */
	if (ei->type != TYPE_FILE)
		return -EPERM;

	if (ei->rwoffset > size)
		ei->rwoffset = size;

	if (!size)
		return 0;

	read_bytes = 0;

	while (size > 0) {
		clu_offset = ei->rwoffset >> sbi->cluster_size_bits;
		clu = ei->start_clu;

		if (ei->flags == 0x03) {
			clu += clu_offset;
		} else {
			/* hint information */
			if ((clu_offset > 0) &&
				((ei->hint_bmap.off != CLUS_EOF) &&
				(ei->hint_bmap.off > 0)) &&
				(clu_offset >= ei->hint_bmap.off)) {
				clu_offset -= ei->hint_bmap.off;
				clu = ei->hint_bmap.clu;
			}

			while (clu_offset > 0) {
				ret = get_next_clus_safe(sb, &clu);
				if (ret)
					goto err_out;

				clu_offset--;
			}
		}

		/* hint information */
		ei->hint_bmap.off = ei->rwoffset >> sbi->cluster_size_bits;
		ei->hint_bmap.clu = clu;

		offset = ei->rwoffset & (sbi->cluster_size - 1);
		sec_offset = offset >> sb->s_blocksize_bits;
		offset &= (sb->s_blocksize - 1);

		logsector = clus_to_sect(sbi, clu) + sec_offset;

		oneblkread = sb->s_blocksize - offset;
		if (oneblkread > size)
			oneblkread = size;

		if ((offset == 0) && (oneblkread == sb->s_blocksize)) {
			bh = sb_bread(sb, logsector);
			if (!bh)
				goto err_out;
			memcpy(buffer + read_bytes, bh->b_data, oneblkread);
		} else {
			bh = sb_bread(sb, logsector);
			if (!bh)
				goto err_out;
			memcpy(buffer + read_bytes, bh->b_data + offset,
				oneblkread);
		}
		size -= oneblkread;
		read_bytes += oneblkread;
		ei->rwoffset += oneblkread;
	}

err_out:
	brelse(bh);
	return ret;
}

static struct dentry *exfat_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct dentry *alias;
	struct exfat_dir_entry info;
	int err;
	loff_t i_pos;
	mode_t i_mode;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	err = exfat_find(dir, &dentry->d_name, &info);
	if (err) {
		if (err == -ENOENT) {
			inode = NULL;
			goto out;
		}
		goto error;
	}

	i_pos = exfat_make_i_pos(&info);
	inode = exfat_build_inode(sb, &info, i_pos);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto error;
	}

	i_mode = inode->i_mode;
	if (S_ISLNK(i_mode) && !EXFAT_I(inode)->target) {
		EXFAT_I(inode)->target = kmalloc((i_size_read(inode) + 1),
			GFP_KERNEL);
		if (!EXFAT_I(inode)->target) {
			err = -ENOMEM;
			goto error;
		}
		exfat_read_link(inode, EXFAT_I(inode)->target);
		*(EXFAT_I(inode)->target + i_size_read(inode)) = '\0';
	}

	alias = d_find_alias(inode);

	/*
	 * Checking "alias->d_parent == dentry->d_parent" to make sure
	 * FS is not corrupted (especially double linked dir).
	 */
	if (alias && alias->d_parent == dentry->d_parent &&
			!exfat_d_anon_disconn(alias)) {

		/*
		 * Unhashed alias is able to exist because of revalidate()
		 * called by lookup_fast. You can easily make this status
		 * by calling create and lookup concurrently
		 * In such case, we reuse an alias instead of new dentry
		 */
		if (d_unhashed(alias)) {
			WARN_ON(alias->d_name.hash_len !=
				dentry->d_name.hash_len);
			exfat_msg(sb, KERN_INFO,
				"rehashed a dentry(%p) in read lookup", alias);
			d_drop(dentry);
			d_rehash(alias);
		} else if (!S_ISDIR(i_mode)) {
			/*
			 * This inode has non anonymous-DCACHE_DISCONNECTED
			 * dentry. This means, the user did ->lookup() by an
			 * another name (longname vs 8.3 alias of it) in past.
			 *
			 * Switch to new one for reason of locality if possible.
			 */
			d_move(alias, dentry);
		}
		iput(inode);
		mutex_unlock(&EXFAT_SB(sb)->s_lock);
		return alias;
	}
	dput(alias);
out:
	/* initialize d_time even though it is positive dentry */
	dentry->d_time = inode_peek_iversion_raw(dir);
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	if (!inode)
		exfat_d_version_set(dentry, inode_query_iversion(dir));

	return d_splice_alias(inode, dentry);
error:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return ERR_PTR(err);
}

/* remove an entry, BUT don't truncate */
static int exfat_unlink(struct inode *dir, struct dentry *dentry)
{
	struct exfat_chain cdir;
	struct exfat_dentry *ep;
	struct super_block *sb = dir->i_sb;
	struct inode *inode = dentry->d_inode;
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct buffer_head *bh;
	unsigned long long sector;
	int num_entries, entry, err = 0;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	cdir.dir = ei->dir.dir;
	cdir.size = ei->dir.size;
	cdir.flags = ei->dir.flags;
	entry = ei->entry;

	if (ei->dir.dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "abnormal access to deleted dentry");
		err = -ENOENT;
		goto out;
	}

	ep = exfat_get_dentry(sb, &cdir, entry, &bh, &sector);
	if (!ep)
		return -EIO;

	num_entries = exfat_count_ext_entries(sb, &cdir, entry, ep);
	if (num_entries < 0)
		return -EIO;
	num_entries++;
	brelse(bh);

	exfat_set_vol_flags(sb, VOL_DIRTY);
	/* update the directory entry */
	if (exfat_remove_entries(sb, &cdir, entry, 0, num_entries)) {
		err = -EIO;
		goto out;
	}

	/* This doesn't modify ei */
	ei->dir.dir = DIR_DELETED;
	exfat_set_vol_flags(sb, VOL_CLEAN);

	inode_inc_iversion(dir);
	dir->i_mtime = dir->i_atime = current_time(dir);
	if (IS_DIRSYNC(dir))
		(void) exfat_sync_inode(dir);
	else
		mark_inode_dirty(dir);

	clear_nlink(inode);
	inode->i_mtime = inode->i_atime = current_time(inode);
	exfat_detach(inode);
	dentry->d_time = inode_peek_iversion_raw(dir);
	exfat_d_version_set(dentry, inode_query_iversion(dir));
out:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);

	return err;
}

static int __exfat_remove(struct inode *inode, struct exfat_inode_info *ei)
{
	struct exfat_chain cdir, clu_to_free;
	struct exfat_dentry *ep;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;
	unsigned long long sector;
	int num_entries, entry, ret;

	cdir.dir = ei->dir.dir;
	cdir.size = ei->dir.size;
	cdir.flags = ei->dir.flags;

	entry = ei->entry;

	if (ei->dir.dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "abnormal access to deleted dentry");
		return -ENOENT;
	}

	ep = exfat_get_dentry(sb, &cdir, entry, &bh, &sector);
	if (!ep)
		return -EIO;

	num_entries = exfat_count_ext_entries(sb, &cdir, entry, ep);
	if (num_entries < 0)
		return -EIO;
	num_entries++;
	brelse(bh);

	exfat_set_vol_flags(sb, VOL_DIRTY);
	ret = exfat_remove_entries(sb, &cdir, entry, 0, num_entries);
	if (ret)
		goto out;

	clu_to_free.dir = ei->start_clu;
	clu_to_free.size =
		((i_size_read(inode) - 1) >> sbi->cluster_size_bits) + 1;
	clu_to_free.flags = ei->flags;

	/* invalidate exfat cache and free the clusters
	 */
	/* clear exfat cache */
	exfat_cache_inval_inode(inode);
	ret = exfat_free_cluster(sb, &clu_to_free);
	/* WARN : DO NOT RETURN ERROR IN HERE */

	/* update struct exfat_inode_info  */
	i_size_write(inode, 0);
	ei->start_clu = CLUS_EOF;
	ei->flags = 0x03;
	ei->dir.dir = DIR_DELETED;
	exfat_set_vol_flags(sb, VOL_CLEAN);
out:
	return ret;
}

/* write data into a opened file */
static int exfat_write_link(struct inode *inode, char *buffer,
		loff_t tsize)
{
	int ret = 0;
	int modified = false, offset, sec_offset;
	unsigned int clu_offset, num_clusters, num_alloc;
	unsigned int clu, last_clu;
	unsigned long long logsector, oneblkwrite, write_bytes;
	struct exfat_chain new_clu;
	struct exfat_timestamp tm;
	struct exfat_dentry *ep, *ep2;
	struct exfat_entry_set_cache *es = NULL;
	struct buffer_head *bh = NULL;
	struct super_block *sb = inode->i_sb;
	unsigned int blksize = sb->s_blocksize;
	unsigned int blksize_mask = sb->s_blocksize - 1;
	unsigned char blksize_bits = sb->s_blocksize_bits;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	loff_t size = i_size_read(inode);

	/* check if the given file ID is opened */
	if (ei->type != TYPE_FILE)
		return -EPERM;

	if (ei->rwoffset > size)
		ei->rwoffset = size;

	if (tsize == 0)
		return 0;

	exfat_set_vol_flags(sb, VOL_DIRTY);

	if (size == 0)
		num_clusters = 0;
	else
		num_clusters = ((size - 1) >> sbi->cluster_size_bits) + 1;

	write_bytes = 0;

	while (tsize > 0) {
		clu_offset = (ei->rwoffset >> sbi->cluster_size_bits);
		clu = last_clu = ei->start_clu;

		if (ei->flags == 0x03) {
			if ((clu_offset > 0) && (!IS_CLUS_EOF(clu))) {
				last_clu += clu_offset - 1;

				if (clu_offset == num_clusters)
					clu = CLUS_EOF;
				else
					clu += clu_offset;
			}
		} else {
			/* hint information */
			if ((clu_offset > 0) &&
				((ei->hint_bmap.off != CLUS_EOF) &&
				(ei->hint_bmap.off > 0)) &&
				(clu_offset >= ei->hint_bmap.off)) {
				clu_offset -= ei->hint_bmap.off;
				clu = ei->hint_bmap.clu;
			}

			while ((clu_offset > 0) && (!IS_CLUS_EOF(clu))) {
				last_clu = clu;
				ret = get_next_clus_safe(sb, &clu);
				if (ret)
					goto err_out;

				clu_offset--;
			}
		}

		if (IS_CLUS_EOF(clu)) {
			num_alloc = ((tsize - 1) >> sbi->cluster_size_bits) + 1;
			new_clu.dir =
				IS_CLUS_EOF(last_clu) ? CLUS_EOF : last_clu + 1;
			new_clu.size = 0;
			new_clu.flags = ei->flags;

			/* allocate a chain of clusters */
			ret = exfat_alloc_cluster(sb, num_alloc, &new_clu);
			if (ret)
				goto err_out;

			/* append to the FAT chain */
			if (IS_CLUS_EOF(last_clu)) {
				if (new_clu.flags == 0x01)
					ei->flags = 0x01;
				ei->start_clu = new_clu.dir;
				modified = true;
			} else {
				if (new_clu.flags != ei->flags) {
					/* no-fat-chain bit is disabled,
					 * so fat-chain should be synced with
					 * alloc-bmp
					 */
					exfat_chain_cont_cluster(sb,
						ei->start_clu, num_clusters);
					ei->flags = 0x01;
					modified = true;
				}
				if (new_clu.flags == 0x01) {
					ret = exfat_ent_set(sb, last_clu,
						new_clu.dir);
					if (ret)
						goto err_out;
				}
			}

			num_clusters += num_alloc;
			clu = new_clu.dir;
		}

		/* hint information */
		ei->hint_bmap.off = ei->rwoffset >> sbi->cluster_size_bits;
		ei->hint_bmap.clu = clu;

		/* byte offset in cluster   */
		offset = ei->rwoffset & (sbi->cluster_size - 1);
		/* sector offset in cluster */
		sec_offset = offset >> blksize_bits;
		/* byte offset in sector    */
		offset &= blksize_mask;
		logsector = clus_to_sect(sbi, clu) + sec_offset;

		oneblkwrite = blksize - offset;
		if (oneblkwrite > tsize)
			oneblkwrite = tsize;

		if ((offset == 0) && (oneblkwrite == blksize)) {
			bh = sb_getblk(sb, logsector);
			if (!bh)
				goto err_out;

			memcpy(bh->b_data, buffer + write_bytes, oneblkwrite);
		} else {
			if ((offset > 0) ||
				((ei->rwoffset+oneblkwrite) < size)) {
				bh = sb_bread(sb, logsector);
				if (bh)
					goto err_out;
			} else {
				bh = sb_getblk(sb, logsector);
				if (!bh)
					goto err_out;
			}

			memcpy(bh->b_data + offset, buffer + write_bytes,
				oneblkwrite);
		}
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);

		tsize -= oneblkwrite;
		write_bytes += oneblkwrite;
		ei->rwoffset += oneblkwrite;

		ei->attr |= ATTR_ARCHIVE;

		if (size < ei->rwoffset) {
			size = ei->rwoffset;
			modified = true;
		}
	}

	brelse(bh);

	/* update the direcoty entry */
	/* get_entry_(set_)in_dir shoulb be check DIR_DELETED flag. */
	es = exfat_get_dentry_set(sb, &(ei->dir), ei->entry, ES_ALL_ENTRIES,
			&ep);
	if (!es) {
		ret = -EIO;
		goto err_out;
	}
	ep2 = ep + 1;

	exfat_set_entry_time(ep, tm_now(EXFAT_SB(sb), &tm), TM_MODIFY);
	exfat_set_entry_attr(ep, ei->attr);

	if (modified) {
		if (exfat_get_entry_flag(ep2) != ei->flags)
			exfat_set_entry_flag(ep2, ei->flags);

		if (exfat_get_entry_size(ep2) != size)
			exfat_set_entry_size(ep2, size);

		if (exfat_get_entry_clu0(ep2) != ei->start_clu)
			exfat_set_entry_clu0(ep2, ei->start_clu);
	}

	if (exfat_update_dir_chksum_with_entry_set(sb, es)) {
		ret = -EIO;
		goto err_out;
	}
	exfat_release_dentry_set(es);

	exfat_set_vol_flags(sb, VOL_CLEAN);

err_out:
	return ret;
}

static int exfat_symlink(struct inode *dir, struct dentry *dentry,
		const char *target)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct exfat_dir_entry info;
	struct exfat_chain cdir;
	loff_t i_pos;
	int err;
	loff_t len = strlen(target);

	/* symlink option check */
	if (!EXFAT_SB(sb)->options.symlink)
		return -ENOTSUPP;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	exfat_set_vol_flags(sb, VOL_DIRTY);
	err = exfat_add_entry(dir, dentry->d_name.name, &cdir, TYPE_FILE,
		FM_SYMLINK, &info);
	exfat_set_vol_flags(sb, VOL_CLEAN);
	if (err)
		goto out;

	inode_inc_iversion(dir);
	dir->i_ctime = dir->i_mtime = dir->i_atime = current_time(dir);
	if (IS_DIRSYNC(dir))
		(void) exfat_sync_inode(dir);
	else
		mark_inode_dirty(dir);

	i_pos = exfat_make_i_pos(&info);
	inode = exfat_build_inode(sb, &info, i_pos);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	err = exfat_write_link(inode, (char *)target, len);
	if (err) {
		__exfat_remove(dir, EXFAT_I(inode));
		goto out;
	}

	inode_inc_iversion(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	EXFAT_I(inode)->target = kmalloc((len + 1), GFP_KERNEL);
	if (!EXFAT_I(inode)->target) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(EXFAT_I(inode)->target, target, len + 1);

	d_instantiate(dentry, inode);
out:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return err;
}

static int exfat_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct exfat_dir_entry info;
	struct exfat_chain cdir;
	loff_t i_pos;
	int err;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	exfat_set_vol_flags(sb, VOL_DIRTY);
	err = exfat_add_entry(dir, dentry->d_name.name, &cdir, TYPE_DIR,
		FM_REGULAR, &info);
	exfat_set_vol_flags(sb, VOL_CLEAN);
	if (err)
		goto out;

	inode_inc_iversion(dir);
	dir->i_ctime = dir->i_mtime = dir->i_atime = current_time(dir);
	if (IS_DIRSYNC(dir))
		(void) exfat_sync_inode(dir);
	else
		mark_inode_dirty(dir);
	inc_nlink(dir);

	i_pos = exfat_make_i_pos(&info);
	inode = exfat_build_inode(sb, &info, i_pos);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	inode_inc_iversion(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	d_instantiate(dentry, inode);

out:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return err;
}

int exfat_check_dir_empty(struct super_block *sb, struct exfat_chain *p_dir)
{
	int i;
	int dentries_per_clu;
	unsigned int type;
	struct exfat_chain clu;
	struct exfat_dentry *ep;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct buffer_head *bh;

	dentries_per_clu = sbi->dentries_per_clu;

	clu.dir = p_dir->dir;
	clu.size = p_dir->size;
	clu.flags = p_dir->flags;

	while (!IS_CLUS_EOF(clu.dir)) {
		for (i = 0; i < dentries_per_clu; i++) {
			ep = exfat_get_dentry(sb, &clu, i, &bh, NULL);
			if (!ep)
				return -EIO;

			type = exfat_get_entry_type(ep);
			brelse(bh);
			if (type == TYPE_UNUSED)
				return 0;

			if ((type != TYPE_FILE) && (type != TYPE_DIR))
				continue;

			return -ENOTEMPTY;
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

	return 0;
}

static int exfat_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct exfat_dentry *ep;
	struct exfat_chain cdir, clu_to_free;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	struct buffer_head *bh;
	unsigned long long sector;
	int num_entries, entry, err;

	mutex_lock(&EXFAT_SB(inode->i_sb)->s_lock);

	cdir.dir = ei->dir.dir;
	cdir.size = ei->dir.size;
	cdir.flags = ei->dir.flags;

	entry = ei->entry;

	if (ei->dir.dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "abnormal access to deleted dentry");
		return -ENOENT;
	}

	exfat_set_vol_flags(sb, VOL_DIRTY);
	clu_to_free.dir = ei->start_clu;
	clu_to_free.size =
		((i_size_read(inode) - 1) >> sbi->cluster_size_bits) + 1;
	clu_to_free.flags = ei->flags;

	err = exfat_check_dir_empty(sb, &clu_to_free);
	if (err) {
		if (err == -EIO)
			exfat_msg(sb, KERN_ERR,
				"failed to exfat_check_dir_empty : err(%d)",
				err);
		goto out;
	}

	ep = exfat_get_dentry(sb, &cdir, entry, &bh, &sector);
	if (!ep)
		return -EIO;

	num_entries = exfat_count_ext_entries(sb, &cdir, entry, ep);
	if (num_entries < 0)
		return -EIO;
	num_entries++;
	brelse(bh);

	err = exfat_remove_entries(sb, &cdir, entry, 0, num_entries);
	if (err) {
		exfat_msg(sb, KERN_ERR,
				"failed to exfat_remove_entries : err(%d)",
				err);
		goto out;
	}
	ei->dir.dir = DIR_DELETED;
	exfat_set_vol_flags(sb, VOL_CLEAN);

	inode_inc_iversion(dir);
	dir->i_mtime = dir->i_atime = current_time(dir);
	if (IS_DIRSYNC(dir))
		(void) exfat_sync_inode(dir);
	else
		mark_inode_dirty(dir);
	drop_nlink(dir);

	clear_nlink(inode);
	inode->i_mtime = inode->i_atime = current_time(inode);
	exfat_detach(inode);
	dentry->d_time = inode_peek_iversion_raw(dir);
	exfat_d_version_set(dentry, inode_query_iversion(dir));
out:
	mutex_unlock(&EXFAT_SB(inode->i_sb)->s_lock);
	return err;
}

static int exfat_rename_file(struct inode *inode, struct exfat_chain *p_dir,
		int oldentry, struct exfat_uni_name *p_uniname,
		struct exfat_inode_info *ei)
{
	int ret, num_old_entries, num_new_entries;
	unsigned long long sector_old, sector_new;
	struct exfat_dos_name dos_name;
	struct exfat_dentry *epold, *epnew;
	struct super_block *sb = inode->i_sb;
	struct buffer_head *new_bh, *old_bh;

	epold = exfat_get_dentry(sb, p_dir, oldentry, &old_bh, &sector_old);
	if (!epold)
		return -EIO;

	num_old_entries = exfat_count_ext_entries(sb, p_dir, oldentry, epold);
	if (num_old_entries < 0)
		return -EIO;
	num_old_entries++;

	ret = exfat_get_num_entries_and_dos_name(sb, p_dir, p_uniname,
		&num_new_entries, &dos_name, 0);
	if (ret)
		return ret;

	if (num_old_entries < num_new_entries) {
		int newentry;

		newentry =
			exfat_find_empty_entry(inode, p_dir, num_new_entries);
		if (newentry < 0)
			return newentry; /* -EIO or -ENOSPC */

		epnew = exfat_get_dentry(sb, p_dir, newentry, &new_bh,
			&sector_new);
		if (!epnew)
			return -EIO;

		memcpy((void *) epnew, (void *) epold, DENTRY_SIZE);
		if (exfat_get_entry_type(epnew) == TYPE_FILE) {
			exfat_set_entry_attr(epnew,
				exfat_get_entry_attr(epnew) | ATTR_ARCHIVE);
			ei->attr |= ATTR_ARCHIVE;
		}
		exfat_update_bh(sb, new_bh, 0);
		brelse(old_bh);
		brelse(new_bh);

		epold = exfat_get_dentry(sb, p_dir, oldentry + 1, &old_bh,
			&sector_old);
		epnew = exfat_get_dentry(sb, p_dir, newentry + 1, &new_bh,
			&sector_new);
		if (!epold || !epnew)
			return -EIO;

		memcpy((void *) epnew, (void *) epold, DENTRY_SIZE);
		exfat_update_bh(sb, new_bh, 0);
		brelse(old_bh);
		brelse(new_bh);

		ret = exfat_init_ext_entry(sb, p_dir, newentry, num_new_entries,
			p_uniname, &dos_name);
		if (ret)
			return ret;

		exfat_remove_entries(sb, p_dir, oldentry, 0, num_old_entries);
		ei->entry = newentry;
	} else {
		if (exfat_get_entry_type(epold) == TYPE_FILE) {
			exfat_set_entry_attr(epold,
				exfat_get_entry_attr(epold) | ATTR_ARCHIVE);
			ei->attr |= ATTR_ARCHIVE;
		}
		exfat_update_bh(sb, old_bh, 0);
		brelse(old_bh);
		ret = exfat_init_ext_entry(sb, p_dir, oldentry, num_new_entries,
			p_uniname, &dos_name);
		if (ret)
			return ret;

		exfat_remove_entries(sb, p_dir, oldentry, num_new_entries,
			num_old_entries);
	}

	return 0;
}

static int exfat_move_file(struct inode *inode, struct exfat_chain *p_olddir,
		int oldentry, struct exfat_chain *p_newdir,
		struct exfat_uni_name *p_uniname, struct exfat_inode_info *ei)
{
	int ret, newentry, num_new_entries, num_old_entries;
	unsigned long long sector_mov, sector_new;
	struct exfat_dos_name dos_name;
	struct exfat_dentry *epmov, *epnew;
	struct super_block *sb = inode->i_sb;
	struct buffer_head *mov_bh, *new_bh;

	epmov = exfat_get_dentry(sb, p_olddir, oldentry, &mov_bh, &sector_mov);
	if (!epmov)
		return -EIO;

	/* check if the source and target directory is the same */
	if (exfat_get_entry_type(epmov) == TYPE_DIR &&
			exfat_get_entry_clu0(epmov) == p_newdir->dir)
		return -EINVAL;

	num_old_entries = exfat_count_ext_entries(sb, p_olddir, oldentry,
		epmov);
	if (num_old_entries < 0)
		return -EIO;
	num_old_entries++;

	ret = exfat_get_num_entries_and_dos_name(sb, p_newdir, p_uniname,
		&num_new_entries, &dos_name, 0);
	if (ret)
		return ret;

	newentry = exfat_find_empty_entry(inode, p_newdir, num_new_entries);
	if (newentry < 0)
		return newentry; /* -EIO or -ENOSPC */

	epnew = exfat_get_dentry(sb, p_newdir, newentry, &new_bh, &sector_new);
	if (!epnew)
		return -EIO;

	memcpy((void *) epnew, (void *) epmov, DENTRY_SIZE);
	if (exfat_get_entry_type(epnew) == TYPE_FILE) {
		exfat_set_entry_attr(epnew,
			exfat_get_entry_attr(epnew) | ATTR_ARCHIVE);
		ei->attr |= ATTR_ARCHIVE;
	}
	exfat_update_bh(sb, new_bh, 0);
	brelse(mov_bh);
	brelse(new_bh);

	epmov = exfat_get_dentry(sb, p_olddir, oldentry + 1, &mov_bh,
		&sector_mov);
	epnew = exfat_get_dentry(sb, p_newdir, newentry + 1, &new_bh,
		&sector_new);
	if (!epmov || !epnew)
		return -EIO;

	memcpy((void *) epnew, (void *) epmov, DENTRY_SIZE);
	exfat_update_bh(sb, new_bh, 0);
	brelse(mov_bh);
	brelse(new_bh);

	ret = exfat_init_ext_entry(sb, p_newdir, newentry, num_new_entries,
		p_uniname, &dos_name);
	if (ret)
		return ret;

	exfat_remove_entries(sb, p_olddir, oldentry, 0, num_old_entries);

	ei->dir.dir = p_newdir->dir;
	ei->dir.size = p_newdir->size;
	ei->dir.flags = p_newdir->flags;

	ei->entry = newentry;

	return 0;
}

static void exfat_update_parent_info(struct exfat_inode_info *ei,
		struct inode *parent_inode)
{
	struct exfat_sb_info *sbi = EXFAT_SB(parent_inode->i_sb);
	struct exfat_inode_info *parent_ei = EXFAT_I(parent_inode);
	loff_t parent_isize = i_size_read(parent_inode);

	/*
	 * the problem that struct exfat_inode_info caches wrong parent info.
	 *
	 * because of flag-mismatch of ei->dir,
	 * there is abnormal traversing cluster chain.
	 */
	if (unlikely((parent_ei->flags != ei->dir.flags)
		|| (parent_isize != (ei->dir.size<<sbi->cluster_size_bits))
		|| (parent_ei->start_clu != ei->dir.dir))) {

		ei->dir.dir = parent_ei->start_clu;
		ei->dir.flags = parent_ei->flags;
		ei->dir.size = ((parent_isize + (sbi->cluster_size - 1))
				>> sbi->cluster_size_bits);
	}
}

/* rename or move a old file into a new file */
static int __exfat_rename(struct inode *old_parent_inode,
		struct exfat_inode_info *ei, struct inode *new_parent_inode,
		struct dentry *new_dentry)
{
	int ret;
	int dentry;
	struct exfat_chain olddir, newdir;
	struct exfat_chain *p_dir = NULL;
	struct exfat_uni_name uni_name;
	struct exfat_dentry *ep;
	struct super_block *sb = old_parent_inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	const unsigned char *new_path = new_dentry->d_name.name;
	struct inode *new_inode = new_dentry->d_inode;
	int num_entries;
	struct exfat_inode_info *new_ei = NULL;
	unsigned int new_entry_type = TYPE_UNUSED;
	int new_entry = 0;
	struct buffer_head *old_bh, *new_bh = NULL;

	/* check the validity of pointer parameters */
	if ((new_path == NULL) || (strlen(new_path) == 0))
		return -EINVAL;

	if (ei->dir.dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR,
				"abnormal access to deleted source dentry");
		return -ENOENT;
	}

	exfat_update_parent_info(ei, old_parent_inode);

	olddir.dir = ei->dir.dir;
	olddir.size = ei->dir.size;
	olddir.flags = ei->dir.flags;

	dentry = ei->entry;

	ep = exfat_get_dentry(sb, &olddir, dentry, &old_bh, NULL);
	if (!ep)
		return -EIO;
	brelse(old_bh);

	/* check whether new dir is existing directory and empty */
	if (new_inode) {
		ret = -EIO;
		new_ei = EXFAT_I(new_inode);

		if (new_ei->dir.dir == DIR_DELETED) {
			exfat_msg(sb, KERN_ERR,
				"abnormal access to deleted target dentry");
			goto out;
		}

		exfat_update_parent_info(new_ei, new_parent_inode);

		p_dir = &(new_ei->dir);
		new_entry = new_ei->entry;
		ep = exfat_get_dentry(sb, p_dir, new_entry, &new_bh, NULL);
		if (!ep)
			goto out;

		new_entry_type = exfat_get_entry_type(ep);
		brelse(new_bh);

		/* if new_inode exists, update ei */
		if (new_entry_type == TYPE_DIR) {
			struct exfat_chain new_clu;

			new_clu.dir = new_ei->start_clu;
			new_clu.size = ((i_size_read(new_inode) - 1) >>
					sbi->cluster_size_bits) + 1;
			new_clu.flags = new_ei->flags;

			ret = exfat_check_dir_empty(sb, &new_clu);
			if (ret)
				return ret;
		}
	}

	/* check the validity of directory name in the given new pathname */
	ret = exfat_resolve_path(new_parent_inode, new_path, &newdir,
			&uni_name);
	if (ret)
		return ret;

	exfat_set_vol_flags(sb, VOL_DIRTY);

	if (olddir.dir == newdir.dir)
		ret = exfat_rename_file(new_parent_inode, &olddir, dentry,
				&uni_name, ei);
	else
		ret = exfat_move_file(new_parent_inode, &olddir, dentry,
				&newdir, &uni_name, ei);

	if ((!ret) && new_inode) {
		/* delete entries of new_dir */
		ep = exfat_get_dentry(sb, p_dir, new_entry, &new_bh, NULL);
		if (!ep) {
			ret = -EIO;
			goto del_out;
		}

		num_entries = exfat_count_ext_entries(sb, p_dir, new_entry, ep);
		if (num_entries < 0) {
			ret = -EIO;
			goto del_out;
		}
		brelse(new_bh);

		if (exfat_remove_entries(sb, p_dir, new_entry, 0,
				num_entries + 1)) {
			ret = -EIO;
			goto del_out;
		}

		/* Free the clusters if new_inode is a dir(as if exfat_rmdir) */
		if (new_entry_type == TYPE_DIR) {
			/* new_ei, new_clu_to_free */
			struct exfat_chain new_clu_to_free;

			new_clu_to_free.dir = new_ei->start_clu;
			new_clu_to_free.size = ((i_size_read(new_inode) - 1) >>
					sbi->cluster_size_bits) + 1;
			new_clu_to_free.flags = new_ei->flags;

			if (exfat_free_cluster(sb, &new_clu_to_free)) {
				/* just set I/O error only */
				ret = -EIO;
			}

			i_size_write(new_inode, 0);
			new_ei->start_clu = CLUS_EOF;
			new_ei->flags = 0x03;
		}
del_out:
		/* Update new_inode ei
		 * Prevent syncing removed new_inode
		 * (new_ei is already initialized above code ("if (new_inode)")
		 */
		new_ei->dir.dir = DIR_DELETED;
	}
out:
	exfat_set_vol_flags(sb, VOL_CLEAN);
	return ret;
}

static int exfat_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry,
		unsigned int flags)
{
	struct inode *old_inode, *new_inode;
	struct super_block *sb = old_dir->i_sb;
	loff_t i_pos;
	int err;

	/*
	 * The VFS already checks for existence, so for local filesystems
	 * the RENAME_NOREPLACE implementation is equivalent to plain rename.
	 * Don't support any other flags
	 */
	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	old_inode = old_dentry->d_inode;
	new_inode = new_dentry->d_inode;

	err = __exfat_rename(old_dir, EXFAT_I(old_inode), new_dir,
		new_dentry);
	if (err)
		goto out;

	inode_inc_iversion(new_dir);
	new_dir->i_ctime = new_dir->i_mtime = new_dir->i_atime =
		current_time(new_dir);
	if (IS_DIRSYNC(new_dir))
		(void) exfat_sync_inode(new_dir);
	else
		mark_inode_dirty(new_dir);

	i_pos = ((loff_t)EXFAT_I(old_inode)->dir.dir << 32) |
		(EXFAT_I(old_inode)->entry & 0xffffffff);
	exfat_detach(old_inode);
	exfat_attach(old_inode, i_pos);
	if (IS_DIRSYNC(new_dir))
		(void) exfat_sync_inode(old_inode);
	else
		mark_inode_dirty(old_inode);

	if ((S_ISDIR(old_inode->i_mode)) && (old_dir != new_dir)) {
		drop_nlink(old_dir);
		if (!new_inode)
			inc_nlink(new_dir);
	}

	inode_inc_iversion(old_dir);
	old_dir->i_ctime = old_dir->i_mtime = current_time(old_dir);
	if (IS_DIRSYNC(old_dir))
		(void) exfat_sync_inode(old_dir);
	else
		mark_inode_dirty(old_dir);

	if (new_inode) {
		exfat_detach(new_inode);

		/* skip drop_nlink if new_inode already has been dropped */
		if (new_inode->i_nlink) {
			drop_nlink(new_inode);
			if (S_ISDIR(new_inode->i_mode))
				drop_nlink(new_inode);
		} else {
			exfat_msg(sb, KERN_WARNING,
					"abnormal access to an inode dropped");
			WARN_ON(new_inode->i_nlink == 0);
		}
		new_inode->i_ctime = current_time(new_inode);
	}

out:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return err;
}

static int exfat_cont_expand(struct inode *inode, loff_t size)
{
	struct address_space *mapping = inode->i_mapping;
	loff_t start = i_size_read(inode), count = size - i_size_read(inode);
	int err, err2;

	err = generic_cont_expand_simple(inode, size);
	if (err)
		return err;

	inode->i_ctime = inode->i_mtime = current_time(inode);
	mark_inode_dirty(inode);

	if (!IS_SYNC(inode))
		return 0;

	err = filemap_fdatawrite_range(mapping, start, start + count - 1);
	err2 = sync_mapping_buffers(mapping);
	err = (err)?(err):(err2);
	err2 = write_inode_now(inode, 1);
	err = (err)?(err):(err2);
	if (err)
		return err;

	return filemap_fdatawait_range(mapping, start, start + count - 1);
}

static int exfat_allow_set_time(struct exfat_sb_info *sbi, struct inode *inode)
{
	mode_t allow_utime = sbi->options.allow_utime;

	if (!uid_eq(current_fsuid(), inode->i_uid)) {
		if (in_group_p(inode->i_gid))
			allow_utime >>= 3;
		if (allow_utime & MAY_WRITE)
			return 1;
	}

	/* use a default check */
	return 0;
}

static int exfat_sanitize_mode(const struct exfat_sb_info *sbi,
		struct inode *inode, umode_t *mode_ptr)
{
	mode_t i_mode, mask, perm;

	i_mode = inode->i_mode;

	if (S_ISREG(i_mode) || S_ISLNK(i_mode))
		mask = sbi->options.fs_fmask;
	else
		mask = sbi->options.fs_dmask;

	perm = *mode_ptr & ~(S_IFMT | mask);

	/* Of the r and x bits, all (subject to umask) must be present.*/
	if ((perm & 0555) != (i_mode & 0555))
		return -EPERM;

	if (exfat_mode_can_hold_ro(inode)) {
		/*
		 * Of the w bits, either all (subject to umask) or none must
		 * be present.
		 */
		if ((perm & 0222) && ((perm & 0222) != (0222 & ~mask)))
			return -EPERM;
	} else {
		/*
		 * If exfat_mode_can_hold_ro(inode) is false, can't change
		 * w bits.
		 */
		if ((perm & 0222) != (0222 & ~mask))
			return -EPERM;
	}

	*mode_ptr &= S_IFMT | perm;

	return 0;
}

static int __exfat_getattr(struct inode *inode, struct kstat *stat)
{
	generic_fillattr(inode, stat);
	stat->blksize = EXFAT_SB(inode->i_sb)->cluster_size;
	return 0;
}

int exfat_getattr(const struct path *path, struct kstat *stat,
		unsigned int request_mask, unsigned int query_flags)
{
	struct inode *inode = d_backing_inode(path->dentry);

	return __exfat_getattr(inode, stat);
}

int exfat_setattr(struct dentry *dentry, struct iattr *attr)
{

	struct exfat_sb_info *sbi = EXFAT_SB(dentry->d_sb);
	struct inode *inode = dentry->d_inode;
	unsigned int ia_valid;
	int error;

	if ((attr->ia_valid & ATTR_SIZE)
			&& (attr->ia_size > i_size_read(inode))) {
		error = exfat_cont_expand(inode, attr->ia_size);
		if (error || attr->ia_valid == ATTR_SIZE)
			return error;
		attr->ia_valid &= ~ATTR_SIZE;
	}

	/* Check for setting the inode time. */
	ia_valid = attr->ia_valid;
	if ((ia_valid & (ATTR_MTIME_SET | ATTR_ATIME_SET | ATTR_TIMES_SET))
			&& exfat_allow_set_time(sbi, inode)) {
		attr->ia_valid &= ~(ATTR_MTIME_SET | ATTR_ATIME_SET |
				ATTR_TIMES_SET);
	}

	error = setattr_prepare(dentry, attr);
	attr->ia_valid = ia_valid;
	if (error)
		return error;

	if (((attr->ia_valid & ATTR_UID) &&
			(!uid_eq(attr->ia_uid, sbi->options.fs_uid))) ||
			((attr->ia_valid & ATTR_GID) &&
			 (!gid_eq(attr->ia_gid, sbi->options.fs_gid))) ||
			((attr->ia_valid & ATTR_MODE) &&
			 (attr->ia_mode & ~(S_IFREG | S_IFLNK | S_IFDIR |
				0777)))) {
		return -EPERM;
	}

	/*
	 * We don't return -EPERM here. Yes, strange, but this is too
	 * old behavior.
	 */
	if (attr->ia_valid & ATTR_MODE) {
		if (exfat_sanitize_mode(sbi, inode, &attr->ia_mode) < 0)
			attr->ia_valid &= ~ATTR_MODE;
	}

	if (attr->ia_valid & ATTR_SIZE) {
		down_write(&EXFAT_I(inode)->truncate_lock);
		truncate_setsize(inode, attr->ia_size);
		exfat_truncate(inode, attr->ia_size);
		up_write(&EXFAT_I(inode)->truncate_lock);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);

	return error;
}

const struct inode_operations exfat_dir_inode_operations = {
	.create		= exfat_create,
	.lookup		= exfat_lookup,
	.unlink		= exfat_unlink,
	.symlink	= exfat_symlink,
	.mkdir		= exfat_mkdir,
	.rmdir		= exfat_rmdir,
	.rename		= exfat_rename,
	.setattr	= exfat_setattr,
	.getattr	= exfat_getattr,
};
