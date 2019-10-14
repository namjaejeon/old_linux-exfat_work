// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 */

#include <linux/iversion.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/cred.h>

#include "exfat_raw.h"
#include "exfat_fs.h"

#define EXFAT_DSTATE_LOCKED     (void *)(0xCAFE2016)
#define EXFAT_DSTATE_UNLOCKED   (void *)(0x00000000)

static inline void __lock_d_revalidate(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	dentry->d_fsdata = EXFAT_DSTATE_LOCKED;
	spin_unlock(&dentry->d_lock);
}

static inline void __unlock_d_revalidate(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	dentry->d_fsdata = EXFAT_DSTATE_UNLOCKED;
	spin_unlock(&dentry->d_lock);
}

/* __check_dstate_locked requires dentry->d_lock */
static inline int __check_dstate_locked(struct dentry *dentry)
{
	if (dentry->d_fsdata == EXFAT_DSTATE_LOCKED)
		return 1;

	return 0;
}

static inline unsigned long exfat_d_version(struct dentry *dentry)
{
	return (unsigned long) dentry->d_fsdata;
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
	if ((!dentry->d_inode) && (!__check_dstate_locked(dentry) &&
		(!inode_eq_iversion(d_inode(dentry->d_parent),
			exfat_d_version(dentry)))))
		ret = 0;
	spin_unlock(&dentry->d_lock);
	return ret;
}

static int __exfat_revalidate(struct dentry *dentry)
{
	/* This is not negative dentry. Always valid. */
	if (dentry->d_inode)
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
	if (dentry->d_inode)
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
static int __exfat_d_hash(const struct dentry *dentry, struct qstr *qstr)
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
static int __exfat_d_hashi(const struct dentry *dentry, struct qstr *qstr)
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

static int exfat_d_hash(const struct dentry *dentry, struct qstr *qstr)
{
	return __exfat_d_hash(dentry, qstr);
}

static int exfat_d_hashi(const struct dentry *dentry, struct qstr *qstr)
{
	return __exfat_d_hashi(dentry, qstr);
}

/*
 * Case sensitive compare of two exfat names.
 */
static int __exfat_cmp(const struct dentry *dentry, unsigned int len,
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
static int __exfat_cmpi(const struct dentry *dentry, unsigned int len,
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

static int exfat_cmp(const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	return __exfat_cmp(dentry, len, str, name);
}

static int exfat_cmpi(const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	return __exfat_cmpi(dentry, len, str, name);
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
	.d_revalidate   = exfat_revalidate,
	.d_hash         = exfat_d_hash,
	.d_compare      = exfat_cmp,
};

const struct dentry_operations exfat_ci_dentry_ops = {
	.d_revalidate   = exfat_revalidate_ci,
	.d_hash         = exfat_d_hashi,
	.d_compare      = exfat_cmpi,
};

/* input  : dir, uni_name
 * output : num_of_entry, dos_name(format : aaaaaa~1.bbb)
 */
static int exfat_get_num_entries_and_dos_name(struct super_block *sb, struct exfat_chain *p_dir,
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

static int exfat_create_file(struct inode *inode, struct exfat_chain *p_dir,
	struct exfat_uni_name *p_uniname, unsigned char mode, struct exfat_file_id *fid)
{
	int ret, dentry, num_entries;
	struct exfat_dos_name dos_name;
	struct super_block *sb = inode->i_sb;

	ret = exfat_get_num_entries_and_dos_name(sb, p_dir, p_uniname, &num_entries,
		&dos_name, 0);
	if (ret)
		return ret;

	/* exfat_find_empty_entry must be called before alloc_cluster() */
	dentry = exfat_find_empty_entry(inode, p_dir, num_entries);
	if (dentry < 0)
		return dentry; /* -EIO or -ENOSPC */

	/* (1) update the directory entry */
	/* fill the dos name directory entry information of the created file.
	 * the first cluster is not determined yet. (0)
	 */
	ret = exfat_init_dir_entry(sb, p_dir, dentry, TYPE_FILE | mode,
		CLUS_FREE, 0);
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

	fid->attr = ATTR_ARCHIVE | mode;
	fid->flags = 0x03;
	fid->size = 0;
	fid->start_clu = CLUS_EOF;

	fid->type = TYPE_FILE;
	fid->rwoffset = 0;
	fid->hint_bmap.off = CLUS_EOF;

	/* hint_stat will be used if this is directory. */
	fid->version = 0;
	fid->hint_stat.eidx = 0;
	fid->hint_stat.clu = fid->start_clu;
	fid->hint_femp.eidx = -1;

	return 0;
}

/* returns the length of a struct qstr, ignoring trailing dots */
static inline unsigned int __striptail_len(unsigned int len, const char *name)
{
	while (len && name[len - 1] == '.')
		len--;
	return len;
}

/*
 * Name Resolution Functions :
 * Zero if it was successful; otherwise nonzero.
 */
static int __exfat_resolve_path(struct inode *inode, const unsigned char *path,
	struct exfat_chain *p_dir, struct exfat_uni_name *p_uniname, int lookup)
{
	int namelen;
	int lossy = NLS_NAME_NO_LOSSY;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);

	/* DOT and DOTDOT are handled by VFS layer */

	/* strip all trailing spaces */
	/* DO NOTHING : Is needed? */

	/* strip all trailing periods */
	namelen = __striptail_len(strlen(path), path);
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

	p_dir->dir = fid->start_clu;
	p_dir->size = (unsigned int)(fid->size >> sbi->cluster_size_bits);
	p_dir->flags = fid->flags;

	return 0;
}

static inline int exfat_resolve_path(struct inode *inode, const unsigned char *path,
	struct exfat_chain *dir, struct exfat_uni_name *uni)
{
	return __exfat_resolve_path(inode, path, dir, uni, 0);
}

static inline int exfat_resolve_path_for_lookup(struct inode *inode,
	const unsigned char *path, struct exfat_chain *dir, struct exfat_uni_name *uni)
{
	return __exfat_resolve_path(inode, path, dir, uni, 1);
}

/* create a file */
static int __exfat_create(struct inode *inode, unsigned char *path, unsigned char mode,
		struct exfat_file_id *fid)
{
	int ret/*, dentry*/;
	struct exfat_chain dir;
	struct exfat_uni_name uni_name;
	struct super_block *sb = inode->i_sb;

	/* check the validity of directory name in the given pathname */
	ret = exfat_resolve_path(inode, path, &dir, &uni_name);
	if (ret)
		return ret;

	exfat_set_vol_flags(sb, VOL_DIRTY);

	/* create a new file */
	ret = exfat_create_file(inode, &dir, &uni_name, mode, fid);

	exfat_set_vol_flags(sb, VOL_CLEAN);

	return ret;
}

static inline loff_t exfat_make_i_pos(struct exfat_file_id *fid)
{
	return ((loff_t) fid->dir.dir << 32) | (fid->entry & 0xffffffff);
}

static int exfat_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct exfat_file_id fid;
	loff_t i_pos;
	int err;

	mutex_lock(&EXFAT_SB(sb)->s_lock);

	err = __exfat_create(dir, (unsigned char *) dentry->d_name.name,
		FM_REGULAR, &fid);
	if (err) {
		goto out;
	}
	__lock_d_revalidate(dentry);

	inode_inc_iversion(dir);
	dir->i_ctime = dir->i_mtime = dir->i_atime = current_time(dir);
	if (IS_DIRSYNC(dir))
		(void) exfat_sync_inode(dir);
	else
		mark_inode_dirty(dir);

	i_pos = exfat_make_i_pos(&fid);
	inode = exfat_build_inode(sb, &fid, i_pos);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	inode_inc_iversion(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	d_instantiate(dentry, inode);
out:
	__unlock_d_revalidate(dentry);
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return err;
}

/* lookup a file */
static int exfat_find(struct inode *dir, struct qstr *qname, struct exfat_file_id *fid)
{
	int ret, dentry, num_entries;
	struct exfat_chain cdir;
	struct exfat_uni_name uni_name;
	struct exfat_dos_name dos_name;
	struct exfat_dentry *ep, *ep2;
	struct exfat_entry_set_cache *es = NULL;
	struct super_block *sb = dir->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_file_id *dir_fid = &(EXFAT_I(dir)->fid);
	unsigned char *path;

	if (qname->len == 0)
		return -ENOENT;

	path = (unsigned char *)qname->name;

	/* check the validity of directory name in the given pathname */
	ret = exfat_resolve_path_for_lookup(dir, path, &cdir, &uni_name);
	if (ret)
		return ret;

	ret = exfat_get_num_entries_and_dos_name(sb, &cdir, &uni_name, &num_entries,
		&dos_name, 1);
	if (ret)
		return ret;

	/* check the validation of hint_stat and initialize it if required */
	if (dir_fid->version != (unsigned int) (inode_peek_iversion_raw(dir)
			& 0xffffffff)) {
		dir_fid->hint_stat.clu = cdir.dir;
		dir_fid->hint_stat.eidx = 0;
		dir_fid->version =
			(unsigned int) (inode_peek_iversion_raw(dir) &
				0xffffffff);
		dir_fid->hint_femp.eidx = -1;
	}

	/* search the file name for directories */
	dentry = exfat_find_dir_entry(sb, dir_fid, &cdir, &uni_name,
			num_entries, &dos_name, TYPE_ALL);

	if ((dentry < 0) && (dentry != -EEXIST))
		return dentry; /* -error value */

	fid->dir.dir = cdir.dir;
	fid->dir.size = cdir.size;
	fid->dir.flags = cdir.flags;
	fid->entry = dentry;

	/* root directory itself */
	if (unlikely(dentry == -EEXIST)) {
		fid->type = TYPE_DIR;
		fid->rwoffset = 0;
		fid->hint_bmap.off = CLUS_EOF;

		fid->attr = ATTR_SUBDIR;
		fid->flags = 0x01;
		fid->size = 0;
		fid->start_clu = sbi->root_dir;
	} else {
		es = get_dentry_set_in_dir(sb, &cdir, dentry, ES_2_ENTRIES, &ep);
		if (!es)
			return -EIO;
		ep2 = ep+1;

		fid->type = exfat_get_entry_type(ep);
		fid->rwoffset = 0;
		fid->hint_bmap.off = CLUS_EOF;
		fid->attr = exfat_get_entry_attr(ep);

		fid->size = exfat_get_entry_size(ep2);
		if ((fid->type == TYPE_FILE) && (fid->size == 0)) {
			fid->flags = 0x03;
			fid->start_clu = CLUS_EOF;
		} else {
			fid->flags = exfat_get_entry_flag(ep2);
			fid->start_clu = exfat_get_entry_clu0(ep2);
		}

		if (IS_CLUS_FREE(fid->start_clu)) {
			exfat_fs_error(sb,
				"non-zero size file starts with zero cluster (size : %llu, p_dir : %u, entry : 0x%08x)",
				fid->size, fid->dir.dir, fid->entry);
			return -EIO;
		}

		exfat_release_dentry_set(es);
	}

	/* hint_stat will be used if this is directory. */
	fid->version = 0;
	fid->hint_stat.eidx = 0;
	fid->hint_stat.clu = fid->start_clu;
	fid->hint_femp.eidx = -1;
	return 0;
}

static int exfat_d_anon_disconn(struct dentry *dentry)
{
	return IS_ROOT(dentry) && (dentry->d_flags & DCACHE_DISCONNECTED);
}

/* read data from a opened file */
static int exfat_read_link(struct inode *inode, struct exfat_file_id *fid, void *buffer,
	unsigned long long count, unsigned long long *rcount)
{
	int ret = 0;
	int offset, sec_offset;
	unsigned int clu_offset;
	unsigned int clu;
	unsigned long long logsector, oneblkread, read_bytes;
	struct buffer_head *tmp_bh = NULL;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	/* check if the given file ID is opened */
	if (fid->type != TYPE_FILE)
		return -EPERM;

	if (fid->rwoffset > fid->size)
		fid->rwoffset = fid->size;

	if (count > (fid->size - fid->rwoffset))
		count = fid->size - fid->rwoffset;

	if (count == 0) {
		if (rcount)
			*rcount = 0;
		return 0;
	}

	read_bytes = 0;

	while (count > 0) {
		clu_offset = fid->rwoffset >> sbi->cluster_size_bits;
		clu = fid->start_clu;

		if (fid->flags == 0x03) {
			clu += clu_offset;
		} else {
			/* hint information */
			if ((clu_offset > 0) &&
				((fid->hint_bmap.off != CLUS_EOF) &&
				(fid->hint_bmap.off > 0)) &&
				(clu_offset >= fid->hint_bmap.off)) {
				clu_offset -= fid->hint_bmap.off;
				clu = fid->hint_bmap.clu;
			}

			while (clu_offset > 0) {
				ret = get_next_clus_safe(sb, &clu);
				if (ret)
					goto err_out;

				clu_offset--;
			}
		}

		/* hint information */
		fid->hint_bmap.off = fid->rwoffset >> sbi->cluster_size_bits;
		fid->hint_bmap.clu = clu;

		offset = (int)(fid->rwoffset & (sbi->cluster_size - 1));
		sec_offset = offset >> sb->s_blocksize_bits;
		offset &= (sb->s_blocksize - 1);

		logsector = CLUS_TO_SECT(sbi, clu) + sec_offset;

		oneblkread = (unsigned long long)(sb->s_blocksize - offset);
		if (oneblkread > count)
			oneblkread = count;

		if ((offset == 0) && (oneblkread == sb->s_blocksize)) {
			tmp_bh = sb_bread(sb, logsector);
			if (!tmp_bh)
				goto err_out;
			memcpy(((char *) buffer)+read_bytes,
				((char *) tmp_bh->b_data), (int) oneblkread);
		} else {
			tmp_bh = sb_bread(sb, logsector);
			if (!tmp_bh)
				goto err_out;
			memcpy(((char *) buffer)+read_bytes,
				((char *) tmp_bh->b_data)+offset,
				(int) oneblkread);
		}
		count -= oneblkread;
		read_bytes += oneblkread;
		fid->rwoffset += oneblkread;
	}

err_out:
	brelse(tmp_bh);

	/* set the size of read bytes */
	if (rcount != NULL)
		*rcount = read_bytes;

	return ret;
}

static struct dentry *exfat_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct dentry *alias;
	int err;
	struct exfat_file_id fid;
	loff_t i_pos;
	unsigned long long ret;
	mode_t i_mode;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	err = exfat_find(dir, &dentry->d_name, &fid);
	if (err) {
		if (err == -ENOENT) {
			inode = NULL;
			goto out;
		}
		goto error;
	}

	i_pos = exfat_make_i_pos(&fid);
	inode = exfat_build_inode(sb, &fid, i_pos);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto error;
	}

	i_mode = inode->i_mode;
	if (S_ISLNK(i_mode) && !EXFAT_I(inode)->target) {
		EXFAT_I(inode)->target = kmalloc((i_size_read(inode)+1),
			GFP_KERNEL);
		if (!EXFAT_I(inode)->target) {
			err = -ENOMEM;
			goto error;
		}
		exfat_read_link(dir, &fid, EXFAT_I(inode)->target,
			i_size_read(inode), &ret);
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

	dentry = d_splice_alias(inode, dentry);
	return dentry;
error:
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return ERR_PTR(err);
}

static int exfat_remove_file(struct inode *inode, struct exfat_chain *p_dir, int entry)
{
	int num_entries;
	unsigned long long sector;
	struct exfat_dentry *ep;
	struct super_block *sb = inode->i_sb;

	ep = exfat_get_dentry_in_dir(sb, p_dir, entry, &sector);
	if (!ep)
		return -EIO;

	dcache_lock(sb, sector);

	/* dcache_lock() before call count_ext_entries() */
	num_entries = exfat_count_ext_entries(sb, p_dir, entry, ep);
	if (num_entries < 0) {
		dcache_unlock(sb, sector);
		return -EIO;
	}
	num_entries++;

	dcache_unlock(sb, sector);

	/* (1) update the directory entry */
	return exfat_delete_dir_entry(sb, p_dir, entry, 0, num_entries);
}

/* remove an entry, BUT don't truncate */
static int exfat_unlink(struct inode *dir, struct dentry *dentry)
{
	int fdentry;
	struct exfat_chain cdir;
	struct exfat_dentry *ep;
	struct super_block *sb = dir->i_sb;
	struct inode *inode = dentry->d_inode;
	struct exfat_file_id *fid = &(EXFAT_I(inode)->fid);
	int err = 0;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	fid->size = i_size_read(inode);

	cdir.dir = fid->dir.dir;
	cdir.size = fid->dir.size;
	cdir.flags = fid->dir.flags;

	fdentry = fid->entry;

	if (fid->dir.dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "abnormal access to deleted dentry");
		err = -ENOENT;
		goto out;
	}

	ep = exfat_get_dentry_in_dir(sb, &cdir, fdentry, NULL);
	if (!ep) {
		err = -EIO;
		goto out;
	}

	exfat_set_vol_flags(sb, VOL_DIRTY);

	/* (1) update the directory entry */
	if (exfat_remove_file(dir, &cdir, fdentry)) {
		err = -EIO;
		goto out;
	}

	/* This doesn't modify fid */
	fid->dir.dir = DIR_DELETED;

	exfat_set_vol_flags(sb, VOL_CLEAN);

	__lock_d_revalidate(dentry);

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
out:
	__unlock_d_revalidate(dentry);
	mutex_unlock(&EXFAT_SB(sb)->s_lock);

	return err;
}

/* remove a file */
static int __exfat_remove(struct inode *inode, struct exfat_file_id *fid)
{
	int ret;
	int dentry;
	struct exfat_chain dir, clu_to_free;
	struct exfat_dentry *ep;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	dir.dir = fid->dir.dir;
	dir.size = fid->dir.size;
	dir.flags = fid->dir.flags;

	dentry = fid->entry;

	if (fid->dir.dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "abnormal access to deleted dentry");
		return -ENOENT;
	}

	ep = exfat_get_dentry_in_dir(sb, &dir, dentry, NULL);
	if (!ep)
		return -EIO;


	exfat_set_vol_flags(sb, VOL_DIRTY);

	/* (1) update the directory entry */
	ret = exfat_remove_file(inode, &dir, dentry);
	if (ret)
		goto out;

	clu_to_free.dir = fid->start_clu;
	clu_to_free.size = ((fid->size-1) >> sbi->cluster_size_bits) + 1;
	clu_to_free.flags = fid->flags;

	/* (2) invalidate exfat cache and free the clusters
	 */
	/* clear exfat cache */
	exfat_cache_inval_inode(inode);
	ret = exfat_free_cluster(sb, &clu_to_free, 0);
	/* WARN : DO NOT RETURN ERROR IN HERE */

	/* (3) update struct exfat_file_id  */
	fid->size = 0;
	fid->start_clu = CLUS_EOF;
	fid->flags = 0x03;
	fid->dir.dir = DIR_DELETED;

	exfat_set_vol_flags(sb, VOL_CLEAN);
out:
	return ret;
}

/* write data into a opened file */
static int exfat_write_link(struct inode *inode, struct exfat_file_id *fid, void *buffer,
		unsigned long long count, unsigned long long *wcount)
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
	struct buffer_head *tmp_bh = NULL;
	struct super_block *sb = inode->i_sb;
	unsigned int blksize = (unsigned int)sb->s_blocksize;
	unsigned int blksize_mask = (unsigned int)(sb->s_blocksize-1);
	unsigned char blksize_bits = sb->s_blocksize_bits;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	/* check if the given file ID is opened */
	if (fid->type != TYPE_FILE)
		return -EPERM;

	if (fid->rwoffset > fid->size)
		fid->rwoffset = fid->size;

	if (count == 0) {
		if (wcount)
			*wcount = 0;
		return 0;
	}

	exfat_set_vol_flags(sb, VOL_DIRTY);

	if (fid->size == 0)
		num_clusters = 0;
	else
		num_clusters = ((fid->size-1) >> sbi->cluster_size_bits) + 1;

	write_bytes = 0;

	while (count > 0) {
		clu_offset = (fid->rwoffset >> sbi->cluster_size_bits);
		clu = last_clu = fid->start_clu;

		if (fid->flags == 0x03) {
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
				((fid->hint_bmap.off != CLUS_EOF) &&
				(fid->hint_bmap.off > 0)) &&
				(clu_offset >= fid->hint_bmap.off)) {
				clu_offset -= fid->hint_bmap.off;
				clu = fid->hint_bmap.clu;
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
			num_alloc = ((count - 1) >> sbi->cluster_size_bits) + 1;
			new_clu.dir =
				IS_CLUS_EOF(last_clu) ? CLUS_EOF : last_clu + 1;
			new_clu.size = 0;
			new_clu.flags = fid->flags;

			/* (1) allocate a chain of clusters */
			ret = exfat_alloc_cluster(sb, num_alloc, &new_clu,
				ALLOC_COLD);
			if (ret)
				goto err_out;

			/* (2) append to the FAT chain */
			if (IS_CLUS_EOF(last_clu)) {
				if (new_clu.flags == 0x01)
					fid->flags = 0x01;
				fid->start_clu = new_clu.dir;
				modified = true;
			} else {
				if (new_clu.flags != fid->flags) {
					/* no-fat-chain bit is disabled,
					 * so fat-chain should be synced with
					 * alloc-bmp
					 */
					exfat_chain_cont_cluster(sb, fid->start_clu,
						num_clusters);
					fid->flags = 0x01;
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
		fid->hint_bmap.off = fid->rwoffset >> sbi->cluster_size_bits;
		fid->hint_bmap.clu = clu;

		/* byte offset in cluster   */
		offset = (int)(fid->rwoffset & (sbi->cluster_size-1));
		/* sector offset in cluster */
		sec_offset = offset >> blksize_bits;
		/* byte offset in sector    */
		offset &= blksize_mask;
		logsector = CLUS_TO_SECT(sbi, clu) + sec_offset;

		oneblkwrite = (unsigned long long)(blksize - offset);
		if (oneblkwrite > count)
			oneblkwrite = count;

		if ((offset == 0) && (oneblkwrite == blksize)) {
			tmp_bh = sb_getblk(sb, logsector);
			if (!tmp_bh)
				goto err_out;

			memcpy(((char *)tmp_bh->b_data),
					((char *)buffer)+write_bytes,
					(int)oneblkwrite);
			mark_buffer_dirty(tmp_bh);
		} else {
			if ((offset > 0) ||
				((fid->rwoffset+oneblkwrite) < fid->size)) {
				tmp_bh = sb_bread(sb, logsector);
				if (tmp_bh)
					goto err_out;
			} else {
				tmp_bh = sb_getblk(sb, logsector);
				if (!tmp_bh)
					goto err_out;
			}

			memcpy(((char *) tmp_bh->b_data)+offset,
				((char *) buffer)+write_bytes, (int) oneblkwrite);
			mark_buffer_dirty(tmp_bh);
		}

		count -= oneblkwrite;
		write_bytes += oneblkwrite;
		fid->rwoffset += oneblkwrite;

		fid->attr |= ATTR_ARCHIVE;

		if (fid->size < fid->rwoffset) {
			fid->size = fid->rwoffset;
			modified = true;
		}
	}

	brelse(tmp_bh);

	/* (3) update the direcoty entry */
	/* get_entry_(set_)in_dir shoulb be check DIR_DELETED flag. */
	es = get_dentry_set_in_dir(sb, &(fid->dir), fid->entry, ES_ALL_ENTRIES,
			&ep);
	if (!es) {
		ret = -EIO;
		goto err_out;
	}
	ep2 = ep + 1;

	exfat_set_entry_time(ep, tm_now(EXFAT_SB(sb), &tm), TM_MODIFY);
	exfat_set_entry_attr(ep, fid->attr);

	if (modified) {
		if (exfat_get_entry_flag(ep2) != fid->flags)
			exfat_set_entry_flag(ep2, fid->flags);

		if (exfat_get_entry_size(ep2) != fid->size)
			exfat_set_entry_size(ep2, fid->size);

		if (exfat_get_entry_clu0(ep2) != fid->start_clu)
			exfat_set_entry_clu0(ep2, fid->start_clu);
	}

	if (exfat_update_dir_chksum_with_entry_set(sb, es)) {
		ret = -EIO;
		goto err_out;
	}
	exfat_release_dentry_set(es);

	exfat_set_vol_flags(sb, VOL_CLEAN);

err_out:
	/* set the size of written bytes */
	if (wcount)
		*wcount = write_bytes;

	return ret;
}

static int exfat_symlink(struct inode *dir, struct dentry *dentry,
		const char *target)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct exfat_file_id fid;
	loff_t i_pos;
	int err;
	unsigned long long len = (unsigned long long) strlen(target);
	unsigned long long ret;

	/* symlink option check */
	if (!EXFAT_SB(sb)->options.symlink)
		return -ENOTSUPP;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	err = __exfat_create(dir, (unsigned char *) dentry->d_name.name,
		FM_SYMLINK, &fid);
	if (err)
		goto out;

	err = exfat_write_link(dir, &fid, (char *) target, len, &ret);

	if (err) {
		__exfat_remove(dir, &fid);
		goto out;
	}

	__lock_d_revalidate(dentry);

	inode_inc_iversion(dir);
	dir->i_ctime = dir->i_mtime = dir->i_atime = current_time(dir);
	if (IS_DIRSYNC(dir))
		(void) exfat_sync_inode(dir);
	else
		mark_inode_dirty(dir);

	i_pos = exfat_make_i_pos(&fid);
	inode = exfat_build_inode(sb, &fid, i_pos);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	inode_inc_iversion(inode);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	EXFAT_I(inode)->target = kmalloc((len+1), GFP_KERNEL);
	if (!EXFAT_I(inode)->target) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(EXFAT_I(inode)->target, target, len+1);

	d_instantiate(dentry, inode);
out:
	__unlock_d_revalidate(dentry);
	mutex_unlock(&EXFAT_SB(sb)->s_lock);
	return err;
}

static int exfat_create_dir(struct inode *inode, struct exfat_chain *p_dir,
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

static int exfat_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct exfat_file_id fid;
	struct exfat_chain cdir;
        struct exfat_uni_name uni_name;
	loff_t i_pos;
	int err;

	mutex_lock(&EXFAT_SB(sb)->s_lock);
	/* check the validity of directory name in the given old pathname */
	err = exfat_resolve_path(dir, (unsigned char *) dentry->d_name.name,
		&cdir, &uni_name);
	if (err)
		goto out;

	exfat_set_vol_flags(sb, VOL_DIRTY);
	err = exfat_create_dir(dir, &cdir, &uni_name, &fid);
	exfat_set_vol_flags(sb, VOL_CLEAN);
	if (err)
		goto out;

	__lock_d_revalidate(dentry);

	inode_inc_iversion(dir);
	dir->i_ctime = dir->i_mtime = dir->i_atime = current_time(dir);
	if (IS_DIRSYNC(dir))
		(void) exfat_sync_inode(dir);
	else
		mark_inode_dirty(dir);
	inc_nlink(dir);

	i_pos = exfat_make_i_pos(&fid);
	inode = exfat_build_inode(sb, &fid, i_pos);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	inode_inc_iversion(inode);
	dir->i_ctime = dir->i_mtime = dir->i_atime = current_time(dir);
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	/* timestamp is already written, so mark_inode_dirty() is unneeded. */

	d_instantiate(dentry, inode);

out:
	__unlock_d_revalidate(dentry);
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

	if (IS_CLUS_FREE(p_dir->dir)) /* FAT16 root_dir */
		dentries_per_clu = sbi->dentries_in_root;
	else
		dentries_per_clu = sbi->dentries_per_clu;

	clu.dir = p_dir->dir;
	clu.size = p_dir->size;
	clu.flags = p_dir->flags;

	while (!IS_CLUS_EOF(clu.dir)) {
		for (i = 0; i < dentries_per_clu; i++) {
			ep = exfat_get_dentry_in_dir(sb, &clu, i, NULL);
			if (!ep)
				return -EIO;

			type = exfat_get_entry_type(ep);

			if (type == TYPE_UNUSED)
				return 0;

			if ((type != TYPE_FILE) && (type != TYPE_DIR))
				continue;

			/* FAT16 root_dir */
			if (IS_CLUS_FREE(p_dir->dir))
				return -ENOTEMPTY;

			return -ENOTEMPTY;
		}

		/* FAT16 root_dir */
		if (IS_CLUS_FREE(p_dir->dir))
			return -ENOTEMPTY;

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

/* remove a directory */
static int __exfat_rmdir(struct inode *inode, struct exfat_file_id *fid)
{
	int ret;
	int dentry;
	struct exfat_dentry *ep;
	struct exfat_chain dir, clu_to_free;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	dir.dir = fid->dir.dir;
	dir.size = fid->dir.size;
	dir.flags = fid->dir.flags;

	dentry = fid->entry;

	if (fid->dir.dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR, "abnormal access to deleted dentry");
		return -ENOENT;
	}

	ep = exfat_get_dentry_in_dir(sb, &dir, dentry, NULL);
	if (!ep)
		return -EIO;

	clu_to_free.dir = fid->start_clu;
	clu_to_free.size = ((fid->size-1) >> sbi->cluster_size_bits) + 1;
	clu_to_free.flags = fid->flags;

	ret = exfat_check_dir_empty(sb, &clu_to_free);
	if (ret) {
		if (ret == -EIO)
			exfat_msg(sb, KERN_ERR,
				"failed to exfat_check_dir_empty : err(%d)", ret);
		return ret;
	}

	exfat_set_vol_flags(sb, VOL_DIRTY);

	/* (1) update the directory entry */
	ret = exfat_remove_file(inode, &dir, dentry);
	if (ret) {
		exfat_msg(sb, KERN_ERR, "failed to exfat_remove_file : err(%d)", ret);
		return ret;
	}

	fid->dir.dir = DIR_DELETED;

	exfat_set_vol_flags(sb, VOL_CLEAN);

	return ret;
}

static int exfat_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int err;

	mutex_lock(&EXFAT_SB(inode->i_sb)->s_lock);
	EXFAT_I(inode)->fid.size = i_size_read(inode);

	err = __exfat_rmdir(dir, &(EXFAT_I(inode)->fid));
	if (err)
		goto out;

	__lock_d_revalidate(dentry);

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
out:
	__unlock_d_revalidate(dentry);
	mutex_unlock(&EXFAT_SB(inode->i_sb)->s_lock);
	return err;
}

static int exfat_rename_file(struct inode *inode, struct exfat_chain *p_dir, int oldentry,
		struct exfat_uni_name *p_uniname, struct exfat_file_id *fid)
{
	int ret, newentry = -1, num_old_entries, num_new_entries;
	unsigned long long sector_old, sector_new;
	struct exfat_dos_name dos_name;
	struct exfat_dentry *epold, *epnew;
	struct super_block *sb = inode->i_sb;

	epold = exfat_get_dentry_in_dir(sb, p_dir, oldentry, &sector_old);
	if (!epold)
		return -EIO;

	dcache_lock(sb, sector_old);

	/* dcache_lock() before call count_ext_entries() */
	num_old_entries = exfat_count_ext_entries(sb, p_dir, oldentry, epold);
	if (num_old_entries < 0) {
		dcache_unlock(sb, sector_old);
		return -EIO;
	}
	num_old_entries++;

	ret = exfat_get_num_entries_and_dos_name(sb, p_dir, p_uniname,
		&num_new_entries, &dos_name, 0);
	if (ret) {
		dcache_unlock(sb, sector_old);
		return ret;
	}

	if (num_old_entries < num_new_entries) {
		newentry = exfat_find_empty_entry(inode, p_dir, num_new_entries);
		if (newentry < 0) {
			dcache_unlock(sb, sector_old);
			return newentry; /* -EIO or -ENOSPC */
		}

		epnew = exfat_get_dentry_in_dir(sb, p_dir, newentry, &sector_new);
		if (!epnew) {
			dcache_unlock(sb, sector_old);
			return -EIO;
		}

		memcpy((void *) epnew, (void *) epold, DENTRY_SIZE);
		if (exfat_get_entry_type(epnew) == TYPE_FILE) {
			exfat_set_entry_attr(epnew,
				exfat_get_entry_attr(epnew) | ATTR_ARCHIVE);
			fid->attr |= ATTR_ARCHIVE;
		}
		dcache_modify(sb, sector_new);
		dcache_unlock(sb, sector_old);

		epold = exfat_get_dentry_in_dir(sb, p_dir, oldentry + 1, &sector_old);
		dcache_lock(sb, sector_old);
		epnew = exfat_get_dentry_in_dir(sb, p_dir, newentry + 1, &sector_new);

		if (!epold || !epnew) {
			dcache_unlock(sb, sector_old);
			return -EIO;
		}

		memcpy((void *) epnew, (void *) epold, DENTRY_SIZE);
		dcache_modify(sb, sector_new);
		dcache_unlock(sb, sector_old);

		ret = exfat_init_ext_entry(sb, p_dir, newentry, num_new_entries,
			p_uniname, &dos_name);
		if (ret)
			return ret;

		exfat_delete_dir_entry(sb, p_dir, oldentry, 0, num_old_entries);
		fid->entry = newentry;
	} else {
		if (exfat_get_entry_type(epold) == TYPE_FILE) {
			exfat_set_entry_attr(epold,
				exfat_get_entry_attr(epold) | ATTR_ARCHIVE);
			fid->attr |= ATTR_ARCHIVE;
		}
		dcache_modify(sb, sector_old);
		dcache_unlock(sb, sector_old);

		ret = exfat_init_ext_entry(sb, p_dir, oldentry, num_new_entries,
			p_uniname, &dos_name);
		if (ret)
			return ret;

		exfat_delete_dir_entry(sb, p_dir, oldentry, num_new_entries,
			num_old_entries);
	}

	return 0;
}

static int exfat_move_file(struct inode *inode, struct exfat_chain *p_olddir, int oldentry,
		struct exfat_chain *p_newdir, struct exfat_uni_name *p_uniname, struct exfat_file_id *fid)
{
	int ret, newentry, num_new_entries, num_old_entries;
	unsigned long long sector_mov, sector_new;
	struct exfat_dos_name dos_name;
	struct exfat_dentry *epmov, *epnew;
	struct super_block *sb = inode->i_sb;

	epmov = exfat_get_dentry_in_dir(sb, p_olddir, oldentry, &sector_mov);
	if (!epmov)
		return -EIO;

	/* check if the source and target directory is the same */
	if (exfat_get_entry_type(epmov) == TYPE_DIR &&
			exfat_get_entry_clu0(epmov) == p_newdir->dir)
		return -EINVAL;

	dcache_lock(sb, sector_mov);

	/* dcache_lock() before call count_ext_entries() */
	num_old_entries = exfat_count_ext_entries(sb, p_olddir, oldentry,
		epmov);
	if (num_old_entries < 0) {
		dcache_unlock(sb, sector_mov);
		return -EIO;
	}
	num_old_entries++;

	ret = exfat_get_num_entries_and_dos_name(sb, p_newdir, p_uniname,
		&num_new_entries, &dos_name, 0);
	if (ret) {
		dcache_unlock(sb, sector_mov);
		return ret;
	}

	newentry = exfat_find_empty_entry(inode, p_newdir, num_new_entries);
	if (newentry < 0) {
		dcache_unlock(sb, sector_mov);
		return newentry; /* -EIO or -ENOSPC */
	}

	epnew = exfat_get_dentry_in_dir(sb, p_newdir, newentry, &sector_new);
	if (!epnew) {
		dcache_unlock(sb, sector_mov);
		return -EIO;
	}

	memcpy((void *) epnew, (void *) epmov, DENTRY_SIZE);
	if (exfat_get_entry_type(epnew) == TYPE_FILE) {
		exfat_set_entry_attr(epnew,
			exfat_get_entry_attr(epnew) | ATTR_ARCHIVE);
		fid->attr |= ATTR_ARCHIVE;
	}
	dcache_modify(sb, sector_new);
	dcache_unlock(sb, sector_mov);

	epmov = exfat_get_dentry_in_dir(sb, p_olddir, oldentry+1, &sector_mov);
	dcache_lock(sb, sector_mov);
	epnew = exfat_get_dentry_in_dir(sb, p_newdir, newentry+1, &sector_new);
	if (!epmov || !epnew) {
		dcache_unlock(sb, sector_mov);
		return -EIO;
	}

	memcpy((void *) epnew, (void *) epmov, DENTRY_SIZE);
	dcache_modify(sb, sector_new);
	dcache_unlock(sb, sector_mov);

	ret = exfat_init_ext_entry(sb, p_newdir, newentry, num_new_entries,
		p_uniname, &dos_name);
	if (ret)
		return ret;

	exfat_delete_dir_entry(sb, p_olddir, oldentry, 0, num_old_entries);

	fid->dir.dir = p_newdir->dir;
	fid->dir.size = p_newdir->size;
	fid->dir.flags = p_newdir->flags;

	fid->entry = newentry;

	return 0;
}

static void exfat_update_parent_info(struct exfat_file_id *fid, struct inode *parent_inode)
{
	struct exfat_sb_info *sbi = EXFAT_SB(parent_inode->i_sb);
	struct exfat_file_id *parent_fid = &(EXFAT_I(parent_inode)->fid);

	/*
	 * the problem that struct exfat_file_id caches wrong parent info.
	 *
	 * because of flag-mismatch of fid->dir,
	 * there is abnormal traversing cluster chain.
	 */
	if (unlikely((parent_fid->flags != fid->dir.flags)
		|| (parent_fid->size != (fid->dir.size<<sbi->cluster_size_bits))
		|| (parent_fid->start_clu != fid->dir.dir))) {

		fid->dir.dir = parent_fid->start_clu;
		fid->dir.flags = parent_fid->flags;
		fid->dir.size = ((parent_fid->size + (sbi->cluster_size-1))
				>> sbi->cluster_size_bits);
	}
}

/* rename or move a old file into a new file */
static int __exfat_rename(struct inode *old_parent_inode, struct exfat_file_id *fid,
		struct inode *new_parent_inode, struct dentry *new_dentry)
{
	int ret;
	int dentry;
	struct exfat_chain olddir, newdir;
	struct exfat_chain *p_dir = NULL;
	struct exfat_uni_name uni_name;
	struct exfat_dentry *ep;
	struct super_block *sb = old_parent_inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	unsigned char *new_path = (unsigned char *) new_dentry->d_name.name;
	struct inode *new_inode = new_dentry->d_inode;
	int num_entries;
	struct exfat_file_id *new_fid = NULL;
	unsigned int new_entry_type = TYPE_UNUSED;
	int new_entry = 0;

	/* check the validity of pointer parameters */
	if ((new_path == NULL) || (strlen(new_path) == 0))
		return -EINVAL;

	if (fid->dir.dir == DIR_DELETED) {
		exfat_msg(sb, KERN_ERR,
				"abnormal access to deleted source dentry");
		return -ENOENT;
	}

	exfat_update_parent_info(fid, old_parent_inode);

	olddir.dir = fid->dir.dir;
	olddir.size = fid->dir.size;
	olddir.flags = fid->dir.flags;

	dentry = fid->entry;

	ep = exfat_get_dentry_in_dir(sb, &olddir, dentry, NULL);
	if (!ep)
		return -EIO;

	/* check whether new dir is existing directory and empty */
	if (new_inode) {
		ret = -EIO;
		new_fid = &EXFAT_I(new_inode)->fid;

		if (new_fid->dir.dir == DIR_DELETED) {
			exfat_msg(sb, KERN_ERR,
				"abnormal access to deleted target dentry");
			goto out;
		}

		exfat_update_parent_info(new_fid, new_parent_inode);

		p_dir = &(new_fid->dir);
		new_entry = new_fid->entry;
		ep = exfat_get_dentry_in_dir(sb, p_dir, new_entry, NULL);
		if (!ep)
			goto out;

		new_entry_type = exfat_get_entry_type(ep);

		/* if new_inode exists, update fid */
		new_fid->size = i_size_read(new_inode);
		if (new_entry_type == TYPE_DIR) {
			struct exfat_chain new_clu;

			new_clu.dir = new_fid->start_clu;
			new_clu.size = ((new_fid->size-1) >>
					sbi->cluster_size_bits) + 1;
			new_clu.flags = new_fid->flags;

			ret = exfat_check_dir_empty(sb, &new_clu);
			if (ret)
				return ret;
		}
	}

	/* check the validity of directory name in the given new pathname */
	ret = exfat_resolve_path(new_parent_inode, new_path, &newdir, &uni_name);
	if (ret)
		return ret;

	exfat_set_vol_flags(sb, VOL_DIRTY);

	if (olddir.dir == newdir.dir)
		ret = exfat_rename_file(new_parent_inode, &olddir, dentry, &uni_name, fid);
	else
		ret = exfat_move_file(new_parent_inode, &olddir, dentry, &newdir,
			&uni_name, fid);

	if ((!ret) && new_inode) {
		/* delete entries of new_dir */
		ep = exfat_get_dentry_in_dir(sb, p_dir, new_entry, NULL);
		if (!ep) {
			ret = -EIO;
			goto del_out;
		}

		num_entries = exfat_count_ext_entries(sb, p_dir, new_entry, ep);
		if (num_entries < 0) {
			ret = -EIO;
			goto del_out;
		}

		if (exfat_delete_dir_entry(sb, p_dir, new_entry, 0,
				num_entries + 1)) {
			ret = -EIO;
			goto del_out;
		}

		/* Free the clusters if new_inode is a dir(as if __rmdir) */
		if (new_entry_type == TYPE_DIR) {
			/* new_fid, new_clu_to_free */
			struct exfat_chain new_clu_to_free;

			new_clu_to_free.dir = new_fid->start_clu;
			new_clu_to_free.size = ((new_fid->size-1) >>
					sbi->cluster_size_bits) + 1;
			new_clu_to_free.flags = new_fid->flags;

			if (exfat_free_cluster(sb, &new_clu_to_free, 1)) {
				/* just set I/O error only */
				ret = -EIO;
			}

			new_fid->size = 0;
			new_fid->start_clu = CLUS_EOF;
			new_fid->flags = 0x03;
		}
del_out:
		/* Update new_inode fid
		 * Prevent syncing removed new_inode
		 * (new_fid is already initialized above code ("if (new_inode)")
		 */
		new_fid->dir.dir = DIR_DELETED;
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

	EXFAT_I(old_inode)->fid.size = i_size_read(old_inode);

	err = __exfat_rename(old_dir, &(EXFAT_I(old_inode)->fid), new_dir,
		new_dentry);
	if (err)
		goto out;

	__lock_d_revalidate(old_dentry);
	__lock_d_revalidate(new_dentry);

	inode_inc_iversion(new_dir);
	new_dir->i_ctime = new_dir->i_mtime = new_dir->i_atime =
		current_time(new_dir);
	if (IS_DIRSYNC(new_dir))
		(void) exfat_sync_inode(new_dir);
	else
		mark_inode_dirty(new_dir);

	i_pos = exfat_make_i_pos(&(EXFAT_I(old_inode)->fid));
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
	__unlock_d_revalidate(old_dentry);
	__unlock_d_revalidate(new_dentry);
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
	if ((perm & (S_IRUGO | S_IXUGO)) != (i_mode & (S_IRUGO | S_IXUGO)))
		return -EPERM;

	if (exfat_mode_can_hold_ro(inode)) {
		/*
		 * Of the w bits, either all (subject to umask) or none must
		 * be present.
		 */
		if ((perm & S_IWUGO) && ((perm & S_IWUGO) != (S_IWUGO & ~mask)))
			return -EPERM;
	} else {
		/*
		 * If exfat_mode_can_hold_ro(inode) is false, can't change
		 * w bits.
		 */
		if ((perm & S_IWUGO) != (S_IWUGO & ~mask))
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

static void __exfat_do_truncate(struct inode *inode, loff_t old, loff_t new)
{
	down_write(&EXFAT_I(inode)->truncate_lock);
	truncate_setsize(inode, new);
	exfat_truncate(inode, old);
	up_write(&EXFAT_I(inode)->truncate_lock);
}

int exfat_setattr(struct dentry *dentry, struct iattr *attr)
{

	struct exfat_sb_info *sbi = EXFAT_SB(dentry->d_sb);
	struct inode *inode = dentry->d_inode;
	unsigned int ia_valid;
	int error;
	loff_t old_size;

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
				S_IRWXUGO)))) {
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

	EXFAT_I(inode)->fid.size = i_size_read(inode);

	/* patch 1.2.0 : fixed the problem of size mismatch. */
	if (attr->ia_valid & ATTR_SIZE) {
		old_size = i_size_read(inode);

		__exfat_do_truncate(inode, old_size, attr->ia_size);
	}
	setattr_copy(inode, attr);
	mark_inode_dirty(inode);

	return error;
}

const struct inode_operations exfat_dir_inode_operations = {
	.create        = exfat_create,
	.lookup        = exfat_lookup,
	.unlink        = exfat_unlink,
	.symlink       = exfat_symlink,
	.mkdir         = exfat_mkdir,
	.rmdir         = exfat_rmdir,
	.rename        = exfat_rename,
	.setattr       = exfat_setattr,
	.getattr       = exfat_getattr,
};
